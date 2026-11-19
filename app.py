#!/usr/bin/env python3
"""Oracle Listener Log Analyzer — Web Application"""

import os, io, re, uuid, json, time, tempfile, threading, sqlite3, gzip, tarfile, shutil
from datetime import datetime
from flask import Flask, request, jsonify, render_template, Response, send_file, make_response
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500 MB (compressed upload limit)

SESSIONS: dict = {}
_LOCK = threading.Lock()

# ── Session storage & cleanup ──────────────────────────────────────────────
# Each analysis session is backed by a temporary SQLite file in the system temp
# dir (ollda_*.db); uploads are staged as ollda_*.tmp / ollda_*.log until the
# worker has parsed them. Sessions idle for more than OLLDA_SESSION_TTL_HOURS are
# removed together with their files by a per-process janitor thread. Because
# Gunicorn runs several workers (each with its own SESSIONS dict), orphan files
# are only removed based on their mtime, which is refreshed on every access.

SESSION_TTL_SECONDS = max(float(os.environ.get('OLLDA_SESSION_TTL_HOURS', '6')), 0.01) * 3600
CLEANUP_INTERVAL_SECONDS = max(float(os.environ.get('OLLDA_CLEANUP_INTERVAL_MIN', '15')), 0.1) * 60
TMP_PREFIX = 'ollda_'
_SQLITE_MAGIC = b'SQLite format 3\x00'
_JANITOR_PID = None
_JANITOR_LOCK = threading.Lock()


def _new_db_path():
    fd, dp = tempfile.mkstemp(prefix=TMP_PREFIX, suffix='.db')
    os.close(fd)
    return dp


def _source_paths(log_sources):
    for src in log_sources or []:
        if isinstance(src, str):
            yield src
        elif isinstance(src, tuple) and len(src) >= 2:
            yield src[1]


def _touch(paths):
    """Refresh mtime so the orphan sweep (in any worker) treats files as in use."""
    for p in paths:
        try:
            os.utime(p)
        except OSError:
            pass


def _get_session(sid):
    """Return SESSIONS[sid] and mark it as accessed. Caller must hold _LOCK."""
    s = SESSIONS.get(sid)
    if s is not None:
        s['last_access'] = time.time()
        _touch([s.get('db_path', ''), *_source_paths(s.get('log_sources'))])
    return s


def _discard_session(s):
    """Delete every file owned by a session dict (already removed from SESSIONS)."""
    for p in _source_paths(s.get('log_sources')):
        try: os.unlink(p)
        except Exception: pass
    try: os.unlink(s.get('db_path', ''))
    except Exception: pass


def _is_ollda_db(path):
    """True for files created by OLLDA (ollda_*) or legacy tmp*.db SQLite
    files that contain the `connections` table (or are still empty)."""
    name = os.path.basename(path)
    if name.startswith(TMP_PREFIX):
        return True
    try:
        if os.path.getsize(path) == 0:
            return True
        with open(path, 'rb') as f:
            if f.read(16) != _SQLITE_MAGIC:
                return False
        conn = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
        try:
            return conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='connections'"
            ).fetchone() is not None
        finally:
            conn.close()
    except Exception:
        return False


def _expire_sessions(now=None):
    """Remove this process's sessions idle for longer than the TTL."""
    now = now or time.time()
    expired = []
    with _LOCK:
        for sid, s in list(SESSIONS.items()):
            if s.get('status') == 'parsing':
                continue    # worker thread still writing to it
            last = s.get('last_access') or s.get('created_at') or now
            if now - last > SESSION_TTL_SECONDS:
                expired.append(SESSIONS.pop(sid))
    for s in expired:
        _discard_session(s)
    return len(expired)


_SWEEP_SUFFIXES = ('.db', '.db-journal', '.tmp', '.log', '.xlsx')


def _sweep_orphan_dbs(now=None):
    """Remove OLLDA temp files (ollda_*.db/.tmp/.log/.xlsx, plus legacy tmp*.db
    SQLite files) that are not owned by this process and whose mtime is older
    than the TTL (safe across workers: in-use files get their mtime refreshed)."""
    now = now or time.time()
    with _LOCK:
        owned = set()
        for s in SESSIONS.values():
            owned.add(os.path.abspath(s.get('db_path', '')))
            owned.update(os.path.abspath(p) for p in _source_paths(s.get('log_sources')))
    tmpdir = tempfile.gettempdir()
    removed = 0
    try:
        names = os.listdir(tmpdir)
    except OSError:
        return 0
    for name in names:
        if name.startswith(TMP_PREFIX):
            if not name.endswith(_SWEEP_SUFFIXES):
                continue
        elif not (name.startswith('tmp') and name.endswith('.db')):
            continue
        path = os.path.abspath(os.path.join(tmpdir, name))
        if path in owned:
            continue
        try:
            if now - os.path.getmtime(path) <= SESSION_TTL_SECONDS:
                continue
        except OSError:
            continue
        if not _is_ollda_db(path):
            continue
        try:
            os.unlink(path)
            removed += 1
        except OSError:
            pass
    return removed


def _janitor_loop():
    while True:
        time.sleep(CLEANUP_INTERVAL_SECONDS)
        try:
            n_s = _expire_sessions()
            n_f = _sweep_orphan_dbs()
            if n_s or n_f:
                app.logger.info('OLLDA cleanup: %d expired session(s), %d orphan db file(s)', n_s, n_f)
        except Exception:
            app.logger.exception('OLLDA cleanup failed')


def _ensure_janitor():
    """Start the cleanup thread once per process (survives Gunicorn --preload forks)."""
    global _JANITOR_PID
    pid = os.getpid()
    if _JANITOR_PID == pid:
        return
    with _JANITOR_LOCK:
        if _JANITOR_PID == pid:
            return
        _JANITOR_PID = pid
        try:
            n = _sweep_orphan_dbs()
            if n:
                app.logger.info('OLLDA startup cleanup: removed %d orphan db file(s)', n)
        except Exception:
            pass
        threading.Thread(target=_janitor_loop, name='ollda-janitor', daemon=True).start()


@app.before_request
def _janitor_hook():
    _ensure_janitor()

# ── Parsing ────────────────────────────────────────────────────────────────

MONTH_MAP = {m: f'{i+1:02d}' for i, m in enumerate(
    ['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC'])}

DDL = """
CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT, date TEXT, hour INTEGER,
    service_name TEXT, instance_name TEXT, server_type TEXT,
    program TEXT, client_host TEXT, os_user TEXT,
    client_ip TEXT, client_port TEXT, action TEXT, status_code TEXT, success INTEGER
);
"""

# ── Pre-aggregated table ───────────────────────────────────────────────────
# `connections` keeps every parsed line (raw, unindexed, kept for fidelity), but
# all views read `agg`: one row per distinct combination of AGG_KEYS with the
# number of connections (cnt) and the first/last timestamp. Every metric the UI
# shows is decomposable over that key, so results are identical to querying the
# raw table: COUNT(*) -> SUM(cnt), SUM(success) -> SUM(success*cnt),
# MIN/MAX(timestamp) -> MIN(first_ts)/MAX(last_ts); COUNT(DISTINCT dim) and
# WHERE/GROUP BY on any key column work unchanged. client_port is the only
# column left out of the key (no view uses it).
AGG_KEYS = ['date', 'hour', 'service_name', 'instance_name', 'server_type',
            'program', 'client_host', 'os_user', 'client_ip', 'action',
            'status_code', 'success']
AGG_NT_KEYS = [k for k in AGG_KEYS if k not in ('date', 'hour')]
AGG_FLUSH_KEYS = int(os.environ.get('OLLDA_AGG_FLUSH_KEYS', '200000'))

_AGG_STAGE_DDL = ("CREATE TABLE IF NOT EXISTS agg_stage ("
                  + ', '.join(AGG_KEYS) + ", cnt INTEGER, first_ts TEXT, last_ts TEXT)")
_AGG_STAGE_INSERT = ("INSERT INTO agg_stage VALUES ("
                     + ','.join('?' * (len(AGG_KEYS) + 3)) + ")")
_AGG_BUILD = (
    "CREATE TABLE agg AS SELECT " + ', '.join(AGG_KEYS)
    + ", SUM(cnt) AS cnt, MIN(first_ts) AS first_ts, MAX(last_ts) AS last_ts"
    + " FROM agg_stage GROUP BY " + ', '.join(AGG_KEYS) + ";"
    + " DROP TABLE agg_stage;"
    + " CREATE INDEX agg_ip ON agg(client_ip);"
    + " CREATE INDEX agg_date ON agg(date, hour);"
    # agg_nt: same key without date/hour -> much smaller; serves every view
    # that does not group or filter by time
    + " CREATE TABLE agg_nt AS SELECT " + ', '.join(AGG_NT_KEYS)
    + ", SUM(cnt) AS cnt, MIN(first_ts) AS first_ts, MAX(last_ts) AS last_ts"
    + " FROM agg GROUP BY " + ', '.join(AGG_NT_KEYS) + ";"
    + " CREATE INDEX agg_nt_ip ON agg_nt(client_ip);"
)
TIME_KEYS = ('date', 'hour')

REPORT_MAX_AGG_ROWS = int(os.environ.get('OLLDA_REPORT_MAX_AGG_ROWS', '150000'))

C_CNT  = 'COALESCE(SUM(cnt),0)'
C_SUCC = 'SUM(success*cnt)'

_INSERT = (
    "INSERT INTO connections VALUES "
    "(NULL,:timestamp,:date,:hour,:service_name,:instance_name,:server_type,"
    ":program,:client_host,:os_user,:client_ip,:client_port,:action,:status_code,:success)"
)

# Pattern used to detect Oracle listener log header lines
LISTENER_HDR_RE = re.compile(
    r'^\d{2}-(?:JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)-\d{4}'
    r' \d{2}:\d{2}:\d{2}',
    re.IGNORECASE
)


def _ts(s):
    try:
        d, m, rest = s.split('-', 2)
        y, t = rest.split(' ', 1)
        return datetime.strptime(
            f"{y}-{MONTH_MAP[m.upper()]}-{int(d):02d} {t}", "%Y-%m-%d %H:%M:%S"
        )
    except Exception:
        return None


def _parse(line):
    line = line.strip()
    if not line or ' * ' not in line:
        return None
    p = line.split(' * ')
    if len(p) < 5:
        return None
    m = re.match(r'^(\d{2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2})', p[0])
    if not m:
        return None
    ts = _ts(m.group(1))
    if not ts:
        return None

    cd, addr, act = p[1], p[2], p[3].strip().lower()
    if act not in ('establish', 'refused'):
        return None

    svc  = re.search(r'SERVICE_NAME=([^)]+)', cd)
    inst = re.search(r'INSTANCE_NAME=([^)]+)', cd)
    srv  = re.search(r'(?:^|\()SERVER=([A-Za-z]+)', cd)

    prog = host = user = None
    pos = cd.find('(CID=')
    if pos >= 0:
        c = cd[pos + 5:]
        pm = re.search(r'\(PROGRAM=([^)]+)\)', c)
        hm = re.search(r'\(HOST=([^)]+)\)', c)
        um = re.search(r'\(USER=([^)]+)\)', c)
        prog = pm.group(1).strip() if pm else None
        host = hm.group(1).strip() if hm else None
        user = um.group(1).strip() if um else None
        if host == '__jdbc__':
            host = None

    ah = re.search(r'\(HOST=([^)]+)\)', addr)
    ap = re.search(r'\(PORT=(\d+)\)', addr)
    sc = p[-1].strip()
    if not re.fullmatch(r'-?\d+', sc):
        sc = None

    return dict(
        timestamp    = ts.isoformat(sep=' '),
        date         = ts.date().isoformat(),
        hour         = ts.hour,
        service_name = svc.group(1).strip()  if svc  else None,
        instance_name= inst.group(1).strip() if inst else None,
        server_type  = srv.group(1).upper()  if srv  else None,
        program      = prog,
        client_host  = host,
        os_user      = user,
        client_ip    = ah.group(1).strip() if ah else None,
        client_port  = ap.group(1)         if ap else None,
        action       = act,
        status_code  = sc,
        success      = 1 if sc == '0' else 0,
    )


def _summary(conn):
    q = lambda sql: (conn.execute(sql).fetchone() or [0])[0] or 0
    return dict(
        total      = q(f"SELECT {C_CNT} FROM agg_nt"),
        success    = q(f"SELECT {C_SUCC} FROM agg_nt"),
        failures   = q(f"SELECT {C_CNT}-{C_SUCC} FROM agg_nt"),
        uniq_ips   = q("SELECT COUNT(DISTINCT client_ip)    FROM agg_nt WHERE client_ip    IS NOT NULL"),
        uniq_prog  = q("SELECT COUNT(DISTINCT program)      FROM agg_nt WHERE program      IS NOT NULL"),
        uniq_host  = q("SELECT COUNT(DISTINCT client_host)  FROM agg_nt WHERE client_host  IS NOT NULL"),
        uniq_user  = q("SELECT COUNT(DISTINCT os_user)      FROM agg_nt WHERE os_user      IS NOT NULL"),
        uniq_svc   = q("SELECT COUNT(DISTINCT service_name) FROM agg_nt WHERE service_name IS NOT NULL"),
        first      = conn.execute("SELECT MIN(first_ts) FROM agg_nt").fetchone()[0],
        last       = conn.execute("SELECT MAX(last_ts) FROM agg_nt").fetchone()[0],
    )


# ── Compressed file handling ───────────────────────────────────────────────

def _looks_like_listener(fileobj, check_lines=40):
    """Return True if file-like object contains Oracle listener log lines."""
    matches = seen = 0
    for raw in fileobj:
        line = raw.decode('utf-8', errors='replace') if isinstance(raw, bytes) else raw
        stripped = line.strip()
        if stripped:
            seen += 1
            if LISTENER_HDR_RE.match(stripped) and ' * ' in stripped:
                matches += 1
        if seen >= check_lines:
            break
    return matches > 0


def _scan_tar(archive_path):
    """
    Open a .tar.gz and return [(member_name, uncompressed_size)] for
    qualifying listener log members. Does not extract to disk.
    """
    qualifying = []
    try:
        with tarfile.open(archive_path, 'r:gz') as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                ext = os.path.splitext(member.name.lower())[1]
                if ext and ext not in ('.log', '.txt', ''):
                    continue
                fobj = tar.extractfile(member)
                if fobj is None:
                    continue
                ok = _looks_like_listener(fobj)
                fobj.close()
                if ok:
                    qualifying.append((member.name, member.size))
    except Exception:
        pass
    return qualifying


def _decompress_gz(src_path, src_name):
    """
    Streaming decompress a .gz file to a temp file (1 MB chunks).
    Returns the temp path, or None if the content is not a listener log.
    Deletes src_path on exit regardless of outcome.
    """
    fd, dst = tempfile.mkstemp(prefix=TMP_PREFIX, suffix='.log')
    os.close(fd)
    try:
        with gzip.open(src_path, 'rb') as gz, open(dst, 'wb') as out:
            shutil.copyfileobj(gz, out, length=1024 * 1024)
        with open(dst, 'r', encoding='utf-8', errors='replace') as f:
            if not _looks_like_listener(f):
                os.unlink(dst)
                return None
        return dst
    except Exception:
        try:
            os.unlink(dst)
        except Exception:
            pass
        return None
    finally:
        try:
            os.unlink(src_path)
        except Exception:
            pass


def _resolve_upload(upload_file):
    """
    Save one uploaded file to temp and prepare it for the worker.
    Returns a list of log sources:
      - str  → plain temp file path
      - ('tar', archive_path, [(name, size), ...]) → streaming tar source
    Returns [] if no listener logs were found.
    """
    name = upload_file.filename or 'upload'
    nl   = name.lower()

    fd, src = tempfile.mkstemp(prefix=TMP_PREFIX, suffix='.tmp')
    os.close(fd)
    upload_file.save(src)

    if nl.endswith('.tar.gz') or nl.endswith('.tgz'):
        members = _scan_tar(src)
        if not members:
            try:
                os.unlink(src)
            except Exception:
                pass
            return []
        return [('tar', src, members)]

    if nl.endswith('.gz'):
        result = _decompress_gz(src, name)  # deletes src internally
        return [result] if result else []

    # Plain .log / .txt — verify it's a listener log before accepting
    with open(src, 'r', encoding='utf-8', errors='replace') as f:
        if not _looks_like_listener(f):
            try:
                os.unlink(src)
            except Exception:
                pass
            return []
    return [src]


# ── Fingerprinting & compatibility ─────────────────────────────────────────

def _instance_base(name):
    """Strip trailing digits from instance name: ORCL1 → ORCL."""
    return name.rstrip('0123456789') or name


def _fingerprint_source(src, max_records=2000):
    """
    Scan up to max_records parsed lines from a log source and return
    {'services': set, 'instances': set}.
    Works with both plain file paths and tar sources.
    """
    services, instances = set(), set()
    count = [0]

    def scan_file(path):
        with open(path, encoding='utf-8', errors='replace') as f:
            for line in f:
                r = _parse(line)
                if r:
                    if r['service_name']:  services.add(r['service_name'].upper())
                    if r['instance_name']: instances.add(r['instance_name'].upper())
                    count[0] += 1
                    if count[0] >= max_records:
                        return

    if isinstance(src, str):
        scan_file(src)
    else:
        _, archive_path, members = src
        try:
            with tarfile.open(archive_path, 'r:gz') as tar:
                member_set = {m for m, _ in members}
                for tarinfo in tar:
                    if count[0] >= max_records:
                        break
                    if tarinfo.name not in member_set or not tarinfo.isfile():
                        continue
                    fobj = tar.extractfile(tarinfo)
                    if fobj is None:
                        continue
                    fd, tp = tempfile.mkstemp(prefix=TMP_PREFIX, suffix='.log')
                    os.close(fd)
                    try:
                        with open(tp, 'wb') as out:
                            shutil.copyfileobj(fobj, out, 1024 * 1024)
                        fobj.close()
                        scan_file(tp)
                    finally:
                        try:
                            os.unlink(tp)
                        except Exception:
                            pass
        except Exception:
            pass

    return {'services': services, 'instances': instances}


def _compatible_databases(fps):
    """
    Return (True, None) if files appear to be from the same DB,
    or (False, reason_string) if they look like different databases.
    """
    if len(fps) < 2:
        return True, None

    common_svc = fps[0]['services'].copy()
    for fp in fps[1:]:
        common_svc &= fp['services']
    if common_svc:
        return True, None

    def bases(fp):
        return {_instance_base(i) for i in fp['instances']}

    all_bases = [bases(fp) for fp in fps]
    common_bases = all_bases[0].copy()
    for b in all_bases[1:]:
        common_bases &= b
    if common_bases:
        return True, None

    summaries = []
    for i, fp in enumerate(fps, 1):
        svc  = ', '.join(sorted(fp['services'])[:4])  or '(none)'
        inst = ', '.join(sorted(fp['instances'])[:4]) or '(none)'
        summaries.append(f'File {i}: services=[{svc}] instances=[{inst}]')
    reason = ('No common service names or instance name prefixes found.\n'
              + '\n'.join(summaries))
    return False, reason


# ── Worker ─────────────────────────────────────────────────────────────────

def _worker(sid, log_sources, db_path):
    """
    log_sources: list of:
      - str                                  → plain temp file path
      - ('tar', archive_path, [(name,size)]) → streaming tar extraction
    Files/archives are deleted after processing to free disk space.
    """
    try:
        conn = sqlite3.connect(db_path)
        # Throw-away session DB: durability is irrelevant, speed is not
        conn.execute('PRAGMA journal_mode=OFF')
        conn.execute('PRAGMA synchronous=OFF')
        conn.execute('PRAGMA cache_size=-65536')   # 64 MB
        conn.executescript(DDL)
        conn.execute(_AGG_STAGE_DDL)

        acc = {}   # key tuple -> [cnt, first_ts, last_ts]

        def accumulate(r):
            k = tuple([r[c] for c in AGG_KEYS])
            e = acc.get(k)
            ts = r['timestamp']
            if e is None:
                acc[k] = [1, ts, ts]
            else:
                e[0] += 1
                if ts < e[1]: e[1] = ts
                if ts > e[2]: e[2] = ts

        def flush_acc():
            if acc:
                conn.executemany(_AGG_STAGE_INSERT,
                                 (k + tuple(v) for k, v in acc.items()))
                conn.commit()
                acc.clear()

        # Count total lines (plain files counted directly;
        # tar members estimated from uncompressed size ~150 bytes/line)
        total = 0
        for src in log_sources:
            if isinstance(src, str):
                with open(src, encoding='utf-8', errors='replace') as f:
                    total += sum(1 for _ in f)
            else:
                _, _, members = src
                total += max(sum(sz // 150 for _, sz in members), 1)
        total = max(total, 1)
        with _LOCK:
            SESSIONS[sid]['total_lines'] = total

        batch, parsed, done = [], 0, 0

        for src in log_sources:
            if isinstance(src, str):
                with open(src, encoding='utf-8', errors='replace') as f:
                    for raw in f:
                        done += 1
                        r = _parse(raw)
                        if r:
                            batch.append(r)
                            accumulate(r)
                            parsed += 1
                        if len(batch) >= 5000:
                            conn.executemany(_INSERT, batch)
                            conn.commit()
                            batch.clear()
                            if len(acc) >= AGG_FLUSH_KEYS:
                                flush_acc()
                        if done % 10000 == 0:
                            _touch(_source_paths(log_sources))
                            with _LOCK:
                                SESSIONS[sid].update(
                                    parsed=parsed, lines_done=done,
                                    pct=min(int(100 * done / total), 99))
                try:
                    os.unlink(src)
                except Exception:
                    pass

            else:
                _, archive_path, members = src
                member_set = {m for m, _ in members}
                try:
                    with tarfile.open(archive_path, 'r:gz') as tar:
                        for tarinfo in tar:
                            if tarinfo.name not in member_set or not tarinfo.isfile():
                                continue
                            fobj = tar.extractfile(tarinfo)
                            if fobj is None:
                                continue
                            # Extract this member to a temp file, then process and delete
                            fd, tp = tempfile.mkstemp(prefix=TMP_PREFIX, suffix='.log')
                            os.close(fd)
                            with open(tp, 'wb') as out:
                                shutil.copyfileobj(fobj, out, 1024 * 1024)
                            fobj.close()
                            try:
                                with open(tp, encoding='utf-8', errors='replace') as f:
                                    for raw in f:
                                        done += 1
                                        r = _parse(raw)
                                        if r:
                                            batch.append(r)
                                            accumulate(r)
                                            parsed += 1
                                        if len(batch) >= 5000:
                                            conn.executemany(_INSERT, batch)
                                            conn.commit()
                                            batch.clear()
                                            if len(acc) >= AGG_FLUSH_KEYS:
                                                flush_acc()
                                        if done % 10000 == 0:
                                            _touch([tp, *_source_paths(log_sources)])
                                            with _LOCK:
                                                SESSIONS[sid].update(
                                                    parsed=parsed, lines_done=done,
                                                    pct=min(int(100 * done / total), 99))
                            finally:
                                try:
                                    os.unlink(tp)
                                except Exception:
                                    pass
                finally:
                    try:
                        os.unlink(archive_path)
                    except Exception:
                        pass

        if batch:
            conn.executemany(_INSERT, batch)
            conn.commit()
        flush_acc()
        conn.executescript(_AGG_BUILD)
        conn.commit()

        sm = _summary(conn)
        conn.close()
        with _LOCK:
            SESSIONS[sid].update(status='ready', parsed=parsed,
                                 lines_done=done, pct=100, summary=sm,
                                 last_access=time.time())
    except Exception as e:
        with _LOCK:
            if sid in SESSIONS:
                SESSIONS[sid].update(status='error', error=str(e),
                                     last_access=time.time())
    finally:
        # Safety cleanup for any sources not yet deleted
        for src in log_sources:
            if isinstance(src, str):
                try:
                    os.unlink(src)
                except Exception:
                    pass
            elif isinstance(src, tuple) and len(src) >= 2:
                try:
                    os.unlink(src[1])
                except Exception:
                    pass


# ── Query builder ──────────────────────────────────────────────────────────

DIMS = [
    ('client_ip',    'Client IP'),
    ('program',      'Program'),
    ('client_host',  'Client Host'),
    ('os_user',      'OS User'),
    ('service_name', 'Service'),
    ('instance_name','Instance'),
    ('server_type',  'Server Type'),
    ('date',         'Date'),
    ('hour',         'Hour'),
    ('action',       'Action'),
    ('status_code',  'Status Code'),
]
DIMKEYS   = [k for k, _ in DIMS]
COUNTABLE = ['client_ip', 'program', 'client_host', 'os_user', 'service_name']


def _build_sql(group_by, limit=2000):
    valid = [c for c in group_by if c in DIMKEYS] or ['client_ip']
    dlabel = dict(DIMS)
    sel, hdr = [], []

    for c in valid:
        sel.append(f"COALESCE(CAST({c} AS TEXT), '(unknown)') AS {c}")
        hdr.append(dlabel[c])

    sel += [
        f"{C_CNT} AS connections",
        f"{C_SUCC} AS success",
        f"{C_CNT}-{C_SUCC} AS failures",
        f"ROUND(100.0*{C_SUCC}/{C_CNT}, 1) AS pct",
    ]
    hdr += ["Connections", "Success", "Failures", "% Success"]

    for c in COUNTABLE:
        if c not in valid:
            sel.append(f"COUNT(DISTINCT {c}) AS u_{c}")
            hdr.append(f"# {dlabel[c]}")

    sel += ["MIN(first_ts)", "MAX(last_ts)"]
    hdr += ["First Seen", "Last Seen"]

    gc  = [f"COALESCE(CAST({c} AS TEXT), '(unknown)')" for c in valid]
    table = 'agg' if any(c in TIME_KEYS for c in valid) else 'agg_nt'
    sql = (f"SELECT {', '.join(sel)} FROM {table} "
           f"GROUP BY {', '.join(gc)} "
           f"ORDER BY connections DESC, {', '.join(gc)} LIMIT {limit}")
    return sql, hdr


# ── Routes ─────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html', dims=DIMS)


@app.route('/upload', methods=['POST'])
def upload():
    files = request.files.getlist('file')
    files = [f for f in files if f and f.filename]
    if not files:
        return jsonify(error='No files provided'), 400

    all_sources, file_names, skipped = [], [], []
    for f in files:
        sources = _resolve_upload(f)
        if not sources:
            skipped.append(f.filename)
        else:
            all_sources.extend(sources)
            file_names.append(f.filename)

    if not all_sources:
        msg = ('No valid Oracle listener log files found in: '
               + ', '.join(skipped)) if skipped else 'No valid listener log files provided'
        return jsonify(error=msg), 400

    # Check compatibility — warn but do NOT hard-block
    warning_msg = None
    is_rac = False
    if len(all_sources) > 1:
        fps = [_fingerprint_source(s) for s in all_sources]
        ok, reason = _compatible_databases(fps)
        if not ok:
            warning_msg = reason
        # RAC = multiple distinct instance base names across files
        all_bases = set()
        for fp in fps:
            for inst in fp['instances']:
                all_bases.add(_instance_base(inst))
        is_rac = len(all_bases) > 1

    sid = str(uuid.uuid4())
    dp = _new_db_path()
    now = time.time()

    if warning_msg:
        with _LOCK:
            SESSIONS[sid] = dict(
                status='pending_confirm',
                log_sources=all_sources,
                db_path=dp,
                file_names=file_names,
                warning_msg=warning_msg,
                created_at=now,
                last_access=now,
            )
        return jsonify(warning=True, warning_msg=warning_msg, session_id=sid, is_rac=is_rac)

    with _LOCK:
        SESSIONS[sid] = dict(status='parsing', parsed=0, lines_done=0,
                             total_lines=1, pct=0, db_path=dp,
                             file_names=file_names,
                             created_at=now, last_access=now)

    threading.Thread(target=_worker, args=(sid, all_sources, dp), daemon=True).start()
    return jsonify(session_id=sid, file_count=len(all_sources), is_rac=is_rac)


@app.route('/confirm/<sid>', methods=['POST'])
def confirm(sid):
    with _LOCK:
        s = _get_session(sid)
        if not s or s.get('status') != 'pending_confirm':
            return jsonify(error='Invalid session'), 400
        log_sources = s.pop('log_sources')
        s.pop('warning_msg', None)
        s.update(status='parsing', parsed=0, lines_done=0, total_lines=1, pct=0)

    threading.Thread(
        target=_worker,
        args=(sid, log_sources, s['db_path']),
        daemon=True
    ).start()
    return jsonify(ok=True)


@app.route('/cancel/<sid>', methods=['POST'])
def cancel_session(sid):
    with _LOCK:
        s = SESSIONS.pop(sid, None)
    if s:
        _discard_session(s)
    return jsonify(ok=True)


@app.route('/progress/<sid>')
def progress(sid):
    def gen():
        for _ in range(1200):   # up to 10 minutes
            with _LOCK:
                s = {k: v for k, v in (_get_session(sid) or {}).items()
                     if k not in ('db_path', 'log_sources')}
            if not s:
                yield f"data: {json.dumps({'error': 'session not found'})}\n\n"
                break
            yield f"data: {json.dumps(s)}\n\n"
            if s.get('status') in ('ready', 'error'):
                break
            time.sleep(0.5)
    return Response(gen(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/query/<sid>')
def query(sid):
    with _LOCK:
        s = _get_session(sid)
    if not s or s['status'] != 'ready':
        return jsonify(error='Session not ready'), 400

    sql, hdr = _build_sql(
        request.args.getlist('g'),
        min(int(request.args.get('limit', 2000)), 10000),
    )
    conn = sqlite3.connect(s['db_path'])
    rows = conn.execute(sql).fetchall()
    conn.close()
    return jsonify(headers=hdr, rows=[list(r) for r in rows])


@app.route('/export/<sid>')
def export(sid):
    with _LOCK:
        s = _get_session(sid)
    if not s or s['status'] != 'ready':
        return jsonify(error='Session not ready'), 400

    sql, hdr = _build_sql(request.args.getlist('g'), 100000)
    conn = sqlite3.connect(s['db_path'])
    rows = conn.execute(sql).fetchall()
    conn.close()

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = 'Analysis'

    hfill = PatternFill(start_color='2563EB', end_color='2563EB', fill_type='solid')
    hfont = Font(color='FFFFFF', bold=True)
    ws.append(hdr)
    for cell in ws[1]:
        cell.fill = hfill
        cell.font = hfont
        cell.alignment = Alignment(horizontal='center')

    for row in rows:
        ws.append(list(row))

    for col in ws.columns:
        w = max((len(str(c.value or '')) for c in col), default=10)
        ws.column_dimensions[col[0].column_letter].width = min(w + 2, 50)
    ws.freeze_panes = 'A2'

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)

    label = '_'.join(request.args.getlist('g')) or 'analysis'
    return send_file(
        buf, as_attachment=True,
        download_name=f'listener_{label}.xlsx',
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    )


@app.route('/ipmap/<sid>')
def ipmap(sid):
    with _LOCK:
        s = _get_session(sid)
    if not s or s['status'] != 'ready':
        return jsonify(error='Not ready'), 400

    conn = sqlite3.connect(s['db_path'])
    total = _total(conn)

    rows = conn.execute(f"""
        SELECT
            a1.client_ip,
            SUM(a1.cnt)                                                    AS connections,
            COALESCE(SUM(a1.success*a1.cnt), 0)                            AS success,
            SUM(a1.cnt) - COALESCE(SUM(a1.success*a1.cnt), 0)              AS failures,
            (SELECT a2.client_host FROM agg_nt a2
             WHERE a2.client_ip = a1.client_ip AND a2.client_host IS NOT NULL
             GROUP BY a2.client_host ORDER BY SUM(a2.cnt) DESC, a2.client_host
             LIMIT 1)                                                      AS primary_host,
            COUNT(DISTINCT a1.program)                                     AS programs,
            MIN(a1.first_ts)                                               AS first_seen,
            MAX(a1.last_ts)                                                AS last_seen
        FROM agg_nt a1
        WHERE a1.client_ip IS NOT NULL
        GROUP BY a1.client_ip
        ORDER BY connections DESC, a1.client_ip
    """).fetchall()
    conn.close()

    return jsonify(total=total, ips=[{
        'ip': r[0], 'connections': r[1], 'success': r[2], 'failures': r[3],
        'host': r[4], 'programs': r[5], 'first': r[6], 'last': r[7],
        'pct': round(100 * r[1] / total, 2),
    } for r in rows])


def _total(conn):
    return conn.execute(f"SELECT {C_CNT} FROM agg_nt").fetchone()[0] or 1


def _ip_detail(conn, ip, total_all, with_failures=True):
    """Per-IP breakdown used by /detail and by the offline HTML report."""
    def q(sql):
        return [list(r) for r in conn.execute(sql, (ip,)).fetchall()]

    basic = conn.execute(f"""
        SELECT {C_CNT}, COALESCE({C_SUCC},0),
               {C_CNT}-COALESCE({C_SUCC},0),
               COUNT(DISTINCT program), COUNT(DISTINCT client_host),
               COUNT(DISTINCT os_user), COUNT(DISTINCT service_name),
               MIN(first_ts), MAX(last_ts)
        FROM agg_nt WHERE client_ip = ?
    """, (ip,)).fetchone()
    total = basic[0] or 0

    d = dict(
        ip=ip,
        total=total, success=basic[1], failures=basic[2],
        uniq_programs=basic[3], uniq_hosts=basic[4],
        uniq_users=basic[5], uniq_services=basic[6],
        first=basic[7], last=basic[8],
        pct=round(100 * total / total_all, 2),
        programs  = q(f"SELECT COALESCE(program,'(unknown)'),{C_CNT},COALESCE({C_SUCC},0) FROM agg_nt WHERE client_ip=? GROUP BY program ORDER BY {C_CNT} DESC, program"),
        hosts     = q(f"SELECT COALESCE(client_host,'(no hostname)'),{C_CNT} FROM agg_nt WHERE client_ip=? GROUP BY client_host ORDER BY {C_CNT} DESC, client_host"),
        users     = q(f"SELECT COALESCE(os_user,'(unknown)'),{C_CNT} FROM agg_nt WHERE client_ip=? GROUP BY os_user ORDER BY {C_CNT} DESC, os_user"),
        services  = q(f"SELECT COALESCE(service_name,'(unknown)'),{C_CNT} FROM agg_nt WHERE client_ip=? GROUP BY service_name ORDER BY {C_CNT} DESC, service_name"),
        by_hour   = q(f"SELECT hour,{C_CNT} FROM agg WHERE client_ip=? GROUP BY hour ORDER BY hour"),
        by_date   = q(f"SELECT date,{C_CNT} FROM agg WHERE client_ip=? GROUP BY date ORDER BY date"),
        fail_codes= q(f"SELECT status_code,{C_CNT} FROM agg_nt WHERE client_ip=? AND success=0 GROUP BY status_code ORDER BY {C_CNT} DESC, status_code"),
        by_hour_by_date = q(f"SELECT date,hour,{C_CNT} FROM agg WHERE client_ip=? GROUP BY date,hour ORDER BY date,hour"),
    )
    if with_failures:
        d.update(
            by_hour_failures  = q(f"SELECT hour,{C_CNT} FROM agg WHERE client_ip=? AND success=0 GROUP BY hour ORDER BY hour"),
            by_date_failures  = q(f"SELECT date,{C_CNT} FROM agg WHERE client_ip=? AND success=0 GROUP BY date ORDER BY date"),
            by_hour_by_date_failures = q(f"SELECT date,hour,{C_CNT} FROM agg WHERE client_ip=? AND success=0 GROUP BY date,hour ORDER BY date,hour"),
        )
    return d


@app.route('/detail/<sid>')
def detail(sid):
    with _LOCK:
        s = _get_session(sid)
    if not s or s['status'] != 'ready':
        return jsonify(error='Not ready'), 400

    ip = request.args.get('ip', '').strip()
    if not ip:
        return jsonify(error='No IP specified'), 400

    conn = sqlite3.connect(s['db_path'])

    result = _ip_detail(conn, ip, _total(conn))
    conn.close()
    return jsonify(result)


@app.route('/failures_drilldown/<sid>')
def failures_drilldown(sid):
    with _LOCK:
        s = _get_session(sid)
    if not s or s['status'] != 'ready':
        return jsonify(error='Not ready'), 400

    level = request.args.get('level', 'date')   # date | hour | ip
    date  = request.args.get('date', None)
    try:
        hour = int(request.args.get('hour', -1))
    except (ValueError, TypeError):
        hour = -1

    conn = sqlite3.connect(s['db_path'])

    if level == 'date':
        rows = conn.execute(
            f"SELECT date, {C_CNT}-COALESCE({C_SUCC},0) AS failures "
            "FROM agg WHERE success=0 GROUP BY date ORDER BY date"
        ).fetchall()
        result = {'level': 'date', 'labels': [r[0] for r in rows], 'failures': [r[1] for r in rows]}

    elif level == 'hour' and date:
        rows = conn.execute(
            f"SELECT hour, {C_CNT}-COALESCE({C_SUCC},0) AS failures "
            "FROM agg WHERE success=0 AND date=? GROUP BY hour ORDER BY hour",
            (date,)
        ).fetchall()
        # fill all 24 hours so the axis is complete
        hour_map = {r[0]: r[1] for r in rows}
        result = {
            'level': 'hour', 'date': date,
            'labels': [f'{h:02d}h' for h in range(24)],
            'failures': [hour_map.get(h, 0) for h in range(24)],
        }

    elif level == 'ip' and date and hour >= 0:
        rows = conn.execute(
            f"SELECT COALESCE(client_ip,'(unknown)'), {C_CNT}-COALESCE({C_SUCC},0) AS failures "
            "FROM agg WHERE success=0 AND date=? AND hour=? "
            "GROUP BY client_ip ORDER BY failures DESC, client_ip LIMIT 50",
            (date, hour)
        ).fetchall()
        result = {
            'level': 'ip', 'date': date, 'hour': hour,
            'labels': [r[0] for r in rows], 'failures': [r[1] for r in rows],
        }
    else:
        conn.close()
        return jsonify(error='Invalid parameters'), 400

    conn.close()
    return jsonify(result)


@app.route('/export-html/<sid>')
def export_html(sid):
    with _LOCK:
        s = _get_session(sid)
    if not s or s['status'] != 'ready':
        return jsonify(error='Session not ready'), 400

    conn = sqlite3.connect(s['db_path'])

    def q(sql, p=()):
        return [list(r) for r in conn.execute(sql, p).fetchall()]

    # Pre-compute all groupings
    queries = {}
    for dim in DIMKEYS:
        sql, hdr = _build_sql([dim], 5000)
        rows = conn.execute(sql).fetchall()
        queries[dim] = {'headers': hdr, 'rows': [list(r) for r in rows]}

    # Multi-dim groupings used by the Quick Views buttons
    for dims in [['client_ip', 'program'], ['client_ip', 'program', 'client_host'],
                 ['date', 'hour']]:
        key = ','.join(dims)
        if key not in queries:
            sql, hdr = _build_sql(dims, 5000)
            rows = conn.execute(sql).fetchall()
            queries[key] = {'headers': hdr, 'rows': [list(r) for r in rows]}

    # Status codes for fail panel
    sc_sql, sc_hdr = _build_sql(['status_code'], 200)
    sc_rows = conn.execute(sc_sql).fetchall()
    queries['status_code'] = {'headers': sc_hdr, 'rows': [list(r) for r in sc_rows]}

    # Aggregate tables, so the offline report can compute any Custom Group By
    # combination in the browser (skipped when too large for an HTML file;
    # the report then only offers the pre-computed groupings above).
    def table_dump(name, keys):
        n = conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
        if n > REPORT_MAX_AGG_ROWS:
            return None
        cols = keys + ['cnt', 'first_ts', 'last_ts']
        return {'cols': cols,
                'rows': q(f"SELECT {', '.join(cols)} FROM {name}")}

    agg_nt_dump = table_dump('agg_nt', AGG_NT_KEYS)
    agg_dump = table_dump('agg', AGG_KEYS)

    # Failures drill-down (date -> hour -> IP), same data as /failures_drilldown
    fail_drill = q(f"SELECT date, hour, client_ip, {C_CNT} FROM agg WHERE success=0 "
                   "GROUP BY date, hour, client_ip")

    # IP details (incl. failure series): top 500 IPs + every IP with failures
    ip_sql, _ = _build_sql(['client_ip'], 500)
    top_ips = [r[0] for r in conn.execute(ip_sql).fetchall() if r[0] != '(unknown)']
    fail_ips = [r[0] for r in conn.execute(
        "SELECT DISTINCT client_ip FROM agg_nt WHERE success=0 AND client_ip IS NOT NULL")]
    total_all = _total(conn)

    ip_details = {ip: _ip_detail(conn, ip, total_all)
                  for ip in dict.fromkeys(top_ips + fail_ips)}
    summary = s.get('summary') or _summary(conn)
    conn.close()

    report_data = {
        'files'       : s.get('file_names', []),
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'summary'     : summary,
        'queries'     : queries,
        'ip_details'  : ip_details,
        'dims'        : DIMS,
        'countable'   : COUNTABLE,
        'agg_nt'      : agg_nt_dump,
        'agg'         : agg_dump,
        'fail_drill'  : fail_drill,
    }

    data_script = ('<script>window.__REPORT__ = '
                   + json.dumps(report_data, default=str).replace('</', '<\\/')
                   + ';</script>')

    html = render_template('index.html', dims=DIMS)

    # Inline Chart.js so the report works 100% offline (no CDN dependency)
    chartjs_path = os.path.join(app.static_folder, 'chart.umd.min.js')
    try:
        with open(chartjs_path, 'r', encoding='utf-8') as f:
            chartjs_content = f.read()
        cdn_tag = '<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>'
        html = html.replace(cdn_tag, f'<script>{chartjs_content}</script>', 1)
    except Exception:
        pass  # fallback: keep CDN tag if file not found

    html = html.replace('</head>', data_script + '\n</head>', 1)

    filename = 'OLLDA_report_{}.html'.format(
        datetime.now().strftime('%Y%m%d_%H%M%S'))
    resp = make_response(html)
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    resp.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return resp


if __name__ == '__main__':
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    host  = os.environ.get('FLASK_HOST', '127.0.0.1')
    port  = int(os.environ.get('FLASK_PORT', '5000'))
    app.run(debug=debug, host=host, port=port, threaded=True)
