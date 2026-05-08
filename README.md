# OLLDA — Oracle Listener Log Discovery & Analyzer

> Local listener log analyzer for Oracle environments (including RAC) — upload your listener.log and instantly explore connections, IPs, errors and trends.

**OLLDA** is a lightweight web application that runs entirely on your local machine. No data is sent to any external server. Your listener logs never leave your computer.

---

## Features

- Parse one or multiple `listener.log` files simultaneously (RAC-ready)
- Explore connections grouped by IP, program, OS user, service, instance, and more
- IP Tree view with subnet-level aggregation
- Filter by failures only — identify problematic IPs and error codes instantly
- Export results to Excel
- Built-in Oracle error code dictionary (ORA-XXXXX descriptions)
- Dark / light theme

---

## Quick Start

### Option 1 — Docker (recommended, no Python required)

```bash
docker run -p 5000:5000 jvaldeziodba/ollda
```

Then open **http://localhost:5000** in your browser. That's it.

> **Docker Hub:** [hub.docker.com/r/jvaldeziodba/ollda](https://hub.docker.com/r/jvaldeziodba/ollda)

---

### Option 2 — Windows (Python required)

```bat
run.bat
```

### Option 2 — Linux / macOS (Python required)

```bash
chmod +x run.sh
./run.sh
```

Both scripts will:
1. Create a Python virtual environment (`venv/`)
2. Install all dependencies
3. Start the app at **http://localhost:5000**

---

### Option 3 — Manual Setup

```bash
# Clone the repository
git clone https://github.com/jvaldezio-alt/OLLDA_PUBLIC.git
cd OLLDA_PUBLIC

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate.bat     # Windows

# Install dependencies
pip install -r requirements.txt

# Run
python app.py
```

Then open your browser at **http://localhost:5000**

---

## Requirements

| Method | Requirements |
|--------|-------------|
| Docker | Docker Desktop |
| run.bat / run.sh | Python 3.9+ |
| Manual | Python 3.9+, pip |

---

## How to Use

1. Open **http://localhost:5000** in your browser
2. Drag and drop (or select) one or more `listener.log` files
3. Click **Start Analysis**
4. Explore results using the **Table**, **Charts**, and **IP Tree** views
5. Use **Group by** to pivot the data by IP, program, user, service, etc.
6. Export to Excel with one click

---

## Privacy & Security

All processing happens **locally in memory** on your machine. Files are never uploaded to any external server or written to permanent storage. Each session is isolated and discarded when the browser tab is closed.

---

## Legal Disclaimer

This tool is provided **"as is"** for informational and diagnostic purposes only. The author accepts no liability for data leakage, policy violations, security breaches, or any damages arising from its use. Users are solely responsible for ensuring compliance with applicable laws and their organisation's security policies before uploading any data.

---

## Author

**José Valdézio** — Oracle DBA  
[linktr.ee/jvaldeziodba](https://linktr.ee/jvaldeziodba)  
[ora0800dba.com.br](https://ora0800dba.com.br)
