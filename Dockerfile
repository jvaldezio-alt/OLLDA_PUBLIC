# OLLDA — Oracle Listener Log Discovery & Analyzer
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app.py .
COPY templates/ templates/
COPY static/ static/

# Expose port
EXPOSE 5000

# Run (host 0.0.0.0 makes it reachable outside the container)
CMD ["python", "app.py"]
