#!/bin/bash
# OLLDA — Local launcher (Linux / macOS)

echo ""
echo "  ██████  ██      ██      ██████   █████ "
echo " ██    ██ ██      ██      ██   ██ ██   ██"
echo " ██    ██ ██      ██      ██   ██ ███████"
echo " ██    ██ ██      ██      ██   ██ ██   ██"
echo "  ██████  ███████ ███████ ██████  ██   ██"
echo ""
echo "  Oracle Listener Log Discovery & Analyzer"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 not found. Please install Python 3.9 or higher."
    exit 1
fi

# Create virtualenv if needed
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate and install dependencies
source venv/bin/activate
pip install -q -r requirements.txt

echo "Starting OLLDA at http://localhost:5000"
echo "Press Ctrl+C to stop."
echo ""

python app.py
