#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_USER="$(id -un)"

if [ "$SERVICE_USER" = "root" ]; then
    echo "ERROR: Run this script as a normal user, not root."
    exit 1
fi

if ! command -v sudo >/dev/null 2>&1; then
    echo "ERROR: sudo is required."
    exit 1
fi

echo "=== SOCMind AI API Installation ==="
echo "Project: $PROJECT_DIR"
echo "User: $SERVICE_USER"

echo "[1/7] Installing system dependencies..."
sudo apt-get update
sudo apt-get install -y curl python3 python3-venv python3-pip

echo "[2/7] Installing Ollama if needed..."
if ! command -v ollama >/dev/null 2>&1; then
    curl -fsSL https://ollama.com/install.sh | sh
else
    echo "Ollama is already installed."
fi

echo "[3/7] Enabling Ollama service..."
sudo systemctl enable --now ollama

echo "[4/7] Creating Python virtual environment..."
if [ ! -d "$PROJECT_DIR/venv" ]; then
    python3 -m venv "$PROJECT_DIR/venv"
fi

"$PROJECT_DIR/venv/bin/python" -m pip install --upgrade pip
"$PROJECT_DIR/venv/bin/pip" install -r "$PROJECT_DIR/requirements.txt"

echo "[5/7] Downloading AI model..."
ollama pull qwen2.5:1.5b

echo "[6/7] Installing SOCMind AI systemd service..."
TEMP_SERVICE="$(mktemp)"
trap 'rm -f "$TEMP_SERVICE"' EXIT

sed \
    -e "s|@SERVICE_USER@|$SERVICE_USER|g" \
    -e "s|@PROJECT_DIR@|$PROJECT_DIR|g" \
    "$PROJECT_DIR/systemd/ai-soc-api.service.example" > "$TEMP_SERVICE"

sudo install -m 644 "$TEMP_SERVICE" /etc/systemd/system/ai-soc-api.service
sudo systemctl daemon-reload
sudo systemctl enable --now ai-soc-api

echo "[7/7] Checking API health..."
sleep 3

if curl -fsS http://127.0.0.1:8000/health; then
    echo
    echo "SUCCESS: SOCMind AI API is running."
else
    echo
    echo "WARNING: API health check failed."
    echo "Check logs: sudo journalctl -u ai-soc-api -n 50 --no-pager"
    exit 1
fi

echo
echo "Installation completed."
