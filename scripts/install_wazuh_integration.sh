#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WAZUH_DIR="/var/ossec"
INTEGRATION_DIR="$WAZUH_DIR/integrations"
LOG_DIR="/var/log/ai-soc"

echo "=== SOCMind AI Wazuh Integration Installer ==="

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Run with sudo."
    exit 1
fi

if [ ! -x "$WAZUH_DIR/framework/python/bin/python3" ]; then
    echo "ERROR: Wazuh manager Python was not found."
    echo "Install Wazuh Manager before running this installer."
    exit 1
fi

if [ ! -f "$PROJECT_DIR/integrations/custom-ai_soc.py" ] || \
   [ ! -f "$PROJECT_DIR/integrations/custom-ai_soc" ]; then
    echo "ERROR: Project integration files are missing."
    exit 1
fi

echo "[1/5] Checking Wazuh group..."
if getent group wazuh >/dev/null; then
    WAZUH_GROUP="wazuh"
else
    WAZUH_GROUP="root"
    echo "WARNING: wazuh group not found; using root group."
fi

echo "[2/5] Creating integration directory..."
install -d -o root -g "$WAZUH_GROUP" -m 750 "$INTEGRATION_DIR"

echo "[3/5] Backing up existing integration files..."
BACKUP_DIR="/var/backups/socmind-ai-$(date +%Y%m%d-%H%M%S)"
for file in custom-ai_soc custom-ai_soc.py; do
    if [ -e "$INTEGRATION_DIR/$file" ]; then
        mkdir -p "$BACKUP_DIR"
        cp -a "$INTEGRATION_DIR/$file" "$BACKUP_DIR/"
        echo "Backup created: $BACKUP_DIR/$file"
    fi
done

echo "[4/5] Installing integration files..."
install -o root -g "$WAZUH_GROUP" -m 750 \
    "$PROJECT_DIR/integrations/custom-ai_soc" \
    "$INTEGRATION_DIR/custom-ai_soc"

install -o root -g "$WAZUH_GROUP" -m 750 \
    "$PROJECT_DIR/integrations/custom-ai_soc.py" \
    "$INTEGRATION_DIR/custom-ai_soc.py"

echo "[5/5] Creating AI analysis log directory..."
install -d -o root -g "$WAZUH_GROUP" -m 750 "$LOG_DIR"
touch "$LOG_DIR/ai-analysis.json"
chown root:"$WAZUH_GROUP" "$LOG_DIR/ai-analysis.json"
chmod 660 "$LOG_DIR/ai-analysis.json"

echo
echo "Checking integration Python syntax..."
"$WAZUH_DIR/framework/python/bin/python3" -m py_compile \
    "$INTEGRATION_DIR/custom-ai_soc.py"

echo
echo "SUCCESS: Wazuh integration files installed."
echo
echo "IMPORTANT:"
echo "1. Review wazuh/integration-snippet.xml"
echo "2. Review wazuh/localfile-snippet.xml"
echo "3. Merge rules/local_rules.xml into the existing Wazuh rules file."
echo "4. Back up ossec.conf and local_rules.xml before editing."
echo "5. Validate Wazuh configuration before restarting the manager."
echo
echo "This installer does not edit Wazuh configuration or restart services."
