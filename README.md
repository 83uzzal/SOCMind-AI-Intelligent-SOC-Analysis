# SOCMind AI — Intelligent SOC Analysis

**Turning Security Alerts into AI-Powered Incident Intelligence.**

SOCMind AI is an educational defensive cybersecurity project integrating Wazuh, Suricata, FastAPI, Ollama and Qwen2.5.

AI-generated incident summaries and recommended actions are available in Bengali (বাংলা).

## Technology Stack

- Wazuh 4.14 — SIEM
- Suricata — Network IDS
- FastAPI — Backend API
- Ollama — Local AI runtime
- Qwen2.5:1.5B — Language model
- Ubuntu Linux — Server
- Python — Development

## Key Features

- Automated security alert analysis
- AI-assisted risk classification
- Bengali incident summaries
- Security evidence extraction
- Recommended response actions
- Local AI inference without paid cloud AI APIs
- Wazuh dashboard visualization
- Windows security event and FIM monitoring support


## Architecture

Security Events → Wazuh + Suricata → Custom Integration → FastAPI → Ollama + Qwen2.5 → AI Incident Intelligence → Wazuh Dashboard

## System Requirements

- Ubuntu Server 22.04 or a compatible supported Ubuntu release
- 4 CPU cores or more
- 8 GB RAM minimum; 12–16 GB recommended
- 40 GB or more free disk space
- Internet access for installation and model download
- Additional resources for Wazuh indexing and AI inference

CPU-only inference is supported but may be slower.

**Important:** Install and verify Wazuh Manager and Suricata before installing the SOCMind integration. Follow official Wazuh documentation for a compatible installation topology.

## Fresh Ubuntu Deployment

### 1. Install prerequisites

```bash
sudo apt update
sudo apt install -y git curl python3 python3-venv python3-pip
```

### 2. Clone the repository

```bash
git clone https://github.com/83uzzal/SOCMind-AI-Intelligent-SOC-Analysis.git
cd SOCMind-AI-Intelligent-SOC-Analysis
```

### 3. Install Ollama, the AI model and FastAPI

Run as a normal sudo-enabled user, not as root:

```bash
chmod +x scripts/install_ai_api.sh
./scripts/install_ai_api.sh
```

The installer creates a Python virtual environment, installs project dependencies, enables Ollama, downloads `qwen2.5:1.5b`, and configures the FastAPI systemd service.

### 4. Verify the API

```bash
sudo systemctl status ai-soc-api
curl http://127.0.0.1:8000/health
ollama list
```

Expected API health response indicates `api` is healthy and `ollama` is connected.

## Wazuh Integration

### 5. Install the custom integration

Run this from the cloned project directory:

```bash
chmod +x scripts/install_wazuh_integration.sh
sudo ./scripts/install_wazuh_integration.sh
```

The installer backs up existing integration files, installs the SOCMind integration scripts, creates the AI analysis log directory, and checks Python syntax.

### 6. Configure Wazuh

Review and manually merge these project snippets into the existing Wazuh configuration:

- `wazuh/integration-snippet.xml` — custom AI integration
- `wazuh/localfile-snippet.xml` — JSON log monitoring
- `rules/local_rules.xml` — custom detection rules

**Important:** Back up `/var/ossec/etc/ossec.conf` and the existing rules file before editing. Merge the rules into the appropriate existing rules configuration; do not replace the entire configuration file.

### 7. Validate and restart Wazuh Manager

After merging the configuration snippets:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
```

Only restart Wazuh Manager after the configuration test succeeds.

## Windows Endpoint Setup

### 8. Connect a Windows endpoint

1. Install and enroll the Wazuh Windows agent using the [official Wazuh guide](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html).
2. Review `windows/eventchannel-snippet.xml` and merge its settings into the existing Windows agent `ossec.conf`.
3. Add the contents of `windows/fim-snippet.xml` inside the existing `syscheck` section. This enables monitoring of `C:\\SOC-Monitoring`.
4. Restart the Wazuh agent on Windows.

**Important:** Do not replace the complete Windows agent configuration with these snippets.

## Dashboard Verification

### 9. Verify AI-analyzed alerts

1. Open the Wazuh Dashboard.
2. Go to Discover and search for `rule.id:"100120"`.
3. Check AI-generated incident summaries, risk levels, evidence, and recommended actions.
4. Create your own dashboard visualizations using the AI analysis fields.

Dashboard saved objects are not automatically imported by this project; configure visualizations manually.

## Troubleshooting

Check the API service:

```bash
sudo journalctl -u ai-soc-api -n 50 --no-pager
```

Check Wazuh integration logs:

```bash
sudo tail -n 50 /var/ossec/logs/integrations.log
sudo tail -n 50 /var/log/ai-soc/ai-analysis.json
```

## Security and Privacy

- The API binds to `127.0.0.1` by default and is intended for local integration.
- Do not commit passwords, API keys, private logs, or sensitive endpoint data.
- Review AI-generated analysis before taking incident response actions.
- Keep Ubuntu, Wazuh, Suricata, Python packages, and Ollama updated.

## Limitations

- Wazuh Manager and Suricata must be installed separately before configuring the integration.
- CPU-only AI inference may be slow.
- Dashboard visualizations require manual setup.
- The integration analyzes only the rule IDs configured in the Wazuh integration snippet.

## Disclaimer

SOCMind AI is an educational defensive cybersecurity project for authorized lab environments. It is not a replacement for professional security monitoring, incident response, or human review.

## Author

Cybersecurity | SOC | Blue Team | AI Security Automation

