# SOCMind AI — Intelligent SOC Analysis

An AI-powered Security Operations Center using Wazuh, Suricata, FastAPI, Ollama and Qwen2.5.

## Project Overview

This project integrates local AI with traditional security monitoring to analyze security alerts, identify potential risks and generate actionable incident intelligence.

**Special Feature:** AI-generated security analysis is available in Bengali (বাংলা), including incident summaries and recommended actions.

## Technology Stack

- Wazuh 4.14 - SIEM
- Suricata - Network IDS/IPS
- FastAPI - Backend API
- Ollama - Local AI Runtime
- Qwen2.5:1.5B - Language Model
- Ubuntu Linux - Lab Environment
- Python - Development

## Key Features

- Automated security alert analysis
- AI-based risk classification
- Bengali incident summaries
- Security evidence analysis
- Recommended response actions
- Local AI processing without paid cloud AI APIs
- SOC dashboard visualization

## Dashboard Highlights

- Total AI-analyzed alerts
- High and Critical risk monitoring
- Risk distribution
- AI-generated incident summaries
- Recommended security actions

## Architecture

Security Events
      |
      v
Wazuh SIEM + Suricata IDS
      |
      v
Wazuh Integration
      |
      v
FastAPI Backend
      |
      v
Ollama + Qwen2.5
      |
      v
AI Incident Intelligence
      |
      v
Wazuh Dashboard

## Project Status

Ongoing educational and defensive cybersecurity project.

## Security & Privacy

- AI inference runs locally using Ollama.
- No paid cloud AI API is required.
- Do not publish sensitive logs, credentials or private configuration.

## Author

Cybersecurity | SOC | Blue Team | AI Security Automation

---

Disclaimer: This project is intended for educational and defensive cybersecurity purposes.
