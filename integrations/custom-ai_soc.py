#!/var/ossec/framework/python/bin/python3
import json
import sys
import requests
from datetime import datetime, timezone

API_URL = "http://127.0.0.1:8000/analyze"
LOG_FILE = "/var/log/ai-soc/ai-analysis.json"
TIMEOUT = 300

def main():
    if len(sys.argv) < 3:
        sys.exit(1)

    try:
        with open(sys.argv[1], "r", encoding="utf-8") as f:
            alert = json.load(f)

        rule = alert.get("rule", {})
        data = alert.get("data", {})
        suricata = data.get("alert", {})

        if str(rule.get("id")) not in {"100121", "99915", "60122", "550", "553", "554"}:
            return

        # Skip stale alerts to prevent AI analysis backlog.
        timestamp = alert.get("timestamp")
        if timestamp:
            try:
                alert_time = datetime.fromisoformat(
                    timestamp.replace("Z", "+00:00")
                )
                age_seconds = (
                    datetime.now(timezone.utc)
                    - alert_time.astimezone(timezone.utc)
                ).total_seconds()
                if age_seconds > 120:
                    print(
                        f"Skipping stale alert: age={age_seconds:.0f}s",
                        file=sys.stderr,
                    )
                    return
            except (ValueError, TypeError):
                pass

        if str(rule.get("id")) == "60122":
            win = data.get("win", {})
            system = win.get("system", {})
            event = win.get("eventdata", {})
            agent = alert.get("agent", {})

            summary = {
                "event_type": "windows_security_event",
                "timestamp": alert.get("timestamp"),
                "rule_id": rule.get("id"),
                "rule_description": rule.get("description"),
                "rule_level": rule.get("level"),
                "agent_name": agent.get("name"),
                "agent_ip": agent.get("ip"),
                "event_id": system.get("eventID"),
                "computer": system.get("computer"),
                "severity": system.get("severityValue"),
                "username": event.get("targetUserName"),
                "logon_type": event.get("logonType"),
                "failure_status": event.get("status"),
                "failure_sub_status": event.get("subStatus"),
                "failure_reason": event.get("failureReason"),
                "source_ip": event.get("ipAddress"),
                "source_port": event.get("ipPort"),
                "workstation": event.get("workstationName"),
                "process_name": event.get("processName"),
                "authentication_package": event.get("authenticationPackageName"),
                "event_message": system.get("message"),
            }
        elif str(rule.get("id")) in {"550", "553", "554"}:
            syscheck = alert.get("syscheck", {})
            file_path = str(syscheck.get("path", "")).lower()

            # Only analyze changes inside the dedicated SOC test folder.
            if not file_path.startswith("c:\\soc-monitoring\\"):
                return

            summary = {
                "event_type": "fim_file_change",
                "timestamp": alert.get("timestamp"),
                "rule_id": rule.get("id"),
                "rule_description": rule.get("description"),
                "rule_level": rule.get("level"),
                "agent_name": alert.get("agent", {}).get("name"),
                "agent_ip": alert.get("agent", {}).get("ip"),
                "file_path": syscheck.get("path"),
                "file_event": syscheck.get("event"),
                "fim_mode": syscheck.get("mode"),
                "size_after": syscheck.get("size_after"),
                "size_before": syscheck.get("size_before"),
                "sha256_after": syscheck.get("sha256_after"),
                "sha256_before": syscheck.get("sha256_before")
            }
        else:
            summary = {
                "event_type": "suricata_alert",
                "timestamp": alert.get("timestamp"),
                "rule_id": rule.get("id"),
                "rule_description": rule.get("description"),
                "rule_level": rule.get("level"),
                "source_ip": data.get("src_ip"),
                "source_port": data.get("src_port"),
                "destination_ip": data.get("dest_ip"),
                "destination_port": data.get("dest_port"),
                "protocol": data.get("proto"),
                "action": suricata.get("action"),
                "signature": suricata.get("signature"),
                "category": suricata.get("category"),
                "suricata_severity": suricata.get("severity"),
            }

        response = requests.post(
            API_URL,
            json={"alert": json.dumps(summary, ensure_ascii=False)},
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        result = response.json()

        record = {
            **summary,
            "event_type": "ai_soc_analysis",
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            "risk_level": result.get("risk_level", ""),
            "incident_summary": result.get("incident_summary", ""),
            "evidence": result.get("evidence", []),
            "recommended_actions": result.get("recommended_actions", []),
            "analysis": result.get("analysis", ""),
        }

        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

        print(json.dumps({
            "rule_id": rule.get("id"),
            "analysis": record["analysis"]
        }, ensure_ascii=False))

    except (OSError, json.JSONDecodeError, requests.RequestException) as exc:
        print(f"AI SOC integration error: {exc}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
