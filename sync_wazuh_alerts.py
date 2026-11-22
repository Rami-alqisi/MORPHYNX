import json
import subprocess
from pathlib import Path

# ---------- CONFIG ----------
WAZUH_MANAGER_USER = "kali"
WAZUH_MANAGER_HOST = "10.0.0.30"
REMOTE_ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"

LOCAL_RAW_FILE = "raw_alerts.json"
OUTPUT_FILE = "wazuh_alerts.json"

MAX_LINES = 2000
TARGET_IPS = {"10.0.0.10", "10.0.0.20"}


def fetch_remote_alerts():
    ssh_cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        f"{WAZUH_MANAGER_USER}@{WAZUH_MANAGER_HOST}",
        f"sudo cat {REMOTE_ALERTS_FILE}"
    ]

    try:
        result = subprocess.run(
            ssh_cmd,
            check=True,
            capture_output=True,
            text=True,
            timeout=30
        )

        with open(LOCAL_RAW_FILE, "w", encoding="utf-8") as f:
            f.write(result.stdout)

        print(f"[+] Pulled alerts via SSH from {WAZUH_MANAGER_HOST}")
        return True

    except subprocess.CalledProcessError as e:
        print("[!] Failed to fetch alerts via SSH")
        if e.stderr:
            print(e.stderr.strip())
        return False
    except subprocess.TimeoutExpired:
        print("[!] Fetching alerts timed out")
        return False


def read_last_lines(path: str, max_lines: int = 2000):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"{path} not found")

    with p.open("r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    return lines[-max_lines:]


def normalize_alert(obj):
    rule = obj.get("rule", {})
    data = obj.get("data", {})
    agent = obj.get("agent", {}) or {}

    return {
        "id": obj.get("id"),
        "timestamp": obj.get("timestamp"),
        "agent_ip": agent.get("ip"),
        "agent_name": agent.get("name"),
        "dst_ip": (
            data.get("dstip")
            or data.get("destination_ip")
            or obj.get("dstip")
            or obj.get("destination_ip")
        ),
        "src_ip": (
            data.get("srcip")
            or data.get("source_ip")
            or obj.get("srcip")
            or obj.get("source_ip")
        ),
        "rule": {
            "id": rule.get("id"),
            "level": rule.get("level", 0),
            "description": rule.get("description", ""),
            "groups": rule.get("groups", [])
        },
        "location": obj.get("location", ""),
        "decoder": (obj.get("decoder") or {}).get("name", ""),
        "full_log": obj.get("full_log", "")
    }


def is_target_alert(alert):
    return alert.get("agent_ip") in TARGET_IPS


def main():
    if not fetch_remote_alerts():
        return

    raw_lines = read_last_lines(LOCAL_RAW_FILE, MAX_LINES)

    alerts = []
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue

        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        alert = normalize_alert(obj)

        if is_target_alert(alert):
            alerts.append(alert)

    output = {"alerts": alerts}

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"[+] Saved {len(alerts)} filtered alerts into {OUTPUT_FILE}")


if __name__ == "__main__":
    main()