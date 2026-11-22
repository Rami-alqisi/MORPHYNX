"""
MORPHYNX — Live Monitor (tail -f mode)
يقرأ الـ alerts من Wazuh Manager عبر SSH ويشغل الدفاع عند الحاجة.

التحسينات:
- run_defense() بيشتغل في thread منفصل عشان ما يبلوك قراءة الـ alerts
- assets_config.json يُقرأ مرة واحدة عند البدء لتحديد الـ role لكل IP
- lock للـ attack_counters لضمان الـ thread safety
- alerts_buffer محدود بـ 500 entry ويُحفظ بشكل آمن
- SSH يُعاد الاتصال تلقائياً عند الانقطاع
"""

import json
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
WAZUH_MANAGER_USER  = "kali"
WAZUH_MANAGER_HOST  = "10.0.0.30"
REMOTE_ALERTS_FILE  = "/var/ossec/logs/alerts/alerts.json"
CORE_SCRIPT         = "morphynx_core.py"
WAZUH_FILE          = "wazuh_alerts.json"
ASSETS_CONFIG_FILE  = "assets_config.json"
DEFENSE_STATE_FILE  = "defense_state.json"

ATTACK_THRESHOLD    = 3
BUFFER_MAX          = 500
SSH_RECONNECT_DELAY = 5   # ثواني قبل إعادة الاتصال

# ─────────────────────────────────────────────
# GLOBALS — thread-safe
# ─────────────────────────────────────────────
_counter_lock   = threading.Lock()
_buffer_lock    = threading.Lock()
_defense_lock   = threading.Lock()   # منع تشغيل دفاعين في نفس الوقت لنفس الـ IP

attack_counters: dict[str, int] = {}
alerts_buffer:   list           = []
defense_running: set[str]       = set()   # IPs اللي شغّالة عليها defense الحين

# ─────────────────────────────────────────────
# ASSET REGISTRY — يُبنى من assets_config.json
# ─────────────────────────────────────────────
TARGET_IPS: set[str]        = set()
IP_TO_ROLE: dict[str, str]  = {}   # IP → role


def load_assets():
    """يقرأ assets_config.json ويبني الـ registry."""
    global TARGET_IPS, IP_TO_ROLE, attack_counters
    p = Path(ASSETS_CONFIG_FILE)
    if not p.exists():
        print(f"[!] {ASSETS_CONFIG_FILE} not found — using hardcoded defaults.", flush=True)
        TARGET_IPS    = {"10.0.0.10", "10.0.0.20"}
        IP_TO_ROLE    = {"10.0.0.10": "web_server", "10.0.0.20": "db_server"}
        attack_counters = {ip: 0 for ip in TARGET_IPS}
        return

    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        for asset in data.get("assets", []):
            ip   = asset.get("ip")
            role = asset.get("role")
            if ip:
                TARGET_IPS.add(ip)
                IP_TO_ROLE[ip] = role or "unknown"
        attack_counters = {ip: 0 for ip in TARGET_IPS}
        print(f"[*] Loaded {len(TARGET_IPS)} asset(s) from {ASSETS_CONFIG_FILE}", flush=True)
    except Exception as e:
        print(f"[!] Failed to load assets config: {e}", flush=True)
        TARGET_IPS    = {"10.0.0.10", "10.0.0.20"}
        IP_TO_ROLE    = {"10.0.0.10": "web_server", "10.0.0.20": "db_server"}
        attack_counters = {ip: 0 for ip in TARGET_IPS}


# ─────────────────────────────────────────────
# KEYWORD SETS — frozensets للبحث O(1)
# ─────────────────────────────────────────────
_COMMON_KW = frozenset([
    "authentication failure", "failed login", "invalid user",
    "brute force", "attack",
])
_WEB_KW = frozenset([
    "web", "apache", "nginx", "http", "accesslog", "scan", "nmap",
    "web server 400 error code", "sql injection", "sqlmap", "' or '1'='1",
])
_DB_KW = frozenset([
    "sql", "mysql", "mariadb", "postgres", "database",
    "access denied", "connection denied", "too many connections",
    "denied", "db", "login failed", "authentication failed",
    "multiple failed logins", "access denied for user",
])
_ALLOWED_GROUPS = {
    "web_server": frozenset(["attack", "authentication_failed", "sshd", "web", "accesslog"]),
    "db_server":  frozenset(["attack", "authentication_failed", "sshd", "database", "mysql", "sql"]),
    None:         frozenset(["attack", "authentication_failed", "sshd",
                              "web", "accesslog", "database", "mysql", "sql"]),
}


def print_banner():
    print("=" * 60, flush=True)
    print("     MORPHYNX — LIVE MONITOR (tail -f mode)", flush=True)
    print("=" * 60, flush=True)
    print(f"[*] Watching  : {', '.join(sorted(TARGET_IPS))}", flush=True)
    print(f"[*] Threshold : {ATTACK_THRESHOLD} attack alerts", flush=True)
    print(f"[*] Role map  : {IP_TO_ROLE}\n", flush=True)


def normalize_alert(obj: dict) -> dict:
    rule  = obj.get("rule", {})
    data  = obj.get("data", {})
    agent = obj.get("agent", {}) or {}
    return {
        "id":        obj.get("id"),
        "timestamp": obj.get("timestamp"),
        "agent_ip":  agent.get("ip"),
        "src_ip":    (data.get("srcip") or data.get("source_ip")
                      or obj.get("srcip") or obj.get("source_ip")),
        "dst_ip":    (data.get("dstip") or data.get("destination_ip")
                      or obj.get("dstip") or obj.get("destination_ip")),
        "rule": {
            "id":          rule.get("id"),
            "level":       rule.get("level", 0),
            "description": rule.get("description", ""),
            "groups":      rule.get("groups", []),
        },
        "full_log":  obj.get("full_log", ""),
        "location":  obj.get("location", ""),
        "decoder":   (obj.get("decoder") or {}).get("name", ""),
        "data":      data,
    }


def is_attack(alert: dict, asset_role: str | None = None) -> bool:
    rule  = alert.get("rule", {})
    level = int(rule.get("level", 0))
    if level < 3:
        return False

    groups = [str(g).lower() for g in rule.get("groups", [])]
    text   = " ".join([
        str(rule.get("description", "")).lower(),
        " ".join(groups),
        str(alert.get("decoder", "")).lower(),
        str(alert.get("location", "")).lower(),
        str(alert.get("full_log", "")).lower(),
    ])

    if asset_role == "web_server":
        kw = _COMMON_KW | _WEB_KW
    elif asset_role == "db_server":
        kw = _COMMON_KW | _DB_KW
    else:
        kw = _COMMON_KW | _WEB_KW | _DB_KW

    allowed_groups = _ALLOWED_GROUPS.get(asset_role, _ALLOWED_GROUPS[None])
    return any(k in text for k in kw) or any(g in allowed_groups for g in groups)


def _save_alerts_snapshot(snapshot: list):
    """يحفظ snapshot من الـ buffer في الوقت الحالي بشكل آمن."""
    tmp = Path(WAZUH_FILE + ".tmp")
    tmp.write_text(json.dumps({"alerts": snapshot}, indent=2), encoding="utf-8")
    tmp.replace(Path(WAZUH_FILE))


def _run_defense_thread(agent_ip: str, snapshot: list):
    """
    يشغل morphynx_core.py في thread منفصل.
    يستخدم _defense_lock لمنع تشغيل نفس الدفاع مرتين.
    """
    with _defense_lock:
        if agent_ip in defense_running:
            print(f"[i] Defense already running for {agent_ip}. Skipping.", flush=True)
            return
        defense_running.add(agent_ip)

    try:
        _save_alerts_snapshot(snapshot)

        process = subprocess.Popen(
            ["python3", CORE_SCRIPT, "defense"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        for line in process.stdout:
            print(line, end="", flush=True)
        process.wait()

        if process.returncode != 0:
            print(f"[!] Core script exited with code {process.returncode}", flush=True)

    except Exception as e:
        print(f"[!] Defense thread error for {agent_ip}: {e}", flush=True)
    finally:
        with _defense_lock:
            defense_running.discard(agent_ip)


def process_line(line: str):
    global alerts_buffer

    line = line.strip()
    if not line:
        return

    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return

    alert    = normalize_alert(obj)
    agent_ip = alert.get("agent_ip")

    # أضف للـ buffer بشكل thread-safe
    with _buffer_lock:
        alerts_buffer.append(alert)
        if len(alerts_buffer) > BUFFER_MAX:
            alerts_buffer = alerts_buffer[-BUFFER_MAX:]

    if agent_ip not in TARGET_IPS:
        return

    role = IP_TO_ROLE.get(agent_ip)
    now  = datetime.utcnow().strftime("%H:%M:%S")
    desc = alert["rule"]["description"]
    lvl  = alert["rule"]["level"]

    if not is_attack(alert, role):
        print(f"  [{now}] INFO   {agent_ip} — L{lvl} — {desc}", flush=True)
        return

    with _counter_lock:
        attack_counters[agent_ip] = attack_counters.get(agent_ip, 0) + 1
        count = attack_counters[agent_ip]

    print(
        f"  [{now}] ATTACK [{count}/{ATTACK_THRESHOLD}] "
        f"{agent_ip} — L{lvl} — {desc}",
        flush=True,
    )

    if count >= ATTACK_THRESHOLD:
        print(f"\n[!!!] Threshold reached for {agent_ip} — launching defense thread...\n", flush=True)

        # snapshot من الـ buffer الحالي
        with _buffer_lock:
            snapshot = list(alerts_buffer)

        # reset العداد قبل ما تبدأ الـ thread عشان ما يتراكم
        with _counter_lock:
            attack_counters[agent_ip] = 0

        # شغّل الدفاع في thread منفصل — المونيتور يكمل يقرأ
        t = threading.Thread(
            target=_run_defense_thread,
            args=(agent_ip, snapshot),
            daemon=True,
            name=f"defense-{agent_ip}",
        )
        t.start()

        # مسح الـ buffer بعد ما بدأت الـ thread
        with _buffer_lock:
            alerts_buffer = []


def _reset_last_seen_ids():
    """يمسح last_seen_alert_ids من الـ state عند البدء."""
    p = Path(DEFENSE_STATE_FILE)
    if not p.exists():
        return
    try:
        state = json.loads(p.read_text(encoding="utf-8"))
        state["last_seen_alert_ids"] = {}
        p.write_text(json.dumps(state, indent=2), encoding="utf-8")
    except Exception as e:
        print(f"[!] Could not reset state file: {e}", flush=True)


def _connect_and_watch():
    """
    يفتح SSH ويقرأ الـ alerts. لو الاتصال انقطع يحاول يعيد.
    """
    ssh_cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ServerAliveInterval=10",
        "-o", "ServerAliveCountMax=3",
        "-o", "ConnectTimeout=5",
        f"{WAZUH_MANAGER_USER}@{WAZUH_MANAGER_HOST}",
        f"sudo tail -f -n 0 {REMOTE_ALERTS_FILE}",
    ]

    while True:
        print(f"[*] Connecting to {WAZUH_MANAGER_HOST}...", flush=True)
        try:
            proc = subprocess.Popen(
                ssh_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            print("[+] Connected — watching live alerts\n", flush=True)

            for line in proc.stdout:
                process_line(line)

            # لو وصلنا هنا يعني الـ SSH انتهى
            rc = proc.wait()
            print(f"[!] SSH connection closed (rc={rc}). Reconnecting in {SSH_RECONNECT_DELAY}s...", flush=True)

        except KeyboardInterrupt:
            print("\n[*] Monitor stopped by user.", flush=True)
            try:
                proc.terminate()
            except Exception:
                pass
            sys.exit(0)

        except Exception as e:
            print(f"[!] Connection error: {e}. Retrying in {SSH_RECONNECT_DELAY}s...", flush=True)

        time.sleep(SSH_RECONNECT_DELAY)


def main():
    load_assets()
    _reset_last_seen_ids()
    print_banner()
    _connect_and_watch()


if __name__ == "__main__":
    main()