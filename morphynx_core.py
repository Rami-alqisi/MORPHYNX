print("""
███╗   ███╗ ██████╗ ██████╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗██╗  ██╗
████╗ ████║██╔═══██╗██╔══██╗██╔══██╗██║  ██║╚██╗ ██╔╝████╗  ██║╚██╗██╔╝
██╔████╔██║██║   ██║██████╔╝██████╔╝███████║ ╚████╔╝ ██╔██╗ ██║ ╚███╔╝
██║╚██╔╝██║██║   ██║██╔══██╗██╔═══╝ ██╔══██║  ╚██╔╝  ██║╚██╗██║ ██╔██╗
██║ ╚═╝ ██║╚██████╔╝██║  ██║██║     ██║  ██╗   ██║   ██║ ╚████║██╔╝ ██╗
╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═══╝╚═╝  ╚═╝

Adaptive Moving Target Defense System
""")

import base64
import json
import random
import re
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from datetime import datetime

# ─────────────────────────────────────────────
# CONFIG PATHS
# ─────────────────────────────────────────────
ASSETS_FILE            = "assets_config.json"
NESSUS_FILE            = "nessus_report.json"
WAZUH_FILE             = "wazuh_alerts.json"
RAW_ALERTS_FILE        = "raw_alerts.json"
ACTIONS_LOG            = "actions_log.json"
STATE_FILE             = "defense_state.json"
BLOCKED_ATTACKERS_FILE = "blocked_attackers.json"
ALERT_COUNT_THRESHOLD  = 3

SSH_CONNECT_TIMEOUT = 3
SSH_COMMAND_TIMEOUT = 8

# ─────────────────────────────────────────────
# PFSENSE CONFIG
# ─────────────────────────────────────────────
PFSENSE_HOST        = "10.0.0.1"
PFSENSE_USER        = "admin"
PFSENSE_SSH_TIMEOUT = 10

ACTIVE_ALIAS_MAP = {
    "web_server": "ACTIVE_WEB",
    "db_server":  "ACTIVE_DB",
}
BLOCK_ALIAS_MAP = {
    "web_server": "morphynx_block_web",
    "db_server":  "morphynx_block_db",
}

# ─────────────────────────────────────────────
# LOCKS
# ─────────────────────────────────────────────
_state_lock   = threading.Lock()
_log_lock     = threading.Lock()
_blocked_lock = threading.Lock()

# ─────────────────────────────────────────────
# COMPILED REGEX
# ─────────────────────────────────────────────
_VALID_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

_IP_PATTERNS = [
    re.compile(r"from\s+(\d{1,3}(?:\.\d{1,3}){3})\s+port", re.I),
    re.compile(r"rhost=([\d.]+)",                            re.I),
    re.compile(r"src(?:ip|_ip|source)?[=:\s]+([\d.]+)",     re.I),
    re.compile(r"client[:\s]+([\d.]+)",                      re.I),
    re.compile(r"from\s+'([\d.]+)'",                         re.I),
    re.compile(r"^([\d.]+)\s+-\s+-\s+\[",                    re.M),
    re.compile(r"srcip=([\d.]+)",                            re.I),
    re.compile(r"source_ip=([\d.]+)",                        re.I),
]

# ─────────────────────────────────────────────
# KEYWORD SETS — O(1) lookup
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
    "user missed the password more than one time",
])
_ROLE_KW = {
    "web_server": _COMMON_KW | _WEB_KW,
    "db_server":  _COMMON_KW | _DB_KW,
    None:         _COMMON_KW | _WEB_KW | _DB_KW,
}
_ROLE_GROUPS = {
    "web_server": frozenset(["attack", "authentication_failed", "sshd", "web", "accesslog"]),
    "db_server":  frozenset(["attack", "authentication_failed", "sshd", "database", "mysql", "sql"]),
    None:         frozenset(["attack", "authentication_failed", "sshd",
                              "web", "accesslog", "database", "mysql", "sql"]),
}


# ═══════════════════════════════════════════════
# I/O HELPERS
# ═══════════════════════════════════════════════

def load_json(path):
    p = Path(path)
    if not p.exists():
        return None
    raw = p.read_text(encoding="utf-8", errors="ignore").strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        print(f"[!] Warning: {path} — invalid JSON. Attempting recovery...")
        try:
            last = raw.rfind("]")
            if last != -1:
                return json.loads(raw[:last + 1])
        except Exception:
            pass
        print(f"[!] Could not recover {path}.")
        return None


def save_json(path, data):
    """Atomic write via tmp file."""
    p   = Path(path)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(p)


def log_action(action_type, details):
    with _log_lock:
        log = load_json(ACTIONS_LOG)
        if not isinstance(log, list):
            log = []
        log.append({
            "time":    datetime.utcnow().isoformat() + "Z",
            "type":    action_type,
            "details": details,
        })
        save_json(ACTIONS_LOG, log)


# ═══════════════════════════════════════════════
# STATE — FIX: single read/write per operation, no nested locks
# ═══════════════════════════════════════════════

def _default_state():
    return {"shifted_assets": [], "last_seen_alert_ids": {}, "active_safe_ips": {}}


def _load_state_unlocked():
    """يقرأ الـ state بدون lock — للاستخدام داخل _state_lock فقط."""
    s = load_json(STATE_FILE)
    if not s or not isinstance(s, dict):
        return _default_state()
    s.setdefault("shifted_assets", [])
    s.setdefault("last_seen_alert_ids", {})
    s.setdefault("active_safe_ips", {})
    return s


def load_state():
    with _state_lock:
        return _load_state_unlocked()


def reset_state_file():
    with _state_lock:
        save_json(STATE_FILE, _default_state())


def is_asset_shifted(asset_ip):
    with _state_lock:
        return asset_ip in _load_state_unlocked().get("shifted_assets", [])


def mark_asset_shifted(asset_ip):
    with _state_lock:
        s = _load_state_unlocked()
        if asset_ip not in s["shifted_assets"]:
            s["shifted_assets"].append(asset_ip)
        save_json(STATE_FILE, s)


def unmark_asset_shifted(asset_ip):
    with _state_lock:
        s = _load_state_unlocked()
        s["shifted_assets"] = [ip for ip in s["shifted_assets"] if ip != asset_ip]
        save_json(STATE_FILE, s)


def get_last_seen_alert_id(asset_ip):
    with _state_lock:
        return _load_state_unlocked().get("last_seen_alert_ids", {}).get(asset_ip)


def set_last_seen_alert_id(asset_ip, alert_id):
    if not alert_id:
        return
    with _state_lock:
        s = _load_state_unlocked()
        s["last_seen_alert_ids"][asset_ip] = alert_id
        save_json(STATE_FILE, s)


def clear_last_seen_alert_id(asset_ip):
    with _state_lock:
        s = _load_state_unlocked()
        s["last_seen_alert_ids"].pop(asset_ip, None)
        save_json(STATE_FILE, s)


def get_active_safe_ip(asset_ip):
    with _state_lock:
        return _load_state_unlocked().get("active_safe_ips", {}).get(asset_ip)


def set_active_safe_ip(asset_ip, safe_ip):
    with _state_lock:
        s = _load_state_unlocked()
        s["active_safe_ips"][asset_ip] = safe_ip
        save_json(STATE_FILE, s)


def clear_active_safe_ip(asset_ip):
    with _state_lock:
        s = _load_state_unlocked()
        s["active_safe_ips"].pop(asset_ip, None)
        save_json(STATE_FILE, s)


def clear_local_alert_cache():
    save_json(WAZUH_FILE, {"alerts": []})
    Path(RAW_ALERTS_FILE).write_text("", encoding="utf-8")


def maybe_reset_empty_state_file():
    with _state_lock:
        s = _load_state_unlocked()
        if not s["shifted_assets"] and not s["last_seen_alert_ids"] and not s["active_safe_ips"]:
            save_json(STATE_FILE, _default_state())


# ═══════════════════════════════════════════════
# SSH EXECUTION
# ═══════════════════════════════════════════════

def _build_ssh_cmd(user, host, command):
    return [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-o", "PasswordAuthentication=no",
        "-o", f"ConnectTimeout={SSH_CONNECT_TIMEOUT}",
        f"{user}@{host}",
        command,
    ]


def run_remote_command(user, host, command, timeout=SSH_COMMAND_TIMEOUT, quiet=False):
    try:
        r = subprocess.run(
            _build_ssh_cmd(user, host, command),
            check=True, capture_output=True, text=True, timeout=timeout,
        )
        if not quiet:
            if r.stdout.strip(): print(r.stdout.strip())
            if r.stderr.strip(): print(r.stderr.strip())
        return True, r.stdout.strip()
    except subprocess.TimeoutExpired:
        if not quiet: print(f"[!] SSH timeout on {host}.")
        return False, ""
    except subprocess.CalledProcessError:
        if not quiet: print(f"[!] SSH command failed on {host}.")
        return False, ""


def run_pfsense_command(command, timeout=PFSENSE_SSH_TIMEOUT, quiet=True):
    ssh_cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-o", "PasswordAuthentication=no",
        "-o", f"ConnectTimeout={SSH_CONNECT_TIMEOUT}",
        f"{PFSENSE_USER}@{PFSENSE_HOST}",
        command,
    ]
    try:
        r = subprocess.run(ssh_cmd, check=False, capture_output=True, text=True, timeout=timeout)
        out, err = r.stdout.strip(), r.stderr.strip()
        if r.returncode != 0:
            if not quiet:
                print(f"[!] pfSense failed (rc={r.returncode})")
                if err: print(f"    stderr: {err}")
            return False, err or out
        if not quiet and out:
            print(out)
        return True, out
    except subprocess.TimeoutExpired:
        if not quiet: print("[!] pfSense SSH timed out.")
        return False, "timeout"
    except Exception as e:
        if not quiet: print(f"[!] pfSense SSH error: {e}")
        return False, str(e)


# ═══════════════════════════════════════════════
# PFSENSE ALIAS MANAGEMENT
# FIX: use base64 to transfer PHP — avoids ALL shell escaping issues
# ═══════════════════════════════════════════════

_PHP_UPDATE_ACTIVE = r"""<?php
require_once("/etc/inc/config.inc");
require_once("/etc/inc/filter.inc");
$alias_name = $argv[1]; $new_ip = $argv[2]; $updated = false;
if (!isset($config['aliases']['alias']) || !is_array($config['aliases']['alias'])) { exit(2); }
foreach ($config['aliases']['alias'] as &$alias) {
    if (isset($alias['name']) && $alias['name'] === $alias_name) {
        $alias['address'] = $new_ip; $updated = true; break;
    }
}
if (!$updated) { exit(3); }
write_config("MORPHYNX updated alias " . $alias_name . " -> " . $new_ip);
filter_configure();
exec("pfctl -t " . escapeshellarg($alias_name) . " -T replace " . escapeshellarg($new_ip) . " 2>/dev/null");
echo "updated";
"""

_PHP_ALIAS_ADD = r"""<?php
require_once("/etc/inc/config.inc");
require_once("/etc/inc/filter.inc");
require_once("/etc/inc/util.inc");
$alias_name = $argv[1]; $new_ip = $argv[2];
if (!isset($config['aliases']['alias']) || !is_array($config['aliases']['alias'])) { echo "ERROR: no aliases"; exit(1); }
$found = false;
foreach ($config['aliases']['alias'] as &$alias) {
    if ($alias['name'] !== $alias_name) continue;
    $found = true;
    $existing = array_values(array_filter(array_map('trim', explode(" ", $alias['address'] ?? ""))));
    if (in_array($new_ip, $existing)) { echo "EXISTS"; exit(0); }
    $existing[] = $new_ip;
    $alias['address'] = implode(" ", $existing);
    $details = array_values(array_filter(array_map('trim', explode("||", $alias['detail'] ?? ""))));
    $details[] = "MORPHYNX blocked";
    $alias['detail'] = implode("||", $details);
    break;
}
if (!$found) { echo "ERROR: alias not found: " . $alias_name; exit(2); }
write_config("MORPHYNX added " . $new_ip . " to " . $alias_name);
filter_configure();
exec("pfctl -t " . escapeshellarg($alias_name) . " -T add " . escapeshellarg($new_ip) . " 2>/dev/null");
echo "ADDED";
"""

_PHP_ALIAS_REMOVE = r"""<?php
require_once("/etc/inc/config.inc");
require_once("/etc/inc/filter.inc");
$alias_name = $argv[1]; $del_ip = $argv[2];
if (!isset($config['aliases']['alias']) || !is_array($config['aliases']['alias'])) { echo "ERROR: no aliases"; exit(1); }
$found = false;
foreach ($config['aliases']['alias'] as &$alias) {
    if ($alias['name'] !== $alias_name) continue;
    $found = true;
    $existing = array_values(array_filter(
        array_map('trim', explode(" ", $alias['address'] ?? "")),
        function($ip) use ($del_ip) { return $ip !== "" && $ip !== $del_ip; }
    ));
    $alias['address'] = implode(" ", $existing);
    $alias['detail']  = "";
    break;
}
if (!$found) { echo "ERROR: alias not found"; exit(2); }
write_config("MORPHYNX removed " . $del_ip . " from " . $alias_name);
filter_configure();
exec("pfctl -t " . escapeshellarg($alias_name) . " -T delete " . escapeshellarg($del_ip) . " 2>/dev/null");
echo "REMOVED";
"""


def _pfsense_php(php_code, *args):
    """
    FIX: transfers PHP via base64 — no shell escaping issues whatsoever.
    Decodes on pfSense, writes to tmpfile, runs, cleans up.
    """
    b64 = base64.b64encode(php_code.encode()).decode()
    args_q = " ".join(f"'{a}'" for a in args)
    cmd = (
        f"TMPF=$(mktemp /tmp/morphynx_XXXXXX.php) && "
        f"echo '{b64}' | base64 -d > \"$TMPF\" && "
        f"php \"$TMPF\" {args_q}; "
        f"RC=$?; rm -f \"$TMPF\"; exit $RC"
    )
    return run_pfsense_command(cmd, quiet=True)


def update_pfsense_active_alias(alias_name, ip_value):
    ok, _ = _pfsense_php(_PHP_UPDATE_ACTIVE, alias_name, ip_value)
    return ok


def sync_active_alias_for_asset(asset, active_ip):
    alias_name = ACTIVE_ALIAS_MAP.get(asset.get("role"))
    if not alias_name or not active_ip:
        return True
    ok = update_pfsense_active_alias(alias_name, active_ip)
    print(f"[{'i' if ok else '!'}] pfSense alias {alias_name} -> {active_ip} {'✓' if ok else '✗'}")
    return ok


def _pfsense_alias_add_ip(alias_name, attacker_ip):
    ok, out = _pfsense_php(_PHP_ALIAS_ADD, alias_name, attacker_ip)
    if "ADDED" in out:
        print(f"[+] pfSense: {attacker_ip} → '{alias_name}' ✓")
        return True
    if "EXISTS" in out:
        print(f"[i] pfSense: {attacker_ip} already in '{alias_name}'")
        return True
    print(f"[!] pfSense alias_add failed: {out!r}")
    return False


def _pfsense_alias_remove_ip(alias_name, attacker_ip):
    ok, out = _pfsense_php(_PHP_ALIAS_REMOVE, alias_name, attacker_ip)
    if "REMOVED" in out:
        print(f"[+] pfSense: {attacker_ip} removed from '{alias_name}' ✓")
        return True
    print(f"[!] pfSense alias_remove failed: {out!r}")
    return False


# ═══════════════════════════════════════════════
# NETWORK STATE DETECTION
# ═══════════════════════════════════════════════

def detect_active_safe_ip(asset):
    user, iface = asset["ssh_user"], asset["iface"]
    safe_ips    = asset.get("safe_ips", [])

    def _check(host):
        ok, output = run_remote_command(user, host, f"ip -4 addr show dev {iface}", timeout=6, quiet=True)
        if not ok:
            return None
        for sip in safe_ips:
            if f"{sip}/" in output or f"inet {sip} " in output:
                return sip
        return None

    hosts = [asset["ip"]] + safe_ips
    with ThreadPoolExecutor(max_workers=min(len(hosts), 8)) as ex:
        futures = {ex.submit(_check, h): h for h in hosts}
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                return result
    return None


def detect_original_ip_active(asset):
    user, iface = asset["ssh_user"], asset["iface"]
    original_ip = asset["ip"]
    hosts       = [original_ip] + asset.get("safe_ips", [])

    def _check(host):
        ok, output = run_remote_command(user, host, f"ip -4 addr show dev {iface}", timeout=6, quiet=True)
        return ok and (f"{original_ip}/" in output or f"inet {original_ip} " in output)

    with ThreadPoolExecutor(max_workers=min(len(hosts), 8)) as ex:
        return any(ex.map(_check, hosts))


# ═══════════════════════════════════════════════
# SAFE IP SELECTION
# ═══════════════════════════════════════════════

def choose_random_safe_ip(asset):
    safe_ips = asset.get("safe_ips", [])
    if not safe_ips:
        return None
    current    = get_active_safe_ip(asset["ip"])
    candidates = [ip for ip in safe_ips if ip != current] or safe_ips[:]
    return random.choice(candidates)


# ═══════════════════════════════════════════════
# RISK SCORING — CBRS
# ═══════════════════════════════════════════════

def compute_cbrs(cvss, criticality, exposure, exploit, lateral, mac_privilege):
    return round((
        (cvss / 10.0)           * 0.20 +
        (criticality / 5.0)     * 0.25 +
        (exposure / 5.0)        * 0.20 +
        (1.0 if exploit else 0) * 0.15 +
        (lateral / 5.0)         * 0.10 +
        (mac_privilege / 5.0)   * 0.10
    ) * 10.0, 2)


# ═══════════════════════════════════════════════
# NESSUS PARSING
# ═══════════════════════════════════════════════

def aggregate_nessus_by_host(nessus_data):
    by_host = {}
    for item in nessus_data.get("vulnerabilities", []):
        host = item.get("host")
        if not host:
            continue
        rec = by_host.setdefault(host, {"max_cvss": 0.0, "exploit_available": False})
        cvss = item.get("cvss_base_score", 0.0)
        if cvss > rec["max_cvss"]:
            rec["max_cvss"] = cvss
        if item.get("exploit_available"):
            rec["exploit_available"] = True
    return by_host


# ═══════════════════════════════════════════════
# ATTACK CLASSIFICATION
# FIX: build text once, reuse — no double work
# ═══════════════════════════════════════════════

def _build_alert_text(alert):
    """يبني نص الـ alert مرة وحدة للبحث فيه."""
    rule   = alert.get("rule", {})
    groups = [str(g).lower() for g in rule.get("groups", [])]
    return " ".join([
        str(rule.get("description", "")).lower(),
        " ".join(groups),
        str(alert.get("decoder", "")).lower(),
        str(alert.get("location", "")).lower(),
        str(alert.get("full_log", "")).lower(),
    ]), groups


def is_attack_alert(alert, asset_role=None):
    rule = alert.get("rule", {})
    if int(rule.get("level", 0)) < 3:
        return False
    text, groups = _build_alert_text(alert)
    kw_set = _ROLE_KW.get(asset_role, _ROLE_KW[None])
    gr_set = _ROLE_GROUPS.get(asset_role, _ROLE_GROUPS[None])
    return any(k in text for k in kw_set) or any(g in gr_set for g in groups)


# ═══════════════════════════════════════════════
# WAZUH ALERT PARSING
# ═══════════════════════════════════════════════

def get_new_attack_alerts_for_host(wazuh_data, target_ip, asset_role=None):
    """
    يرجع (attack_alerts, latest_id).
    - أول استدعاء (last_seen_id=None): يعالج كل الـ alerts الحالية مباشرة.
    - استدعاءات لاحقة: يرجع فقط alerts بعد آخر ID محفوظ.
    FIX: builds alert text once per alert, not twice.
    """
    kw = _ROLE_KW.get(asset_role, _ROLE_KW[None])

    host_alerts = []
    for a in wazuh_data.get("alerts", []):
        agent_ip = a.get("agent_ip")
        dst_ip   = a.get("dst_ip")
        full_log = str(a.get("full_log", "")).lower()

        if not (
            agent_ip == target_ip or dst_ip == target_ip
            or f"dstip={target_ip}" in full_log
            or f"destination ip: {target_ip}" in full_log
            or f"dst_ip={target_ip}" in full_log
        ):
            continue

        # FIX: build text once and reuse for both filtering passes
        text, groups = _build_alert_text(a)
        if any(k in text for k in kw):
            host_alerts.append((a, text, groups))

    if not host_alerts:
        return [], None

    last_seen_id = get_last_seen_alert_id(target_ip)
    latest_id    = host_alerts[-1][0].get("id")

    gr_set = _ROLE_GROUPS.get(asset_role, _ROLE_GROUPS[None])

    def _is_attack(a, text, groups):
        if int(a.get("rule", {}).get("level", 0)) < 3:
            return False
        return any(k in text for k in kw) or any(g in gr_set for g in groups)

    # أول استدعاء — عالج كل الـ alerts مباشرة
    if last_seen_id is None:
        return [a for a, t, g in host_alerts if _is_attack(a, t, g)], latest_id

    # استدعاءات لاحقة — فقط alerts بعد آخر ID
    new_items  = []
    seen_old   = False
    for item in host_alerts:
        if item[0].get("id") == last_seen_id:
            seen_old  = True
            new_items = []
            continue
        if seen_old:
            new_items.append(item)

    if not seen_old:
        new_items = host_alerts

    return [a for a, t, g in new_items if _is_attack(a, t, g)], latest_id


# ═══════════════════════════════════════════════
# IP SHIFTING
# ═══════════════════════════════════════════════

def shift_real_server_ip(asset, new_ip):
    user  = asset["ssh_user"]
    host  = asset["ssh_host"]
    iface = asset["iface"]
    old   = asset["ip"]
    safe  = asset.get("safe_ips", [])

    parts  = [f"sudo ip addr del {old}/24 dev {iface} 2>/dev/null || true"]
    parts += [f"sudo ip addr del {s}/24 dev {iface} 2>/dev/null || true" for s in safe]
    parts += [f"sudo ip addr add {new_ip}/24 dev {iface}"]
    ok, _ = run_remote_command(user, host, "; ".join(parts), quiet=True)
    return ok


def rollback_real_server_ip(asset):
    user        = asset["ssh_user"]
    iface       = asset["iface"]
    original_ip = asset["ip"]
    safe        = asset.get("safe_ips", [])

    active_safe = get_active_safe_ip(original_ip) or detect_active_safe_ip(asset)
    if not active_safe:
        return False

    parts  = [f"sudo ip addr del {s}/24 dev {iface} 2>/dev/null || true" for s in safe]
    parts += [f"sudo ip addr del {original_ip}/24 dev {iface} 2>/dev/null || true",
              f"sudo ip addr add {original_ip}/24 dev {iface}"]
    ok, _ = run_remote_command(user, active_safe, "; ".join(parts), quiet=True)
    return ok


def enable_honeypot_old_ip(honeypot_conf, old_ip, safe_ips=None):
    user, host, iface = honeypot_conf["ssh_user"], honeypot_conf["ssh_host"], honeypot_conf["iface"]
    parts  = [f"sudo ip addr del {s}/24 dev {iface} 2>/dev/null || true" for s in (safe_ips or [])]
    parts += [f"sudo ip addr del {old_ip}/24 dev {iface} 2>/dev/null || true",
              f"sudo ip addr add {old_ip}/24 dev {iface}"]
    ok, _ = run_remote_command(user, host, "; ".join(parts), quiet=True)
    return ok


def disable_honeypot_old_ip(honeypot_conf, old_ip, safe_ips=None):
    user, host, iface = honeypot_conf["ssh_user"], honeypot_conf["ssh_host"], honeypot_conf["iface"]
    parts  = [f"sudo ip addr del {old_ip}/24 dev {iface} 2>/dev/null || true"]
    parts += [f"sudo ip addr del {s}/24 dev {iface} 2>/dev/null || true" for s in (safe_ips or [])]
    ok, _ = run_remote_command(user, host, "; ".join(parts), quiet=True)
    return ok


# ═══════════════════════════════════════════════
# ATTACKER BLOCKING
# ═══════════════════════════════════════════════

def load_blocked_attackers():
    with _blocked_lock:
        data = load_json(BLOCKED_ATTACKERS_FILE)
        return data if isinstance(data, list) else []


def save_blocked_attackers(blocked):
    with _blocked_lock:
        save_json(BLOCKED_ATTACKERS_FILE, blocked)


def _is_valid_ip(ip):
    ip = str(ip).strip(",'\"[] \t")
    if not _VALID_IP_RE.match(ip):
        return False
    parts = ip.split(".")
    if any(int(p) > 255 for p in parts):
        return False
    return not (ip.startswith("127.") or ip.startswith("0.") or ip == "255.255.255.255")


def _iptables_block_on_host(ssh_user, safe_ip, attacker_ip):
    """FIX: single SSH call — check + add in one command."""
    cmd = (
        f"sudo iptables -C INPUT -s {attacker_ip} -j DROP 2>/dev/null "
        f"|| sudo iptables -I INPUT -s {attacker_ip} -j DROP && echo DONE"
    )
    ok, out = run_remote_command(ssh_user, safe_ip, cmd, quiet=True)
    return ok


def _iptables_unblock_on_host(ssh_user, safe_ip, attacker_ip):
    ok, _ = run_remote_command(
        ssh_user, safe_ip,
        f"sudo iptables -D INPUT -s {attacker_ip} -j DROP 2>/dev/null; echo done",
        quiet=True,
    )
    return ok


def _extract_attacker_ips(alerts):
    src_ips = set()
    for alert in alerts:
        for field in ("src_ip", "srcip", "source_ip", "attacker_ip"):
            val = str(alert.get(field) or "").strip()
            if val and _is_valid_ip(val):
                src_ips.add(val)
        data = alert.get("data") or {}
        if isinstance(data, dict):
            for field in ("srcip", "src_ip", "source_ip", "rhost"):
                val = str(data.get(field) or "").strip()
                if val and _is_valid_ip(val):
                    src_ips.add(val)
        full_log = str(alert.get("full_log", ""))
        for pat in _IP_PATTERNS:
            m = pat.search(full_log)
            if m and _is_valid_ip(m.group(1)):
                src_ips.add(m.group(1))
    return list(src_ips)


def block_attackers_from_alerts(attack_alerts, asset):
    """
    يبلوك الأتاكرين بطريقتين بالتوازي:
    1) iptables على كل safe IP  (ThreadPoolExecutor)
    2) pfSense alias
    الهوني بوت يضل مفتوح ✓
    """
    if not isinstance(asset, dict):
        asset = {"ip": asset, "role": "unknown", "safe_ips": [], "ssh_user": "kali"}

    asset_ip   = asset.get("ip")
    ssh_user   = asset.get("ssh_user", "kali")
    safe_ips   = asset.get("safe_ips", [])
    role       = asset.get("role", "unknown")
    alias_name = BLOCK_ALIAS_MAP.get(role, "morphynx_block_web")

    attacker_ips = _extract_attacker_ips(attack_alerts)
    if not attacker_ips:
        print("[i] No attacker IPs found in alerts.")
        print("[i] Tip: Check full_log — sshd/PAM must log the source IP.")
        return []

    print(f"[i] Identified attacker IPs: {', '.join(attacker_ips)}")

    blocked = load_blocked_attackers()
    already = {e["ip"] for e in blocked
               if e.get("status") == "blocked" and e.get("target_asset") == asset_ip}
    newly_blocked = []

    for attacker_ip in attacker_ips:
        if attacker_ip in already:
            print(f"[i] {attacker_ip} already blocked for {asset_ip}. Skipping.")
            continue

        print(f"[i] Blocking {attacker_ip} — dual (iptables + pfSense) ...")
        print(f"[i] Honeypot ({asset_ip}) stays OPEN ✓")

        # iptables + pfSense بالتوازي الكامل
        ipt_results = []
        pf_future   = None

        with ThreadPoolExecutor(max_workers=min(len(safe_ips) + 1, 16)) as ex:
            futures = {ex.submit(_iptables_block_on_host, ssh_user, sip, attacker_ip): sip
                       for sip in safe_ips}
            pf_future = ex.submit(_pfsense_alias_add_ip, alias_name, attacker_ip)

            for fut in as_completed(futures):
                sip = futures[fut]
                ok  = fut.result()
                ipt_results.append({"host": sip, "ok": ok})
                print(f"    iptables {sip}: {'✓' if ok else '✗'}")

            pf_ok = pf_future.result()
            print(f"    pfSense {alias_name}: {'✓' if pf_ok else '✗'}")

        overall_ok = any(r["ok"] for r in ipt_results) or pf_ok

        blocked.append({
            "ip":               attacker_ip,
            "blocked_at":       datetime.utcnow().isoformat() + "Z",
            "target_asset":     asset_ip,
            "asset_role":       role,
            "method":           "iptables+pfsense",
            "alias":            alias_name,
            "safe_ips":         safe_ips,
            "honeypot_open":    asset_ip,
            "status":           "blocked" if overall_ok else "failed",
            "iptables_results": ipt_results,
            "pfsense_ok":       pf_ok,
        })

        if overall_ok:
            newly_blocked.append(attacker_ip)
            log_action("ATTACKER_BLOCKED", {
                "attacker_ip":   attacker_ip,
                "target_asset":  asset_ip,
                "asset_role":    role,
                "method":        "iptables+pfsense",
                "alias":         alias_name,
                "safe_ips":      safe_ips,
                "honeypot_open": asset_ip,
                "iptables":      ipt_results,
                "pfsense":       pf_ok,
            })

    save_blocked_attackers(blocked)
    return newly_blocked


def unblock_attacker(attacker_ip, role=None):
    blocked = load_blocked_attackers()
    entry_found = next(
        (e for e in reversed(blocked)
         if e.get("ip") == attacker_ip and e.get("status") == "blocked"),
        None,
    )
    if not entry_found:
        print(f"[!] {attacker_ip} not found in blocked list.")
        return False

    assets_conf = load_json(ASSETS_FILE) or {"assets": []}
    ssh_user    = "kali"
    safe_ips    = entry_found.get("safe_ips", [])
    asset_role  = entry_found.get("asset_role") or role
    alias_name  = entry_found.get("alias") or BLOCK_ALIAS_MAP.get(asset_role, "morphynx_block_web")

    for a in assets_conf.get("assets", []):
        if a.get("role") == asset_role:
            ssh_user = a.get("ssh_user", "kali")
            if not safe_ips:
                safe_ips = a.get("safe_ips", [])
            break

    print(f"[i] Unblocking {attacker_ip} — dual (iptables + pfSense) ...")

    ipt_results = []
    with ThreadPoolExecutor(max_workers=min(len(safe_ips) + 1, 16)) as ex:
        futures   = {ex.submit(_iptables_unblock_on_host, ssh_user, sip, attacker_ip): sip
                     for sip in safe_ips}
        pf_future = ex.submit(_pfsense_alias_remove_ip, alias_name, attacker_ip)

        for fut in as_completed(futures):
            sip = futures[fut]
            ok  = fut.result()
            ipt_results.append({"host": sip, "ok": ok})
            print(f"    iptables {sip}: {'✓' if ok else '✗'}")

        pf_ok = pf_future.result()
        print(f"    pfSense {alias_name}: {'✓' if pf_ok else '✗'}")

    overall_ok = any(r["ok"] for r in ipt_results) or pf_ok

    for e in blocked:
        if e.get("ip") == attacker_ip and e.get("status") == "blocked":
            e["status"]           = "unblocked" if overall_ok else e["status"]
            e["unblocked_at"]     = datetime.utcnow().isoformat() + "Z"
            e["unblock_iptables"] = ipt_results
            e["unblock_pfsense"]  = pf_ok
            break

    save_blocked_attackers(blocked)

    if overall_ok:
        log_action("ATTACKER_UNBLOCKED", {
            "attacker_ip": attacker_ip,
            "role":        asset_role,
            "iptables":    ipt_results,
            "pfsense":     pf_ok,
        })
        print(f"[+] {attacker_ip} unblocked successfully.")
    else:
        print(f"[!] Failed to unblock {attacker_ip}.")

    return overall_ok


# ═══════════════════════════════════════════════
# DEFENSE LOGIC
# ═══════════════════════════════════════════════

def trigger_adaptive_defense(asset, honeypot_conf, nessus_info, wazuh_data):
    ip          = asset["ip"]
    safe_ips    = asset.get("safe_ips", [])
    honeypot_ip = asset.get("honeypot_ip")
    role        = asset.get("role")

    if not safe_ips or not honeypot_ip:
        print(f"[i] Asset {ip} has no shifting config. Skipping.")
        return

    if is_asset_shifted(ip):
        return

    host_vuln = nessus_info.get(ip, {"max_cvss": 0.0, "exploit_available": False})
    cbrs = compute_cbrs(
        host_vuln["max_cvss"],
        asset["criticality"], asset["exposure"],
        host_vuln["exploit_available"],
        asset["lateral_movement"], asset["mac_privilege"],
    )
    attack_alerts, latest_alert_id = get_new_attack_alerts_for_host(wazuh_data, ip, role)
    alert_count = len(attack_alerts)

    print(f"[+] Host {ip} CBRS = {cbrs}")
    print(f"[+] Host {ip} new attack alert count = {alert_count}")

    log_action("RISK_ANALYSIS", {"asset_ip": ip, "role": role, "cbrs": cbrs, "alert_count": alert_count})

    if alert_count < ALERT_COUNT_THRESHOLD:
        if latest_alert_id:
            set_last_seen_alert_id(ip, latest_alert_id)
        print(f"[i] Alert count below threshold ({ALERT_COUNT_THRESHOLD}). No adaptive defense.")
        return

    chosen_safe_ip = choose_random_safe_ip(asset)
    if not chosen_safe_ip:
        print(f"[!] No safe IP available for {ip}.")
        return

    print(f"[!] Alert threshold reached on {ip}. Triggering MORPHYNX defense...")

    with ThreadPoolExecutor(max_workers=2) as ex:
        fut_shift = ex.submit(shift_real_server_ip, asset, chosen_safe_ip)
        fut_honey = ex.submit(enable_honeypot_old_ip, honeypot_conf, ip, safe_ips)
        fut_shift.result()
        fut_honey.result()

    detected_safe_ip = detect_active_safe_ip(asset)

    if detected_safe_ip == chosen_safe_ip:
        mark_asset_shifted(ip)
        set_active_safe_ip(ip, detected_safe_ip)
        sync_active_alias_for_asset(asset, detected_safe_ip)
        if latest_alert_id:
            set_last_seen_alert_id(ip, latest_alert_id)
        log_action("DEFENSE_TRIGGERED", {
            "asset_ip":    ip, "role": role,
            "safe_ip":     detected_safe_ip, "honeypot_ip": honeypot_ip,
            "cbrs":        cbrs, "alert_count": alert_count,
        })
        print(f"[+] Adaptive defense applied successfully on {ip}.")

        newly_blocked = block_attackers_from_alerts(attack_alerts, asset)
        if newly_blocked:
            print(f"[+] Blocked {len(newly_blocked)} attacker(s): {', '.join(newly_blocked)}")
        else:
            print("[i] No external attacker IPs identified for blocking.")
    else:
        print(f"[!] Defense finished, but {ip} not verified on {chosen_safe_ip}.")
        print("[!] Check SSH access, sudoers, and interface settings.")


def perform_rollback(asset, honeypot_conf):
    ip          = asset["ip"]
    safe_ips    = asset.get("safe_ips", [])
    honeypot_ip = asset.get("honeypot_ip")

    if not safe_ips or not honeypot_ip:
        return

    active_safe_ip = get_active_safe_ip(ip) or detect_active_safe_ip(asset)
    if active_safe_ip:
        set_active_safe_ip(ip, active_safe_ip)
        mark_asset_shifted(ip)
    else:
        clear_last_seen_alert_id(ip)
        clear_active_safe_ip(ip)
        unmark_asset_shifted(ip)
        clear_local_alert_cache()
        maybe_reset_empty_state_file()
        print(f"[i] No active safe IP found for {ip}. State cleaned.")
        return

    print(f"[i] Performing rollback for {ip}...")

    with ThreadPoolExecutor(max_workers=2) as ex:
        fut_hp = ex.submit(disable_honeypot_old_ip, honeypot_conf, ip, safe_ips)
        fut_rb = ex.submit(rollback_real_server_ip, asset)
        fut_hp.result()
        fut_rb.result()

    original_restored = detect_original_ip_active(asset)

    clear_last_seen_alert_id(ip)
    clear_active_safe_ip(ip)
    unmark_asset_shifted(ip)
    clear_local_alert_cache()
    maybe_reset_empty_state_file()
    sync_active_alias_for_asset(asset, ip)
    log_action("ROLLBACK", {"asset_ip": ip, "safe_ip": active_safe_ip, "honeypot_ip": honeypot_ip})

    if original_restored:
        print(f"[+] Rollback completed successfully for {ip}.")
    else:
        print(f"[!] Rollback commands finished but {ip} not verified on interface.")
        print(f"[!] pfSense alias was still updated to {ip}. Check SSH/sudoers.")


# ═══════════════════════════════════════════════
# MAIN — parallel asset processing (scales to 100+)
# ═══════════════════════════════════════════════

def main(mode="defense"):
    assets_conf = load_json(ASSETS_FILE)
    if not assets_conf:
        print("[!] assets_config.json not found.")
        return

    nessus_data    = load_json(NESSUS_FILE) or {"vulnerabilities": []}
    wazuh_data     = load_json(WAZUH_FILE)  or {"alerts": []}
    nessus_by_host = aggregate_nessus_by_host(nessus_data)
    honeypot_conf  = assets_conf.get("honeypot", {})
    assets         = assets_conf.get("assets", [])

    if not assets:
        print("[!] No assets defined in assets_config.json.")
        return

    max_workers = min(len(assets), 20)

    def _process(asset):
        try:
            if mode == "defense":
                trigger_adaptive_defense(asset, honeypot_conf, nessus_by_host, wazuh_data)
            elif mode == "rollback":
                perform_rollback(asset, honeypot_conf)
        except Exception as e:
            print(f"[!] Error processing {asset.get('ip', '?')}: {e}")

    if len(assets) == 1:
        _process(assets[0])
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            list(ex.map(_process, assets))


if __name__ == "__main__":
    import sys
    mode = sys.argv[1] if len(sys.argv) > 1 else "defense"
    main(mode)