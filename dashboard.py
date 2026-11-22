from __future__ import annotations

import json
import os
import re
import signal
import subprocess
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, Response, request

app = Flask(__name__)

# ============================================================
# CONFIG
# ============================================================
BASE_DIR = Path(__file__).resolve().parent

ASSETS_FILE            = BASE_DIR / "assets_config.json"
NESSUS_FILE            = BASE_DIR / "nessus_report.json"
WAZUH_FILE             = BASE_DIR / "wazuh_alerts.json"
ACTIONS_LOG            = BASE_DIR / "actions_log.json"
STATE_FILE             = BASE_DIR / "defense_state.json"
MONITOR_SCRIPT         = BASE_DIR / "morphynx_monitor.py"
CORE_SCRIPT            = BASE_DIR / "morphynx_core.py"
MONITOR_LOG            = BASE_DIR / "monitor_runtime.log"
MONITOR_PID            = BASE_DIR / ".monitor.pid"
CBRS_HISTORY_FILE      = BASE_DIR / "cbrs_history.json"
BLOCKED_ATTACKERS_FILE = BASE_DIR / "blocked_attackers.json"

MONITOR_CMD  = ["python3", "-u", str(MONITOR_SCRIPT)]
ROLLBACK_CMD = ["python3", str(CORE_SCRIPT), "rollback"]

# ============================================================
# HELPERS
# ============================================================
def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def save_json(path: Path, data: Any) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def append_action(action_type: str, details: dict) -> None:
    actions = load_json(ACTIONS_LOG, [])
    if not isinstance(actions, list):
        actions = []
    actions.append({"time": datetime.utcnow().isoformat() + "Z", "type": action_type, "details": details})
    save_json(ACTIONS_LOG, actions)

def read_last_lines(path: Path, limit: int = 120) -> list:
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        cleaned = [l.rstrip() for l in lines if l.strip() and not l.startswith("=") and "Adaptive Moving Target" not in l]
        return cleaned[-limit:]
    except Exception:
        return []

def compute_cbrs(cvss, criticality, exposure, exploit, lateral, mac_privilege):
    return round(((cvss/10)*0.20 + (criticality/5)*0.25 + (exposure/5)*0.20 +
                  (1.0 if exploit else 0.0)*0.15 + (lateral/5)*0.10 + (mac_privilege/5)*0.10) * 10.0, 2)

def aggregate_nessus_by_host(nessus_data):
    by_host = {}
    for item in nessus_data.get("vulnerabilities", []):
        host = item.get("host")
        if not host:
            continue
        cvss    = float(item.get("cvss_base_score", 0.0) or 0.0)
        exploit = bool(item.get("exploit_available", False))
        cve     = item.get("cve", [])
        if isinstance(cve, str):
            cve = [cve]
        if host not in by_host:
            by_host[host] = {"max_cvss": 0.0, "exploit_available": False, "items": []}
        by_host[host]["items"].append({"plugin_name": str(item.get("plugin_name","Unknown")),
                                       "cvss_base_score": cvss, "exploit_available": exploit, "cve": cve})
        if cvss > by_host[host]["max_cvss"]:
            by_host[host]["max_cvss"] = cvss
        if exploit:
            by_host[host]["exploit_available"] = True
    return by_host

def get_default_state():
    return {"shifted_assets": [], "last_seen_alert_ids": {}, "active_safe_ips": {}}

def get_state():
    state = load_json(STATE_FILE, get_default_state())
    if not isinstance(state, dict):
        return get_default_state()
    state.setdefault("shifted_assets", [])
    state.setdefault("last_seen_alert_ids", {})
    state.setdefault("active_safe_ips", {})
    return state

def get_asset_rows():
    assets_conf    = load_json(ASSETS_FILE, {"assets": []})
    nessus_data    = load_json(NESSUS_FILE, {"vulnerabilities": []})
    nessus_by_host = aggregate_nessus_by_host(nessus_data)
    state          = get_state()
    active_safe    = state.get("active_safe_ips", {})
    shifted        = state.get("shifted_assets", [])
    rows = []
    for asset in assets_conf.get("assets", []):
        ip   = asset.get("ip", "-")
        role = asset.get("role", "unknown")
        vuln = nessus_by_host.get(ip, {"max_cvss": 0.0, "exploit_available": False, "items": []})
        old  = float(vuln.get("max_cvss", 0.0) or 0.0)
        new  = compute_cbrs(old, int(asset.get("criticality",1) or 1), int(asset.get("exposure",1) or 1),
                            bool(vuln.get("exploit_available",False)),
                            int(asset.get("lateral_movement",1) or 1), int(asset.get("mac_privilege",1) or 1))
        is_shifted = ip in shifted
        severity   = "CRITICAL" if new >= 8 else "HIGH" if new >= 6 else "MEDIUM" if new >= 4 else "LOW"
        rows.append({"ip": ip, "role": role, "safe_ips": asset.get("safe_ips",[]),
                     "active_safe_ip": active_safe.get(ip,"-"), "honeypot_ip": asset.get("honeypot_ip","-"),
                     "criticality": asset.get("criticality","-"), "old_score": old, "new_score": new,
                     "exploit_available": bool(vuln.get("exploit_available",False)),
                     "vulnerabilities": vuln.get("items",[]), "is_shifted": is_shifted,
                     "severity": severity, "status": "AT-RISK" if is_shifted or new >= 6 else "HEALTHY"})
    return rows

def get_alert_summary():
    wazuh_data = load_json(WAZUH_FILE, {"alerts": []})
    alerts     = wazuh_data.get("alerts", [])
    return {"total": len(alerts), "recent": alerts[-15:], "all": alerts}

def get_alert_rate():
    alerts     = load_json(WAZUH_FILE, {"alerts": []}).get("alerts", [])
    per_minute = defaultdict(int)
    for a in alerts:
        ts = a.get("timestamp","")
        if ts:
            per_minute[ts[11:16]] += 1
    minutes = sorted(per_minute.keys())[-20:]
    return {"labels": minutes, "counts": [per_minute[m] for m in minutes],
            "current": per_minute[minutes[-1]] if minutes else 0,
            "peak":    max(per_minute.values()) if per_minute else 0}

def get_analytics_data():
    alerts  = load_json(WAZUH_FILE, {"alerts": []}).get("alerts", [])
    actions = load_json(ACTIONS_LOG, [])
    if not isinstance(actions, list):
        actions = []
    attack_types  = defaultdict(int)
    hourly_alerts = defaultdict(int)
    for alert in alerts:
        rule     = alert.get("rule", {})
        text     = (str(rule.get("description","")) + " " +
                    " ".join(str(g) for g in rule.get("groups",[])) + " " +
                    str(alert.get("full_log",""))).lower()
        if "brute" in text:                                          attack_types["Brute Force"] += 1
        elif "sql" in text or "mysql" in text:                       attack_types["SQL/DB"] += 1
        elif "web" in text or "apache" in text or "nginx" in text:   attack_types["Web Attack"] += 1
        elif "authentication failure" in text or "failed login" in text: attack_types["Auth Failure"] += 1
        elif "scan" in text or "nmap" in text:                       attack_types["Port Scan"] += 1
        else:                                                         attack_types["Other"] += 1
        ts = alert.get("timestamp","")
        if ts:
            hourly_alerts[ts[11:13]] += 1
    hours          = [f"{i:02d}" for i in range(24)]
    def_timeline   = defaultdict(int)
    for a in actions:
        if isinstance(a, dict) and a.get("type") == "DEFENSE_TRIGGERED":
            ts = a.get("time","")
            if ts: def_timeline[ts[11:13]] += 1
    return {"attack_types": dict(attack_types), "hourly_labels": hours,
            "hourly_alerts":   [hourly_alerts.get(h,0)  for h in hours],
            "hourly_defenses": [def_timeline.get(h,0)   for h in hours],
            "defense_count":  sum(1 for a in actions if isinstance(a,dict) and a.get("type")=="DEFENSE_TRIGGERED"),
            "rollback_count": sum(1 for a in actions if isinstance(a,dict) and a.get("type")=="ROLLBACK"),
            "analysis_count": sum(1 for a in actions if isinstance(a,dict) and a.get("type")=="RISK_ANALYSIS"),
            "total_alerts": len(alerts), "total_actions": len(actions)}

def get_cbrs_history():
    history = load_json(CBRS_HISTORY_FILE, [])
    if not isinstance(history, list): return {}
    result = {}
    for asset in get_asset_rows():
        ip     = asset["ip"]
        times  = []
        scores = []
        for snap in history[-48:]:
            if ip in snap.get("scores",{}):
                times.append(snap["time"][11:16])
                scores.append(snap["scores"][ip])
        result[ip] = {"times": times, "scores": scores}
    return result

def record_cbrs_snapshot():
    assets  = get_asset_rows()
    history = load_json(CBRS_HISTORY_FILE, [])
    if not isinstance(history, list): history = []
    history.append({"time": datetime.utcnow().isoformat()+"Z", "scores": {a["ip"]: a["new_score"] for a in assets}})
    save_json(CBRS_HISTORY_FILE, history[-288:])

def get_incident_log():
    actions    = load_json(ACTIONS_LOG, [])
    alerts     = load_json(WAZUH_FILE, {"alerts": []}).get("alerts", [])
    if not isinstance(actions, list): return []
    incidents  = []
    for action in actions:
        if not isinstance(action, dict) or action.get("type") != "DEFENSE_TRIGGERED": continue
        details = action.get("details", {})
        ip      = details.get("asset_ip", "-")
        ts      = action.get("time", "")
        related = [{"desc": a.get("rule",{}).get("description",""), "level": a.get("rule",{}).get("level",0),
                    "time": a.get("timestamp","")} for a in alerts if a.get("agent_ip","") == ip]
        rb_time = next((a.get("time") for a in actions
                        if isinstance(a,dict) and a.get("type")=="ROLLBACK"
                        and a.get("details",{}).get("asset_ip")==ip and a.get("time","") > ts), None)
        incidents.append({"time": ts, "asset_ip": ip, "role": details.get("role","-"),
                          "safe_ip": details.get("safe_ip","-"), "honeypot_ip": details.get("honeypot_ip","-"),
                          "cbrs": details.get("cbrs","-"), "alert_count": details.get("alert_count",0),
                          "related_alerts": related[-5:], "rollback_time": rb_time,
                          "duration": _calc_duration(ts, rb_time)})
    return list(reversed(incidents))

def _calc_duration(start, end):
    if not start or not end: return "Active"
    try:
        s = datetime.strptime(start[:19], "%Y-%m-%dT%H:%M:%S")
        e = datetime.strptime(end[:19],   "%Y-%m-%dT%H:%M:%S")
        d = int((e - s).total_seconds())
        return f"{d}s" if d < 60 else f"{d//60}m {d%60}s"
    except Exception:
        return "-"

def get_blocked_attackers():
    data = load_json(BLOCKED_ATTACKERS_FILE, [])
    return list(reversed(data)) if isinstance(data, list) else []

def get_network_map():
    assets     = get_asset_rows()
    alerts     = load_json(WAZUH_FILE, {"alerts": []}).get("alerts", [])
    attacker_c = defaultdict(int)
    target_c   = defaultdict(int)
    for a in alerts[-100:]:
        if a.get("src_ip"):   attacker_c[a["src_ip"]] += 1
        if a.get("agent_ip"): target_c[a["agent_ip"]] += 1
    nodes = [{"ip": a["ip"], "role": a["role"], "status": a["status"], "severity": a["severity"],
              "is_shifted": a["is_shifted"], "active_safe_ip": a["active_safe_ip"],
              "honeypot_ip": a["honeypot_ip"], "attack_count": target_c.get(a["ip"],0),
              "safe_ips": a["safe_ips"]} for a in assets]
    top = sorted(attacker_c.items(), key=lambda x: x[1], reverse=True)[:5]
    return {"nodes": nodes, "top_attackers": [{"ip": ip, "count": c} for ip, c in top]}

def get_recent_actions(limit=10):
    actions = load_json(ACTIONS_LOG, [])
    if not isinstance(actions, list): return []
    return [a for a in reversed(actions) if isinstance(a, dict)][:limit]

def get_last_action():
    actions = load_json(ACTIONS_LOG, [])
    if not isinstance(actions, list) or not actions: return None
    return next((a for a in reversed(actions) if isinstance(a, dict)), None)

# ============================================================
# MONITOR
# ============================================================
def is_monitor_running():
    if not MONITOR_PID.exists(): return False
    try:
        pid = int(MONITOR_PID.read_text(encoding="utf-8").strip())
        os.kill(pid, 0)
        return True
    except Exception:
        MONITOR_PID.unlink(missing_ok=True)
        return False

def start_monitor():
    if is_monitor_running(): return True, "Monitor already running."
    try:
        MONITOR_LOG.write_text("", encoding="utf-8")
    except Exception:
        MONITOR_LOG.touch(exist_ok=True)
    log_handle = MONITOR_LOG.open("a", encoding="utf-8")
    try:
        p = subprocess.Popen(MONITOR_CMD, cwd=str(BASE_DIR),
                             stdout=log_handle, stderr=subprocess.STDOUT,
                             start_new_session=True, env={**os.environ, "PYTHONUNBUFFERED": "1"})
        MONITOR_PID.write_text(str(p.pid), encoding="utf-8")
        return True, "Monitor started successfully."
    except Exception as e:
        return False, f"Failed to start monitor: {e}"

def stop_monitor():
    if not MONITOR_PID.exists(): return True, "Monitor already stopped."
    try:
        pid = int(MONITOR_PID.read_text(encoding="utf-8").strip())
        os.killpg(pid, signal.SIGTERM)
        MONITOR_PID.unlink(missing_ok=True)
        return True, "Monitor stopped."
    except ProcessLookupError:
        MONITOR_PID.unlink(missing_ok=True)
        return True, "Monitor was not running."
    except Exception as e:
        return False, f"Failed: {e}"

def run_rollback():
    try:
        stop_monitor()
        result = subprocess.run(ROLLBACK_CMD, cwd=str(BASE_DIR),
                                capture_output=True, text=True, timeout=120)
        output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
        ok     = result.returncode == 0
        if ok:
            state = get_state()
            state["shifted_assets"] = []
            state["last_seen_alert_ids"] = {}
            state["active_safe_ips"] = {}
            save_json(STATE_FILE, state)
            append_action("DASHBOARD_ROLLBACK_CLEAR", {"cleared": True})
            output = output.strip() + "\n\nRollback executed successfully."
        return ok, output.strip()
    except subprocess.TimeoutExpired:
        return False, "Rollback timeout."
    except Exception as e:
        return False, f"Rollback failed: {e}"

def _ssh_run(user, host, command, timeout=8):
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
           "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
           "-o", "PasswordAuthentication=no", "-o", "ConnectTimeout=4",
           f"{user}@{host}", command]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return False, "", str(e)

def _iptables_block(ssh_user, host, attacker_ip):
    ok, out, _ = _ssh_run(ssh_user, host,
        f"sudo iptables -C INPUT -s {attacker_ip} -j DROP 2>/dev/null && echo EXISTS || echo NEW")
    if not ok: return False
    if "EXISTS" in out: return True
    ok, _, _ = _ssh_run(ssh_user, host, f"sudo iptables -I INPUT -s {attacker_ip} -j DROP")
    return ok

def _iptables_unblock(ssh_user, host, attacker_ip):
    ok, _, _ = _ssh_run(ssh_user, host,
        f"sudo iptables -D INPUT -s {attacker_ip} -j DROP 2>/dev/null; echo done")
    return ok

def block_attacker_iptables(attacker_ip, role=None, target_asset_ip=None):
    assets_conf = load_json(ASSETS_FILE, {"assets": []})
    results = []
    for asset in assets_conf.get("assets", []):
        if role and asset.get("role") != role: continue
        if target_asset_ip and asset.get("ip") != target_asset_ip: continue
        ssh_user = asset.get("ssh_user", "kali")
        for safe_ip in asset.get("safe_ips", []):
            ok = _iptables_block(ssh_user, safe_ip, attacker_ip)
            results.append({"host": safe_ip, "ok": ok})
    return (any(r["ok"] for r in results) if results else False), results

def unblock_attacker_dashboard(attacker_ip):
    data = load_json(BLOCKED_ATTACKERS_FILE, [])
    if not isinstance(data, list): data = []
    role = target_asset = None
    for e in reversed(data):
        if e.get("ip") == attacker_ip and e.get("status") == "blocked":
            role = e.get("asset_role"); target_asset = e.get("target_asset"); break
    assets_conf = load_json(ASSETS_FILE, {"assets": []})
    results = []
    for asset in assets_conf.get("assets", []):
        if role and asset.get("role") != role: continue
        ssh_user = asset.get("ssh_user", "kali")
        for safe_ip in asset.get("safe_ips", []):
            ok = _iptables_unblock(ssh_user, safe_ip, attacker_ip)
            results.append({"host": safe_ip, "ok": ok})
    overall_ok = any(r["ok"] for r in results) if results else False
    updated = []
    for e in data:
        if e.get("ip") == attacker_ip:
            e["status"]         = "unblocked" if overall_ok else e.get("status","blocked")
            e["unblocked_at"]   = datetime.utcnow().isoformat() + "Z"
            e["unblock_results"]= results
        updated.append(e)
    save_json(BLOCKED_ATTACKERS_FILE, updated)
    if overall_ok:
        append_action("ATTACKER_UNBLOCKED", {"attacker_ip": attacker_ip, "role": role, "results": results})
    return overall_ok


# ============================================================
# HTML — نفس تصميم الـ artifact (cyan/orange theme + login)
# ============================================================
HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>MORPHYNX</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
:root{
  --cyan:#00d4ff;--cyan-dim:rgba(0,212,255,.13);--cyan-glow:rgba(0,212,255,.4);
  --orange:#ff6b00;--orange-dim:rgba(255,107,0,.13);--orange-glow:rgba(255,107,0,.35);
  --red:#ff3355;--green:#00ff88;--yellow:#ffcc00;--purple:#9b6dff;
  --bg:#040810;--bg-panel:rgba(8,18,32,.94);--bg-card:rgba(10,22,42,.88);--bg-card2:rgba(6,14,26,.92);
  --text:#e8f4ff;--text2:#7ab3d4;--text3:#3d6080;
  --border:rgba(0,212,255,.14);--border-h:rgba(0,212,255,.38);
}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);overflow-x:hidden;min-height:100vh;}
canvas#bgc{position:fixed;inset:0;z-index:0;pointer-events:none;}
.app{position:relative;z-index:1;display:flex;flex-direction:column;min-height:100vh;}
::-webkit-scrollbar{width:4px;}::-webkit-scrollbar-thumb{background:var(--border-h);border-radius:2px;}
header{display:flex;align-items:center;gap:10px;padding:9px 18px;background:rgba(4,8,16,.9);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100;flex-wrap:wrap;}
.logo-icon{width:32px;height:32px;background:linear-gradient(135deg,var(--cyan),var(--orange));border-radius:7px;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:800;color:#000;font-family:monospace;animation:glo 3s ease-in-out infinite;cursor:pointer;flex-shrink:0;}
@keyframes glo{0%,100%{box-shadow:0 0 8px var(--cyan-glow);}50%{box-shadow:0 0 20px var(--cyan-glow),0 0 40px var(--orange-glow);}}
.logo-name{font-size:15px;font-weight:800;letter-spacing:3px;background:linear-gradient(90deg,var(--cyan),var(--orange));-webkit-background-clip:text;-webkit-text-fill-color:transparent;cursor:pointer;}
.logo-sub{font-size:8px;color:var(--text3);letter-spacing:2px;font-family:monospace;}
nav{display:flex;gap:3px;flex-wrap:wrap;}
.nb{padding:6px 11px;border:1px solid var(--border);background:transparent;color:var(--text2);border-radius:5px;cursor:pointer;font-size:11px;letter-spacing:.5px;transition:.2s;}
.nb:hover,.nb.act{border-color:var(--cyan);color:var(--cyan);background:var(--cyan-dim);box-shadow:0 0 8px var(--cyan-glow);}
.hdr-r{display:flex;align-items:center;gap:7px;margin-left:auto;}
.ib{width:30px;height:30px;border:1px solid var(--border);background:transparent;border-radius:5px;cursor:pointer;color:var(--text2);display:flex;align-items:center;justify-content:center;transition:.2s;font-size:13px;position:relative;}
.ib:hover{border-color:var(--cyan);color:var(--cyan);}
.bdg{position:absolute;top:-3px;right:-3px;width:13px;height:13px;background:var(--red);border-radius:50%;font-size:7px;color:#fff;display:flex;align-items:center;justify-content:center;font-weight:800;animation:pu 2s infinite;}
@keyframes pu{0%,100%{transform:scale(1);}50%{transform:scale(1.2);}}
.page{display:none;}.page.act{display:block;}
.main{padding:18px;max-width:1400px;margin:0 auto;width:100%;}
.stitle{font-size:10px;letter-spacing:2px;color:var(--cyan);text-transform:uppercase;margin-bottom:12px;display:flex;align-items:center;gap:7px;}
.stitle::before{content:'';width:3px;height:12px;background:var(--cyan);border-radius:2px;}
.panel{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:16px;margin-bottom:18px;}
.ph{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:18px;}
.g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-bottom:18px;}
.g4{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:18px;}
.g5{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:18px;}
@media(max-width:900px){.g2,.g3,.g4,.g5{grid-template-columns:1fr 1fr;}}
@media(max-width:600px){.g2,.g3,.g4,.g5{grid-template-columns:1fr;}}
.sc{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:16px;position:relative;overflow:hidden;cursor:pointer;transition:.3s;}
.sc::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);animation:scan 3s linear infinite;}
@keyframes scan{0%{transform:translateX(-100%);}100%{transform:translateX(100%)}}
.sc:hover{border-color:var(--cyan);box-shadow:0 0 20px var(--cyan-glow);transform:translateY(-2px);}
.sc.or::before{background:linear-gradient(90deg,transparent,var(--orange),transparent);}
.sc.or:hover{border-color:var(--orange);box-shadow:0 0 20px var(--orange-glow);}
.sc-label{font-size:9px;letter-spacing:2px;color:var(--text3);text-transform:uppercase;margin-bottom:6px;}
.sc-val{font-size:34px;font-weight:800;line-height:1;margin-bottom:3px;}
.sc-meta{font-size:10px;color:var(--text3);}
.sc-icon{position:absolute;right:12px;top:50%;transform:translateY(-50%);font-size:34px;opacity:.07;}
.cv{color:var(--cyan);}.ov{color:var(--orange);}.gv{color:var(--green);}.rv{color:var(--red);}
.live{width:6px;height:6px;border-radius:50%;background:var(--green);display:inline-block;animation:bl 1.5s infinite;margin-right:4px;}
@keyframes bl{0%,100%{opacity:1;}50%{opacity:.2;}}
.btn{padding:7px 14px;border:1px solid var(--border);background:transparent;color:var(--text2);border-radius:5px;cursor:pointer;font-size:11px;letter-spacing:.5px;transition:.2s;display:inline-flex;align-items:center;gap:5px;font-family:inherit;}
.btn:hover{border-color:var(--cyan);color:var(--cyan);background:var(--cyan-dim);}
.btn-c{border-color:var(--cyan);color:var(--cyan);background:var(--cyan-dim);}
.btn-o{border-color:var(--orange);color:var(--orange);background:var(--orange-dim);}
.btn-r{border-color:var(--red);color:var(--red);background:rgba(255,51,85,.1);}
.btn-g{border-color:var(--green);color:var(--green);background:rgba(0,255,136,.1);}
.btn-sm{padding:5px 11px;font-size:10px;}
.btn-xs{padding:3px 7px;font-size:10px;}
.bgrp{display:flex;gap:5px;flex-wrap:wrap;}
.lv{display:inline-block;padding:2px 8px;border-radius:4px;font-size:9px;letter-spacing:1px;font-weight:700;}
.lv-c{background:rgba(255,51,85,.18);color:var(--red);border:1px solid rgba(255,51,85,.35);}
.lv-h{background:rgba(255,107,0,.18);color:var(--orange);border:1px solid rgba(255,107,0,.35);}
.lv-l{background:rgba(0,255,136,.18);color:var(--green);border:1px solid rgba(0,255,136,.35);}
.lv-info{background:rgba(0,212,255,.18);color:var(--cyan);border:1px solid rgba(0,212,255,.35);}
.tbl{width:100%;border-collapse:collapse;}
.tbl th{font-size:9px;letter-spacing:2px;color:var(--text3);text-align:left;padding:6px 10px;text-transform:uppercase;border-bottom:1px solid var(--border);}
.tbl td{padding:8px 10px;border-bottom:1px solid rgba(0,212,255,.04);font-size:11px;}
.tbl tr:hover td{background:var(--cyan-dim);}
.mono{font-family:monospace;font-size:10px;}
.astrip{background:rgba(255,51,85,.09);border:1px solid rgba(255,51,85,.28);border-radius:7px;padding:8px 13px;display:flex;align-items:center;gap:9px;margin-bottom:16px;font-size:11px;color:var(--red);flex-wrap:wrap;}
.astrip-g{background:rgba(0,255,136,.08);border-color:rgba(0,255,136,.25);color:var(--green);}
.blink{animation:bl 1s infinite;}
.prow{margin-bottom:9px;}
.prow-h{display:flex;justify-content:space-between;margin-bottom:4px;font-size:11px;}
.pbar{height:4px;background:rgba(255,255,255,.05);border-radius:2px;overflow:hidden;}
.pfill{height:100%;border-radius:2px;transition:width 1.5s cubic-bezier(.16,1,.3,1);}
.pf-c{background:linear-gradient(90deg,var(--cyan),#006bff);}
.pf-o{background:linear-gradient(90deg,var(--orange),#cc0000);}
.pf-g{background:linear-gradient(90deg,var(--green),#00a855);}
.arow{display:flex;align-items:center;gap:10px;padding:10px 13px;border:1px solid var(--border);border-radius:7px;margin-bottom:7px;cursor:pointer;transition:.25s;}
.arow:hover{border-color:var(--cyan);background:var(--cyan-dim);transform:translateX(3px);}
.adot{width:8px;height:8px;border-radius:50%;flex-shrink:0;}
.adot-c{background:var(--red);box-shadow:0 0 6px var(--red);}
.adot-h{background:var(--orange);box-shadow:0 0 6px var(--orange);}
.adot-s{background:var(--green);box-shadow:0 0 6px var(--green);}
.ring-wrap{position:relative;display:inline-flex;align-items:center;justify-content:center;}
.ring-val{position:absolute;font-size:18px;font-weight:800;color:var(--cyan);}
.formula{background:var(--bg-card2);border:1px solid var(--border);border-radius:7px;padding:12px 16px;font-family:monospace;font-size:11px;color:var(--cyan);line-height:2;margin-bottom:12px;}
.fw{color:var(--orange);}.fv{color:var(--green);}
.tog{width:36px;height:20px;background:var(--text3);border-radius:10px;cursor:pointer;transition:.3s;position:relative;flex-shrink:0;}
.tog.on{background:var(--cyan);}
.tog::after{content:'';position:absolute;width:14px;height:14px;background:#fff;border-radius:50%;top:3px;left:3px;transition:.3s;}
.tog.on::after{left:19px;}
.overlay{display:none;position:fixed;z-index:200;background:rgba(4,10,22,.97);border:1px solid var(--border-h);border-radius:11px;backdrop-filter:blur(20px);box-shadow:0 14px 44px rgba(0,0,0,.6);}
.overlay.open{display:block;animation:sld .2s ease;}
@keyframes sld{from{opacity:0;transform:translateY(-8px);}to{opacity:1;transform:translateY(0);}}
#notif-ov{top:52px;right:12px;width:320px;max-height:420px;overflow:auto;}
#settings-ov{top:52px;right:12px;width:280px;padding:16px;}
.terminal{min-height:200px;max-height:340px;overflow-y:auto;white-space:pre-wrap;background:#06050d;border-radius:10px;border:1px solid rgba(0,212,255,.14);padding:12px;font-family:'Courier New',monospace;font-size:10px;color:#c8fff7;}
.toast{position:fixed;right:16px;bottom:16px;min-width:260px;padding:12px;border-radius:12px;background:rgba(4,10,22,.97);border:1px solid var(--cyan);box-shadow:0 0 20px var(--cyan-glow);display:none;z-index:999;font-size:12px;}
.toast.show{display:block;animation:fadeIn .25s ease;}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px);}to{opacity:1;transform:translateY(0);}}
.admin-wrap{display:grid;grid-template-columns:200px 1fr;min-height:500px;}
.admin-side{background:var(--bg-card2);border-right:1px solid var(--border);padding:16px 0;}
.asi{display:flex;align-items:center;gap:8px;padding:9px 16px;cursor:pointer;font-size:11px;color:var(--text2);transition:.2s;border-left:3px solid transparent;}
.asi:hover,.asi.act{color:var(--cyan);background:var(--cyan-dim);border-left-color:var(--cyan);}
.admin-content{padding:22px;}
@keyframes bfl{0%{background-position:0%}100%{background-position:200%}}
</style>
</head>
<body>
<canvas id="bgc"></canvas>
<div class="app">

<!-- ═══ LOGIN ═══ -->
<div class="page act" id="pg-login" style="min-height:100vh;display:flex;align-items:center;justify-content:center;background:radial-gradient(ellipse at 25% 60%,rgba(0,212,255,.06),transparent 55%),radial-gradient(ellipse at 75% 40%,rgba(255,107,0,.06),transparent 55%);">
<div style="width:100%;max-width:400px;padding:20px;">
<div style="text-align:center;margin-bottom:28px;">
  <div class="logo-icon" style="width:56px;height:56px;margin:0 auto 12px;font-size:14px;border-radius:13px;">MX</div>
  <div style="font-size:24px;font-weight:800;letter-spacing:5px;background:linear-gradient(90deg,var(--cyan),var(--orange));-webkit-background-clip:text;-webkit-text-fill-color:transparent;">MORPHYNX</div>
  <div style="font-size:9px;letter-spacing:3px;color:var(--text3);margin-top:4px;">ADAPTIVE MOVING TARGET DEFENSE</div>
</div>
<div style="background:var(--bg-card);border:1px solid var(--border-h);border-radius:15px;padding:28px;position:relative;overflow:hidden;">
  <div style="position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--cyan),var(--orange),var(--cyan));background-size:200%;animation:bfl 3s linear infinite;"></div>
  <div style="font-size:10px;letter-spacing:2px;color:var(--text3);margin-bottom:20px;text-align:center;">SECURE AUTHENTICATION REQUIRED</div>
  <div style="margin-bottom:13px;">
    <label style="display:block;font-size:9px;letter-spacing:2px;color:var(--text3);text-transform:uppercase;margin-bottom:4px;">Username</label>
    <input id="lu" type="text" placeholder="Enter username" style="width:100%;background:var(--bg-card2);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:12px;padding:9px 12px;outline:none;transition:.2s;font-family:inherit;" onfocus="this.style.borderColor='var(--cyan)'" onblur="this.style.borderColor='var(--border)'">
  </div>
  <div style="margin-bottom:16px;">
    <label style="display:block;font-size:9px;letter-spacing:2px;color:var(--text3);text-transform:uppercase;margin-bottom:4px;">Password</label>
    <input id="lp" type="password" placeholder="Enter password" style="width:100%;background:var(--bg-card2);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:12px;padding:9px 12px;outline:none;transition:.2s;font-family:inherit;" onfocus="this.style.borderColor='var(--cyan)'" onblur="this.style.borderColor='var(--border)'" onkeydown="if(event.key==='Enter')doLogin()">
    <div id="lerr" style="font-size:10px;color:var(--red);margin-top:3px;display:none;">Invalid credentials.</div>
  </div>
  <button onclick="doLogin()" style="width:100%;padding:11px;border:none;border-radius:6px;background:linear-gradient(135deg,var(--cyan),#0055aa);color:#000;font-size:14px;font-weight:800;letter-spacing:2px;cursor:pointer;transition:.2s;" onmouseover="this.style.boxShadow='0 0 18px var(--cyan-glow)'" onmouseout="this.style.boxShadow=''">&#9670; &nbsp;AUTHENTICATE</button>
  <div style="display:flex;align-items:center;justify-content:center;gap:14px;margin-top:18px;padding-top:14px;border-top:1px solid var(--border);">
    <div style="display:flex;align-items:center;gap:5px;font-size:9px;color:var(--text3);"><span class="live"></span>System Online</div>
    <div style="font-size:9px;color:var(--text3);">Threshold: <span style="color:var(--orange);">8.0</span></div>
    <div style="font-size:9px;color:var(--text3);">Alerts: <span style="color:var(--red);">3</span></div>
  </div>
</div>
<div style="text-align:center;margin-top:14px;font-size:10px;color:var(--text3);">MORPHYNX v1.0 &middot; Moving Target Defense System</div>
</div>
</div>

<!-- ═══ HEADER ═══ -->
<header id="hdr" style="display:none;">
  <div class="logo-icon" onclick="showPg('pg-home')">MX</div>
  <div onclick="showPg('pg-home')" style="cursor:pointer;"><div class="logo-name">MORPHYNX</div><div class="logo-sub">MOVING TARGET DEFENSE</div></div>
  <nav>
    <button class="nb act" id="nb-home"        onclick="showPg('pg-home')">&#x2B21; HOME</button>
    <button class="nb"     id="nb-analytics"   onclick="showPg('pg-analytics')">&#9678; ANALYTICS</button>
    <button class="nb"     id="nb-assets"      onclick="showPg('pg-assets')">&#9636; ASSETS</button>
    <button class="nb"     id="nb-containment" onclick="showPg('pg-containment')">&#128737; CONTAINMENT</button>
    <button class="nb"     id="nb-engine"      onclick="showPg('pg-engine')">&#9881; ENGINE</button>
    <button class="nb"     id="nb-admin"       onclick="showPg('pg-admin')">&#9874; ADMIN</button>
  </nav>
  <div class="hdr-r">
    <div class="ib" onclick="toggleNotif()">&#128276;<span class="bdg" id="nbadge">2</span></div>
    <div class="ib" onclick="toggleSettings()">&#9881;</div>
    <button class="btn btn-sm btn-o" onclick="doLogout()">&#8617; LOGOUT</button>
  </div>
</header>

<!-- OVERLAYS -->
<div class="overlay" id="notif-ov">
  <div style="padding:12px 14px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;"><span style="font-size:11px;font-weight:700;">SYSTEM ALERTS</span><button class="btn btn-xs" onclick="clearNotifs()">Clear</button></div>
  <div id="notif-list">
    <div onclick="this.style.opacity=.4" style="padding:11px 13px;border-bottom:1px solid var(--border);display:flex;gap:9px;cursor:pointer;"><div style="width:6px;height:6px;border-radius:50%;background:var(--orange);flex-shrink:0;margin-top:3px;"></div><div style="font-size:11px;">DB-SERVER CBRS = 8.02 exceeds threshold 8.0</div></div>
    <div onclick="this.style.opacity=.4" style="padding:11px 13px;display:flex;gap:9px;cursor:pointer;"><div style="width:6px;height:6px;border-radius:50%;background:var(--cyan);flex-shrink:0;margin-top:3px;"></div><div style="font-size:11px;">Monitor active &mdash; watching 10.0.0.10 &amp; 10.0.0.20</div></div>
  </div>
</div>
<div class="overlay" id="settings-ov">
  <div style="font-size:12px;font-weight:700;letter-spacing:2px;margin-bottom:12px;color:var(--cyan);">&#9881; SETTINGS</div>
  <div style="display:flex;flex-direction:column;gap:11px;">
    <div style="display:flex;align-items:center;justify-content:space-between;"><div><div style="font-size:11px;">Real-time Updates</div><div style="font-size:9px;color:var(--text3);">Live data polling</div></div><div class="tog on" onclick="this.classList.toggle('on')"></div></div>
    <div style="display:flex;align-items:center;justify-content:space-between;"><div><div style="font-size:11px;">Auto-Defense</div><div style="font-size:9px;color:var(--text3);">Trigger on threshold</div></div><div class="tog on" onclick="this.classList.toggle('on')"></div></div>
    <div style="display:flex;align-items:center;justify-content:space-between;"><div><div style="font-size:11px;">Honeypot Alerts</div><div style="font-size:9px;color:var(--text3);">Notify on hits</div></div><div class="tog on" onclick="this.classList.toggle('on')"></div></div>
    <div style="display:flex;align-items:center;justify-content:space-between;"><div><div style="font-size:11px;">pfSense Sync</div><div style="font-size:9px;color:var(--text3);">Sync alias tables</div></div><div class="tog on" onclick="this.classList.toggle('on')"></div></div>
  </div>
  <button class="btn btn-sm" style="margin-top:12px;width:100%;" onclick="document.getElementById('settings-ov').classList.remove('open')">Close</button>
</div>

<!-- ═══ HOME ═══ -->
<div class="page" id="pg-home">
<div class="main">
  <div class="astrip"><span class="blink">&#9889;</span><span><strong>CBRS BREACH:</strong> DB-SERVER (10.0.0.20) scored 8.02 &mdash; exceeds risk_threshold 8.0</span><button class="btn btn-xs btn-r" style="margin-left:auto;" onclick="showPg('pg-assets')">View &rarr;</button></div>
  <div class="g5">
    <div class="sc"   onclick="showPg('pg-assets')"><div class="sc-label">Protected Assets</div><div class="sc-val cv" id="h-assets">-</div><div class="sc-meta"><span class="live"></span>Live</div></div>
    <div class="sc or"onclick="showPg('pg-assets')"><div class="sc-label">Critical Threats</div><div class="sc-val ov" id="h-critical">-</div><div class="sc-meta">CBRS breach</div></div>
    <div class="sc"   onclick="showPg('pg-engine')"><div class="sc-label">Shifted Assets</div><div class="sc-val cv" id="h-shifted">-</div><div class="sc-meta">Active defenses</div></div>
    <div class="sc"   onclick="showPg('pg-analytics')"><div class="sc-label">Total Alerts</div><div class="sc-val cv" id="h-alerts">-</div><div class="sc-meta"><span class="live"></span>Wazuh</div></div>
    <div class="sc or"onclick="showPg('pg-containment')"><div class="sc-label">Blocked IPs</div><div class="sc-val rv" id="h-blocked">-</div><div class="sc-meta">iptables + pfSense</div></div>
  </div>
  <div class="g2">
    <div class="panel">
      <div class="ph"><div class="stitle" style="margin:0;">ASSET STATUS</div><button class="btn btn-sm btn-c" onclick="showPg('pg-assets')">Details &rarr;</button></div>
      <div id="home-assets"></div>
    </div>
    <div class="panel">
      <div class="ph"><div class="stitle" style="margin:0;">CBRS SCORES vs THRESHOLD (8.0)</div></div>
      <div style="display:flex;align-items:center;justify-content:space-around;padding:6px 0;" id="cbrs-rings"></div>
      <div style="text-align:center;font-size:9px;color:var(--text3);margin-top:4px;">Dashed ring = threshold 8.0 &middot; <a onclick="showPg('pg-admin')" style="color:var(--cyan);cursor:pointer;">CBRS Calc &rarr;</a></div>
    </div>
  </div>

  <div class="stitle">RECENT ACTIONS</div>
  <div id="recent-actions"></div>
</div>
</div>

<!-- ═══ ANALYTICS ═══ -->
<div class="page" id="pg-analytics">
<div class="main">
  <div class="ph"><div style="font-size:20px;font-weight:800;letter-spacing:3px;">&#9678; ANALYTICS</div></div>
  <div class="g4">
    <div class="sc"><div class="sc-label">Total Alerts</div><div class="sc-val cv" id="an-total">-</div></div>
    <div class="sc or"><div class="sc-label">Defense Actions</div><div class="sc-val ov" id="an-defense">-</div></div>
    <div class="sc"><div class="sc-label">Rollbacks</div><div class="sc-val gv" id="an-rollback">-</div></div>
    <div class="sc"><div class="sc-label">Risk Analyses</div><div class="sc-val cv" id="an-analysis">-</div></div>
  </div>
  <div class="g2">
    <div class="panel"><div class="stitle">ALERT TRENDS BY HOUR</div><div style="height:240px;"><canvas id="chart-trends"></canvas></div></div>
    <div class="panel"><div class="stitle">ATTACK TYPE DISTRIBUTION</div><div style="height:240px;"><canvas id="chart-pie"></canvas></div></div>
  </div>
  <div class="g2">
    <div class="panel"><div class="stitle">DEFENSE BREAKDOWN</div><div style="height:200px;"><canvas id="chart-bar"></canvas></div></div>
    <div class="panel"><div class="stitle">CBRS SCORE HISTORY</div><div style="height:200px;"><canvas id="chart-cbrs-hist"></canvas></div></div>
  </div>
  <div class="panel">
    <div class="stitle">CBRS FACTOR TABLE</div>
    <table class="tbl">
      <thead><tr><th>Factor</th><th>Weight</th><th>WEB (10.0.0.10)</th><th>Val</th><th>DB (10.0.0.20)</th><th>Val</th></tr></thead>
      <tbody>
        <tr><td>CVSS Base Score</td><td>&times;0.20</td><td class="mono">2.1/10&times;0.20</td><td style="color:var(--cyan);">0.042</td><td class="mono">2.1/10&times;0.20</td><td style="color:var(--cyan);">0.042</td></tr>
        <tr><td>Criticality</td><td>&times;0.25</td><td class="mono">5/5&times;0.25</td><td style="color:var(--cyan);">0.250</td><td class="mono">5/5&times;0.25</td><td style="color:var(--cyan);">0.250</td></tr>
        <tr><td>Exposure</td><td>&times;0.20</td><td class="mono">5/5&times;0.20</td><td style="color:var(--cyan);">0.200</td><td class="mono">4/5&times;0.20</td><td style="color:var(--orange);">0.160</td></tr>
        <tr><td>Exploit Available</td><td>&times;0.15</td><td class="mono">True&times;0.15</td><td style="color:var(--red);">0.150</td><td class="mono">True&times;0.15</td><td style="color:var(--red);">0.150</td></tr>
        <tr><td>Lateral Movement</td><td>&times;0.10</td><td class="mono">4/5&times;0.10</td><td style="color:var(--cyan);">0.080</td><td class="mono">5/5&times;0.10</td><td style="color:var(--orange);">0.100</td></tr>
        <tr><td>MAC Privilege</td><td>&times;0.10</td><td class="mono">3/5&times;0.10</td><td style="color:var(--cyan);">0.060</td><td class="mono">5/5&times;0.10</td><td style="color:var(--orange);">0.100</td></tr>
        <tr style="font-weight:700;"><td>CBRS &times;10</td><td>&mdash;</td><td>0.782&times;10</td><td style="color:var(--green);font-size:13px;">7.82</td><td>0.802&times;10</td><td style="color:var(--orange);font-size:13px;">8.02 &#9888;</td></tr>
      </tbody>
    </table>
  </div>
</div>
</div>

<!-- ═══ ASSETS ═══ -->
<div class="page" id="pg-assets">
<div class="main">
  <div class="ph"><div style="font-size:20px;font-weight:800;letter-spacing:3px;">&#9636; NETWORK ASSETS</div>
    <div class="bgrp">
      <button class="btn btn-sm btn-c" onclick="location.href='/api/export/assets.csv'">CSV</button>
      <button class="btn btn-sm"       onclick="location.href='/api/export/data.json'">JSON</button>
    </div>
  </div>
  <div class="panel">
    <input style="width:100%;background:var(--bg-card2);border:1px solid var(--border);border-radius:5px;color:var(--text);padding:7px 11px;font-size:11px;outline:none;margin-bottom:12px;font-family:inherit;" placeholder="Search IP / role..." oninput="filterAssets(this.value)">
    <table class="tbl">
      <thead><tr><th>IP</th><th>Role</th><th>CBRS</th><th>Active Safe IP</th><th>Severity</th><th>Status</th><th>Exploit</th></tr></thead>
      <tbody id="assets-table"></tbody>
    </table>
  </div>
  <div id="asset-detail" style="display:none;"></div>
  <div class="stitle">PFSENSE ALIAS TABLES</div>
  <div class="panel">
    <table class="tbl">
      <thead><tr><th>Alias</th><th>Role</th><th>Current</th><th>Purpose</th></tr></thead>
      <tbody>
        <tr><td class="mono">ACTIVE_WEB</td><td>web_server</td><td class="mono cv" id="pf-web">10.0.0.10</td><td style="font-size:10px;">Routes to current web server IP</td></tr>
        <tr><td class="mono">ACTIVE_DB</td><td>db_server</td><td class="mono ov" id="pf-db">10.0.0.20</td><td style="font-size:10px;">Routes to current db server IP</td></tr>
        <tr><td class="mono">morphynx_block_web</td><td>web_server</td><td class="mono" id="pf-block-web" style="color:var(--red);font-size:10px;">-</td><td style="font-size:10px;">Blocked attacker IPs for web</td></tr>
        <tr><td class="mono">morphynx_block_db</td><td>db_server</td><td class="mono" id="pf-block-db" style="color:var(--red);font-size:10px;">-</td><td style="font-size:10px;">Blocked attacker IPs for db</td></tr>
      </tbody>
    </table>
  </div>
</div>
</div>

<!-- ═══ CONTAINMENT ═══ -->
<div class="page" id="pg-containment">
<div class="main">
  <div class="g3">
    <div class="sc"><div class="sc-label">Total Blocked</div><div class="sc-val rv" id="c-total">-</div><div class="sc-meta">iptables</div></div>
    <div class="sc or"><div class="sc-label">Active Blocks</div><div class="sc-val ov" id="c-active">-</div><div class="sc-meta">Blocking Now</div></div>
    <div class="sc"><div class="sc-label">Released</div><div class="sc-val gv" id="c-released">-</div><div class="sc-meta">Unblocked</div></div>
  </div>
  <div class="panel" style="margin-bottom:16px;">
    <div class="stitle">MANUAL BLOCK</div>
    <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
      <input id="manual-ip" type="text" placeholder="Attacker IP (e.g. 10.0.0.50)" style="background:var(--bg-card2);border:1px solid rgba(0,212,255,.3);border-radius:8px;padding:8px 12px;color:var(--text);font-size:12px;width:220px;outline:none;font-family:inherit;">
      <select id="manual-role" style="background:var(--bg-card2);border:1px solid rgba(0,212,255,.3);border-radius:8px;padding:8px 12px;color:var(--text);font-size:12px;outline:none;font-family:inherit;">
        <option value="">All Safe IPs</option>
        <option value="web_server">Web Server</option>
        <option value="db_server">DB Server</option>
      </select>
      <button class="btn btn-r" onclick="doManualBlock()">&#128683; Block</button>
      <span id="manual-result" style="font-size:11px;color:var(--text3);"></span>
    </div>
  </div>
  <div class="panel">
    <div class="stitle">BLOCKED ATTACKERS</div>
    <table class="tbl">
      <thead><tr><th>Attacker IP</th><th>Target</th><th>Blocked At</th><th>Status</th><th>Action</th></tr></thead>
      <tbody id="containment-table"></tbody>
    </table>
    <div id="containment-empty" style="display:none;color:var(--text3);font-size:12px;padding:12px;">No attackers blocked yet.</div>
  </div>
</div>
</div>

<!-- ═══ ENGINE ═══ -->
<div class="page" id="pg-engine">
<div class="main">
  <div class="bgrp" style="margin-bottom:14px;">
    <button class="btn btn-c" onclick="startMonitor()">&#9654; Start Monitor</button>
    <button class="btn btn-r" onclick="stopMonitor()">&#9646;&#9646; Stop Monitor</button>
    <button class="btn btn-o" onclick="runRollback()">&#8617; Rollback</button>
    <button class="btn"       onclick="refreshAll()">&#8635; Refresh</button>
  </div>
  <div class="g4">
    <div class="sc"><div class="sc-label">Monitor</div><div class="sc-val" id="core-monitor" style="font-size:20px;">-</div></div>
    <div class="sc"><div class="sc-label">Shifted Assets</div><div class="sc-val cv" id="core-shifted">0</div></div>
    <div class="sc"><div class="sc-label">Actions Logged</div><div class="sc-val cv" id="core-actions">0</div></div>
    <div class="sc"><div class="sc-label">Active Safe IPs</div><div style="font-size:11px;margin-top:4px;" id="core-safe-ips">-</div></div>
  </div>
  <div class="g2">
    <div><div class="stitle">LIVE ENGINE OUTPUT</div><div class="terminal" id="engine-output">Waiting...</div></div>
    <div><div class="stitle">RECENT ALERTS</div><div class="terminal" id="alerts-output">Waiting...</div></div>
  </div>
</div>
</div>

<!-- ═══ ADMIN ═══ -->
<div class="page" id="pg-admin">
<div class="admin-wrap">
  <div class="admin-side">
    <div style="padding:12px 16px;font-size:11px;letter-spacing:3px;color:var(--cyan);border-bottom:1px solid var(--border);margin-bottom:5px;">&#9874; ADMIN</div>
    <div class="asi act" onclick="adminTab(this,'tab-config')">&#128203; Config Files</div>
    <div class="asi"     onclick="adminTab(this,'tab-cbrs')">&#8747; CBRS Calc</div>
    <div class="asi"     onclick="adminTab(this,'tab-pfsense')">&#128293; pfSense Rules</div>
    <div class="asi"     onclick="adminTab(this,'tab-incidents')">&#9889; Incidents</div>
    <div class="asi"     onclick="showPg('pg-home')">&#127968; Dashboard</div>
  </div>
  <div class="admin-content">
    <!-- Config -->
    <div id="tab-config">
      <div style="font-size:18px;font-weight:800;letter-spacing:2px;margin-bottom:16px;">CONFIGURATION FILES</div>
      <div class="g2">
        <div class="panel"><div class="stitle">assets_config.json</div><pre style="font-family:monospace;font-size:10px;color:var(--cyan);white-space:pre-wrap;background:var(--bg-card2);border:1px solid var(--border);border-radius:6px;padding:11px;max-height:260px;overflow-y:auto;" id="cfg-assets"></pre></div>
        <div class="panel"><div class="stitle">defense_state.json</div><pre style="font-family:monospace;font-size:10px;color:var(--yellow);white-space:pre-wrap;background:var(--bg-card2);border:1px solid var(--border);border-radius:6px;padding:11px;max-height:260px;overflow-y:auto;" id="cfg-state"></pre></div>
      </div>
      <div class="panel"><div class="stitle">CONSTANTS</div>
        <table class="tbl"><thead><tr><th>Constant</th><th>Value</th><th>File</th></tr></thead>
        <tbody>
          <tr><td class="mono">ALERT_COUNT_THRESHOLD</td><td style="color:var(--red);">3</td><td class="mono">morphynx_core.py</td></tr>
          <tr><td class="mono">risk_threshold</td><td style="color:var(--orange);">8.0</td><td class="mono">assets_config.json</td></tr>
          <tr><td class="mono">PFSENSE_HOST</td><td style="color:var(--cyan);">10.0.0.1</td><td class="mono">morphynx_core.py</td></tr>
          <tr><td class="mono">WAZUH_MANAGER_HOST</td><td style="color:var(--cyan);">10.0.0.30</td><td class="mono">morphynx_monitor.py</td></tr>
          <tr><td class="mono">BUFFER_MAX</td><td style="color:var(--cyan);">500</td><td class="mono">morphynx_monitor.py</td></tr>
          <tr><td class="mono">SSH_CONNECT_TIMEOUT</td><td style="color:var(--cyan);">3</td><td class="mono">morphynx_core.py</td></tr>
        </tbody></table>
      </div>
    </div>
    <!-- CBRS Calc -->
    <div id="tab-cbrs" style="display:none;">
      <div style="font-size:18px;font-weight:800;letter-spacing:2px;margin-bottom:16px;">CBRS CALCULATOR</div>
      <div class="formula">CBRS = (<br>&nbsp;&nbsp;(cvss/10) &times; <span class="fw">0.20</span> +<br>&nbsp;&nbsp;(criticality/5) &times; <span class="fw">0.25</span> +<br>&nbsp;&nbsp;(exposure/5) &times; <span class="fw">0.20</span> +<br>&nbsp;&nbsp;(exploit ? 1 : 0) &times; <span class="fw">0.15</span> +<br>&nbsp;&nbsp;(lateral/5) &times; <span class="fw">0.10</span> +<br>&nbsp;&nbsp;(mac_privilege/5) &times; <span class="fw">0.10</span><br>) &times; 10</div>
      <div class="g2">
        <div class="panel"><div class="stitle">PARAMETERS</div><div id="calc-sliders"></div>
          <div class="bgrp" style="margin-top:12px;">
            <button class="btn btn-sm btn-c" onclick="loadPreset('web')">Load WEB</button>
            <button class="btn btn-sm btn-o" onclick="loadPreset('db')">Load DB</button>
            <button class="btn btn-sm"       onclick="loadPreset('reset')">Reset</button>
          </div>
        </div>
        <div class="panel" style="display:flex;flex-direction:column;align-items:center;justify-content:center;">
          <div class="stitle">RESULT</div>
          <div class="ring-wrap">
            <svg width="160" height="160"><circle cx="80" cy="80" r="65" fill="none" stroke="rgba(0,212,255,.08)" stroke-width="10"/><circle cx="80" cy="80" r="65" fill="none" id="calc-ring" stroke="#00d4ff" stroke-width="10" stroke-linecap="round" stroke-dasharray="408.4" stroke-dashoffset="408.4" transform="rotate(-90 80 80)"/><circle cx="80" cy="80" r="65" fill="none" stroke="rgba(255,107,0,.5)" stroke-width="2" stroke-dasharray="3 10" transform="rotate(-90 80 80)"/></svg>
            <div style="text-align:center;"><div style="font-size:30px;font-weight:800;" id="calc-score">0.00</div><div style="font-size:10px;color:var(--text3);">/ 10.0</div></div>
          </div>
          <div id="calc-verdict" style="margin-top:10px;font-size:13px;font-weight:700;letter-spacing:2px;"></div>
          <div style="font-size:10px;color:var(--text3);margin-top:5px;">Threshold: 8.0</div>
        </div>
      </div>
    </div>
    <!-- pfSense -->
    <div id="tab-pfsense" style="display:none;">
      <div style="font-size:18px;font-weight:800;letter-spacing:2px;margin-bottom:16px;">PFSENSE (10.0.0.1)</div>
      <div class="panel"><div class="stitle">ALIAS MAP</div>
        <table class="tbl"><thead><tr><th>Role</th><th>Alias</th><th>Current Value</th><th>Updated When</th></tr></thead>
        <tbody>
          <tr><td>web_server</td><td class="mono">ACTIVE_WEB</td><td class="mono cv" id="adm-pf-web">-</td><td style="font-size:10px;">IP shift &rarr; safe_ip via PHP</td></tr>
          <tr><td>db_server</td><td class="mono">ACTIVE_DB</td><td class="mono ov" id="adm-pf-db">-</td><td style="font-size:10px;">IP shift &rarr; safe_ip via PHP</td></tr>
          <tr><td>web_server</td><td class="mono">morphynx_block_web</td><td id="adm-block-web" style="font-size:10px;"><span style="color:var(--text3);">(empty)</span></td><td style="font-size:10px;">Auto-block on attack</td></tr>
          <tr><td>db_server</td><td class="mono">morphynx_block_db</td><td id="adm-block-db" style="font-size:10px;"><span style="color:var(--text3);">(empty)</span></td><td style="font-size:10px;">Auto-block on attack</td></tr>
        </tbody></table>
      </div>
      <div class="panel"><div class="stitle">BLOCK MECHANISM</div>
        <div class="formula"># iptables on each safe_ip<br>sudo iptables -I INPUT -s <span class="fv">ATTACKER</span> -j DROP<br><br># pfSense PHP alias<br>php -r "_PHP_ALIAS_ADD" -- "<span class="fw">morphynx_block_web</span>" "<span class="fv">ATTACKER</span>"<br><br># Honeypot at old IP stays OPEN &rarr; traps attacker</div>
      </div>
    </div>
    <!-- Incidents -->
    <div id="tab-incidents" style="display:none;">
      <div style="font-size:18px;font-weight:800;letter-spacing:2px;margin-bottom:16px;">DEFENSE INCIDENTS</div>
      <div id="incident-log-admin"></div>
    </div>
  </div>
</div>
</div>

<div class="toast" id="toast"></div>

<script>
// ── Background canvas ──
const bgc=document.getElementById('bgc'),bx=bgc.getContext('2d');
let W,H,pts=[];
function initBg(){W=bgc.width=innerWidth;H=bgc.height=innerHeight;pts=[];for(let i=0;i<60;i++)pts.push({x:Math.random()*W,y:Math.random()*H,vx:(Math.random()-.5)*.2,vy:(Math.random()-.5)*.2,r:Math.random()*1.1+.3,a:Math.random()});}
initBg();addEventListener('resize',initBg);
function drawBg(){bx.clearRect(0,0,W,H);bx.strokeStyle='rgba(0,212,255,.022)';bx.lineWidth=1;for(let x=0;x<W;x+=40){bx.beginPath();bx.moveTo(x,0);bx.lineTo(x,H);bx.stroke();}for(let y=0;y<H;y+=40){bx.beginPath();bx.moveTo(0,y);bx.lineTo(W,y);bx.stroke();}pts.forEach(p=>{p.x+=p.vx;p.y+=p.vy;if(p.x<0||p.x>W)p.vx*=-1;if(p.y<0||p.y>H)p.vy*=-1;bx.beginPath();bx.arc(p.x,p.y,p.r,0,Math.PI*2);bx.fillStyle=`rgba(0,212,255,${p.a*.3})`;bx.fill();});pts.forEach((a,i)=>{pts.slice(i+1).forEach(b=>{const d=Math.hypot(a.x-b.x,a.y-b.y);if(d<120){bx.beginPath();bx.moveTo(a.x,a.y);bx.lineTo(b.x,b.y);bx.strokeStyle=`rgba(0,212,255,${.04*(1-d/120)})`;bx.stroke();}});});requestAnimationFrame(drawBg);}
drawBg();

// ── Nav ──
function showPg(id){document.querySelectorAll('.page').forEach(p=>p.classList.remove('act'));document.getElementById(id).classList.add('act');document.querySelectorAll('.nb').forEach(b=>b.classList.remove('act'));const m={'pg-home':'nb-home','pg-analytics':'nb-analytics','pg-assets':'nb-assets','pg-containment':'nb-containment','pg-engine':'nb-engine','pg-admin':'nb-admin'};if(m[id])document.getElementById(m[id])?.classList.add('act');document.querySelectorAll('.overlay').forEach(o=>o.classList.remove('open'));if(id==='pg-analytics')initCharts();if(id==='pg-admin'){loadAdminConfig();initCalc();}if(id==='pg-containment')loadContainment();}
function doLogin(){const u=document.getElementById('lu').value.trim(),p=document.getElementById('lp').value.trim();if((u==='admin'&&p==='morphynx')||(u===''&&p==='')){const lg=document.getElementById('pg-login');lg.classList.remove('act');lg.style.display='none';document.getElementById('hdr').style.display='flex';showPg('pg-home');}else{const e=document.getElementById('lerr');e.style.display='block';setTimeout(()=>e.style.display='none',2500);}}
function doLogout(){document.getElementById('hdr').style.display='none';document.querySelectorAll('.page').forEach(p=>{p.classList.remove('act');p.style.display='';});const lg=document.getElementById('pg-login');lg.classList.add('act');lg.style.display='flex';document.getElementById('lu').value='';document.getElementById('lp').value='';}
function toggleNotif(){document.getElementById('notif-ov').classList.toggle('open');document.getElementById('settings-ov').classList.remove('open');}
function toggleSettings(){document.getElementById('settings-ov').classList.toggle('open');document.getElementById('notif-ov').classList.remove('open');}
function clearNotifs(){document.getElementById('notif-list').innerHTML='<div style="padding:18px;text-align:center;font-size:11px;color:var(--text3);">No alerts.</div>';document.getElementById('nbadge').textContent='0';}
function adminTab(el,id){document.querySelectorAll('.admin-side .asi').forEach(a=>a.classList.remove('act'));el.classList.add('act');['tab-config','tab-cbrs','tab-pfsense','tab-incidents'].forEach(t=>{const e=document.getElementById(t);if(e)e.style.display=t===id?'block':'none';});if(id==='tab-incidents')loadIncidents();}

// ── Toast ──
function showToast(msg,ok=true){const t=document.getElementById('toast');t.textContent=msg;t.style.borderColor=ok?'var(--cyan)':'var(--red)';t.classList.add('show');setTimeout(()=>t.classList.remove('show'),4000);}

// ── API ──
async function api(url,opts={}){const r=await fetch(url,{cache:'no-store',...opts,headers:{'Cache-Control':'no-cache'}});return r.json();}

const gc='rgba(0,212,255,.04)',tc='#3d6080';
let chartsInit=false,trendCh,pieCh,barCh,cbrsCh;

// ── HOME ──
let assetCache=[];
function renderHome(data){
  const assets=data.assets||[];
  const state=data.state||{};
  const shifted=(state.shifted_assets||[]).length;
  document.getElementById('h-assets').textContent=assets.length;
  document.getElementById('h-critical').textContent=assets.filter(a=>a.severity==='CRITICAL').length;
  document.getElementById('h-shifted').textContent=shifted;
  document.getElementById('h-alerts').textContent=data.alert_total||0;
  document.getElementById('h-blocked').textContent=data.blocked_attackers_count??'-';

  // Asset rows
  assetCache=assets;
  document.getElementById('home-assets').innerHTML=assets.map(a=>`
    <div class="arow" onclick="showPg('pg-assets')">
      <div class="adot ${a.severity==='CRITICAL'?'adot-c':a.severity==='HIGH'?'adot-h':'adot-s'}"></div>
      <div style="flex:1;"><div style="font-size:12px;font-weight:700;">${a.role.toUpperCase()}</div><div class="mono" style="color:var(--text3);">${a.ip}</div></div>
      <div style="text-align:right;min-width:110px;">
        <div class="prow-h"><span style="font-size:10px;">CBRS</span><span style="font-size:10px;color:${a.new_score>=8?'var(--orange)':'var(--cyan)'};">${a.new_score}</span></div>
        <div class="pbar"><div class="pfill ${a.new_score>=8?'pf-o':'pf-c'}" style="width:${a.new_score*10}%"></div></div>
      </div>
      <span class="lv ${a.severity==='CRITICAL'?'lv-c':a.severity==='HIGH'?'lv-h':'lv-l'}">${a.status}</span>
    </div>`).join('');

  // CBRS rings
  document.getElementById('cbrs-rings').innerHTML=assets.map(a=>`
    <div style="text-align:center;">
      <div class="ring-wrap">
        <svg width="110" height="110">
          <circle cx="55" cy="55" r="45" fill="none" stroke="rgba(0,212,255,.08)" stroke-width="8"/>
          <circle cx="55" cy="55" r="45" fill="none" stroke="${a.new_score>=8?'#ff6b00':'#00d4ff'}" stroke-width="8" stroke-linecap="round"
            stroke-dasharray="282.7" stroke-dashoffset="${282.7*(1-a.new_score/10)}" transform="rotate(-90 55 55)"/>
          <circle cx="55" cy="55" r="45" fill="none" stroke="rgba(255,107,0,.5)" stroke-width="2" stroke-dasharray="3 8" transform="rotate(-90 55 55)"/>
        </svg>
        <div style="font-size:16px;font-weight:800;color:${a.new_score>=8?'var(--orange)':'var(--cyan)'};">${a.new_score}</div>
      </div>
      <div style="font-size:9px;color:var(--text3);margin-top:2px;">${a.role.replace('_',' ').toUpperCase()}</div>
      <div style="font-size:8px;color:${a.new_score>=8?'var(--red)':'var(--green)'};">${a.ip} ${a.new_score>=8?'&#9888;':'&#10003;'}</div>
    </div>`).join('');

  // Recent actions
  const icons={DEFENSE_TRIGGERED:'&#9889;',ROLLBACK:'&#8617;',RISK_ANALYSIS:'&#128202;',ATTACKER_BLOCKED:'&#128683;',ATTACKER_BLOCKED_MANUAL:'&#128683;',ATTACKER_UNBLOCKED:'&#9989;',DASHBOARD_ROLLBACK_CLEAR:'&#128465;'};
  const actions=data.recent_actions||[];
  document.getElementById('recent-actions').innerHTML=actions.slice(0,6).map(a=>{
    const d=a.details||{};
    const subip=d.asset_ip||d.attacker_ip||d.ip||(a.type.includes('ROLLBACK_CLEAR')?'System':a.type.includes('BLOCKED')?'IP: '+(d.attacker_ip||d.ip||'?'):'');
    const cls=a.type==='DEFENSE_TRIGGERED'?'lv-c':a.type==='ROLLBACK'?'lv-l':a.type.includes('BLOCKED')&&!a.type.includes('UN')?'lv-h':'lv-info';
    const lbl=a.type==='DEFENSE_TRIGGERED'?'ACTIVE':a.type==='ROLLBACK'?'DONE':a.type.includes('BLOCKED')&&!a.type.includes('UN')?'BLOCKED':'INFO';
    return `<div class="arow">
      <div style="font-size:16px;width:24px;text-align:center;">${icons[a.type]||'&#128295;'}</div>
      <div style="flex:1;"><div style="font-size:11px;font-weight:700;">${a.type.replace(/_/g,' ')}</div><div style="font-size:10px;color:var(--text3);">${subip||'-'} &middot; ${(a.time||'').slice(11,19)} UTC</div></div>
      <span class="lv ${cls}">${lbl}</span>
    </div>`;}).join('') || '<div style="color:var(--text3);font-size:12px;padding:8px;">No actions yet.</div>';

  // pfSense alias update — ACTIVE_WEB / ACTIVE_DB
  const activeIps=state.active_safe_ips||{};
  if(document.getElementById('pf-web'))document.getElementById('pf-web').textContent=activeIps['10.0.0.10']||'10.0.0.10';
  if(document.getElementById('pf-db')) document.getElementById('pf-db').textContent=activeIps['10.0.0.20']||'10.0.0.20';
  // pfSense blocked IPs — morphynx_block_web / morphynx_block_db
  api('/api/blocked-attackers').then(bd=>{
    const atk=bd.attackers||[];
    const webBlocked=atk.filter(a=>a.status==='blocked'&&(a.asset_role==='web_server'||a.asset_role==='all')).map(a=>a.ip);
    const dbBlocked =atk.filter(a=>a.status==='blocked'&&(a.asset_role==='db_server' ||a.asset_role==='all')).map(a=>a.ip);
    const elW=document.getElementById('pf-block-web');
    const elD=document.getElementById('pf-block-db');
    if(elW)elW.innerHTML=webBlocked.length?webBlocked.map(ip=>`<code style="color:var(--red);display:block;">${ip}</code>`).join(''):'<span style="color:var(--text3);">(empty)</span>';
    if(elD)elD.innerHTML=dbBlocked.length ?dbBlocked.map(ip=>`<code style="color:var(--red);display:block;">${ip}</code>`).join(''):'<span style="color:var(--text3);">(empty)</span>';
  });

  // Engine tab
  document.getElementById('core-monitor').textContent=data.monitor_running?'ON':'OFF';
  document.getElementById('core-monitor').style.color=data.monitor_running?'var(--green)':'var(--red)';
  document.getElementById('core-shifted').textContent=shifted;
  document.getElementById('core-actions').textContent=data.actions_count||0;
  const safeIps=Object.entries(activeIps).filter(([k,v])=>v&&v!=='-').map(([k,v])=>`${k}&rarr;${v}`).join('<br>');
  document.getElementById('core-safe-ips').innerHTML=safeIps||'-';
  document.getElementById('engine-output').textContent=(data.monitor_output||[]).join('\n')||'No output yet.';
  document.getElementById('alerts-output').textContent=(data.recent_alerts||[]).map(a=>`[${(a.timestamp||'').slice(11,19)}] ${a.agent_ip||'-'} | ${a.rule?.description||''}`).join('\n')||'No alerts.';

  // Assets table
  document.getElementById('assets-table').innerHTML=assets.map(a=>`
    <tr onclick="showAssetDetail('${a.ip}')">
      <td><code style="color:var(--cyan);">${a.ip}</code></td>
      <td>${a.role}</td>
      <td style="color:${a.new_score>=8?'var(--orange)':'var(--green)'};font-weight:700;">${a.new_score}</td>
      <td>${a.active_safe_ip!=='-'?`<span class="lv lv-h">${a.active_safe_ip}</span>`:'<span class="lv lv-l">Original</span>'}</td>
      <td><span class="lv ${a.severity==='CRITICAL'?'lv-c':a.severity==='HIGH'?'lv-h':'lv-l'}">${a.severity}</span></td>
      <td><span class="lv ${a.status==='AT-RISK'?'lv-c':'lv-l'}">${a.status}</span></td>
      <td>${a.exploit_available?'<span class="lv lv-c">YES</span>':'<span class="lv lv-l">NO</span>'}</td>
    </tr>`).join('');
}

function filterAssets(q){document.querySelectorAll('#assets-table tr').forEach(r=>{r.style.display=r.textContent.toLowerCase().includes(q.toLowerCase())?'':'none';});}
function showAssetDetail(ip){
  const a=assetCache.find(x=>x.ip===ip);if(!a)return;
  const d=document.getElementById('asset-detail');d.style.display='block';
  d.innerHTML=`<div class="panel"><div class="stitle">${ip} &mdash; ${a.role}</div><div class="g2">
    <div>${[['CBRS',a.new_score,'var(--orange)'],['Criticality',a.criticality+'/5',''],['Exposure',a.old_score,''],['Exploit',a.exploit_available?'Yes':'No',a.exploit_available?'var(--red)':'var(--green)'],['Active Safe IP',a.active_safe_ip,'var(--yellow)'],['Honeypot',a.honeypot_ip,'var(--purple)'],['Status',a.status,a.status==='AT-RISK'?'var(--red)':'var(--green)']].map(([k,v,c])=>`<div style="display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid rgba(0,212,255,.06);font-size:11px;"><span style="color:var(--text2);">${k}</span><span class="mono" style="color:${c||'var(--text)'};">${v}</span></div>`).join('')}</div>
    <div><div style="font-size:10px;color:var(--text3);margin-bottom:7px;">Safe IPs</div>${a.safe_ips.map(s=>`<div style="display:flex;align-items:center;gap:7px;padding:6px 10px;border:1px solid var(--border);border-radius:6px;margin-bottom:5px;"><div class="adot adot-s"></div><span class="mono cv">${s}</span></div>`).join('')}</div>
  </div></div>`;
  d.scrollIntoView({behavior:'smooth'});}


// ── ANALYTICS ──
function initCharts(){
  if(chartsInit)return;chartsInit=true;
  const defOpts=()=>({responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:tc,font:{size:9}}}},scales:{x:{ticks:{color:tc,font:{size:8}},grid:{color:gc}},y:{ticks:{color:tc,font:{size:8}},grid:{color:gc},beginAtZero:true}}});
  trendCh=new Chart(document.getElementById('chart-trends'),{type:'line',data:{labels:[],datasets:[{label:'Alerts',data:[],borderColor:'#ff3355',backgroundColor:'rgba(255,51,85,.08)',tension:.4,fill:true,pointRadius:2},{label:'Defenses',data:[],borderColor:'#00ff88',backgroundColor:'rgba(0,255,136,.08)',tension:.4,fill:true,pointRadius:2}]},options:defOpts()});
  pieCh=new Chart(document.getElementById('chart-pie'),{type:'doughnut',data:{labels:['No Data'],datasets:[{data:[1],backgroundColor:['#00d4ff'],borderWidth:0}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{color:tc,font:{size:9}}}}}});
  barCh=new Chart(document.getElementById('chart-bar'),{type:'bar',data:{labels:['Defense','Rollback','Analysis'],datasets:[{data:[0,0,0],backgroundColor:['rgba(255,51,85,.7)','rgba(0,255,136,.7)','rgba(0,212,255,.7)'],borderRadius:4}]},options:defOpts()});
  cbrsCh=new Chart(document.getElementById('chart-cbrs-hist'),{type:'line',data:{labels:[],datasets:[]},options:defOpts()});
  loadAnalytics();
}
function loadAnalytics(){
  api('/api/analytics').then(d=>{
    document.getElementById('an-total').textContent=d.total_alerts||0;
    document.getElementById('an-defense').textContent=d.defense_count||0;
    document.getElementById('an-rollback').textContent=d.rollback_count||0;
    document.getElementById('an-analysis').textContent=d.analysis_count||0;
    if(trendCh){trendCh.data.labels=d.hourly_labels;trendCh.data.datasets[0].data=d.hourly_alerts;trendCh.data.datasets[1].data=d.hourly_defenses;trendCh.update();}
    const pl=Object.keys(d.attack_types),pd=Object.values(d.attack_types);
    if(pieCh){pieCh.data.labels=pl.length?pl:['No Data'];pieCh.data.datasets[0].data=pd.length?pd:[1];pieCh.data.datasets[0].backgroundColor=['#ff5c7c','#ff4dc4','#ffd166','#00d4ff','#29ff9a','#a78bfa'];pieCh.update();}
    if(barCh){barCh.data.datasets[0].data=[d.defense_count,d.rollback_count,d.analysis_count];barCh.update();}
  });
  api('/api/cbrs-history').then(hist=>{
    const ips=Object.keys(hist);if(!ips.length)return;
    const colors=['#ff5c7c','#00d4ff','#29ff9a','#ffd166'];
    if(cbrsCh){cbrsCh.data.labels=hist[ips[0]]?.times||[];cbrsCh.data.datasets=ips.map((ip,i)=>({label:ip,data:hist[ip].scores,borderColor:colors[i%colors.length],backgroundColor:'transparent',tension:.3,pointRadius:2}));cbrsCh.update();}
  });
}

// ── CONTAINMENT ──
async function loadContainment(){
  const d=await api('/api/blocked-attackers');
  const atk=d.attackers||[];
  document.getElementById('c-total').textContent=atk.length;
  document.getElementById('c-active').textContent=atk.filter(a=>a.status==='blocked').length;
  document.getElementById('c-released').textContent=atk.filter(a=>a.status==='unblocked').length;
  const tb=document.getElementById('containment-table');
  const em=document.getElementById('containment-empty');
  if(!atk.length){tb.innerHTML='';em.style.display='block';return;}
  em.style.display='none';
  tb.innerHTML=atk.map(a=>`<tr>
    <td><code style="color:var(--red);font-weight:700;">${a.ip}</code></td>
    <td><code style="color:var(--cyan);">${a.target_asset||'-'}</code></td>
    <td style="font-size:10px;color:var(--text3);">${(a.blocked_at||'').slice(0,19).replace('T',' ')} UTC</td>
    <td><span class="lv ${a.status==='blocked'?'lv-c':'lv-l'}">${a.status.toUpperCase()}</span></td>
    <td>${a.status==='blocked'?`<button class="btn btn-xs btn-g" onclick="doUnblock('${a.ip}',this)">Unblock</button>`:'<span style="color:var(--text3);font-size:10px;">Released</span>'}</td>
  </tr>`).join('');
}
async function doUnblock(ip,btn){btn.disabled=true;btn.textContent='...';const d=await api('/api/unblock/'+ip,{method:'POST'});showToast(d.message,d.ok);await loadContainment();}
async function doManualBlock(){
  const ip=document.getElementById('manual-ip').value.trim();
  const role=document.getElementById('manual-role').value;
  const res=document.getElementById('manual-result');
  if(!ip){showToast('Enter an IP',false);return;}
  res.textContent='Blocking...';res.style.color='var(--yellow)';
  const d=await api('/api/block-manual',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip,role:role||null})});
  showToast(d.message,d.ok);
  res.textContent=d.message;res.style.color=d.ok?'var(--green)':'var(--red)';
  if(d.ok){document.getElementById('manual-ip').value='';await loadContainment();refreshAll();}
}

// ── ENGINE ──
async function startMonitor(){const d=await api('/api/monitor/start',{method:'POST'});showToast(d.message,!!d.ok);refreshAll();}
async function stopMonitor(){const d=await api('/api/monitor/stop',{method:'POST'});showToast(d.message,!!d.ok);refreshAll();}
async function runRollback(){showToast('Running rollback...',true);const d=await api('/api/rollback',{method:'POST'});showToast(d.ok?'Rollback done':'Rollback failed',d.ok);document.getElementById('engine-output').textContent=d.output||'';refreshAll();}



// ── CBRS CALC ──
const calcParams=[{id:'cvss',label:'CVSS Base Score',min:0,max:10,step:.1,val:5},{id:'criticality',label:'Criticality',min:1,max:5,step:1,val:3},{id:'exposure',label:'Exposure',min:1,max:5,step:1,val:3},{id:'exploit',label:'Exploit Available',min:0,max:1,step:1,val:0,bool:true},{id:'lateral',label:'Lateral Movement',min:1,max:5,step:1,val:3},{id:'mac_priv',label:'MAC Privilege',min:1,max:5,step:1,val:3}];
function initCalc(){
  const el=document.getElementById('calc-sliders');if(!el||el.children.length)return;
  el.innerHTML=calcParams.map(p=>`<div class="prow"><div class="prow-h"><span style="font-size:11px;">${p.label}</span><span id="pv-${p.id}" style="color:var(--cyan);font-size:11px;">${p.bool?'No':p.val}</span></div><input type="range" min="${p.min}" max="${p.max}" step="${p.step}" value="${p.val}" style="width:100%;accent-color:var(--cyan);" oninput="calcUpdate('${p.id}',this.value)"></div>`).join('');
  updateCalc();}
function calcUpdate(id,val){const p=calcParams.find(x=>x.id===id);p.val=parseFloat(val);document.getElementById('pv-'+id).textContent=p.bool?(+val?'Yes':'No'):val;updateCalc();}
function updateCalc(){
  const p=Object.fromEntries(calcParams.map(x=>[x.id,x.val]));
  const score=Math.round(((p.cvss/10)*0.20+(p.criticality/5)*0.25+(p.exposure/5)*0.20+(p.exploit?1:0)*0.15+(p.lateral/5)*0.10+(p.mac_priv/5)*0.10)*100)/10;
  document.getElementById('calc-score').textContent=score.toFixed(2);
  const ring=document.getElementById('calc-ring');
  ring.setAttribute('stroke-dashoffset',(408.4*(1-score/10)).toFixed(1));
  ring.setAttribute('stroke',score>=8?'#ff6b00':score>=6?'#ffcc00':'#00d4ff');
  const v=document.getElementById('calc-verdict');
  if(score>=8){v.textContent='EXCEEDS THRESHOLD';v.style.color='var(--red)';}
  else if(score>=6){v.textContent='ELEVATED RISK';v.style.color='var(--yellow)';}
  else{v.textContent='BELOW THRESHOLD';v.style.color='var(--green)';}
}
function loadPreset(t){
  const pr={web:{cvss:2.1,criticality:5,exposure:5,exploit:1,lateral:4,mac_priv:3},db:{cvss:2.1,criticality:5,exposure:4,exploit:1,lateral:5,mac_priv:5},reset:{cvss:5,criticality:3,exposure:3,exploit:0,lateral:3,mac_priv:3}}[t];
  calcParams.forEach(p=>{p.val=pr[p.id]||0;const inp=document.querySelector(`input[oninput*="${p.id}"]`);if(inp)inp.value=p.val;const pv=document.getElementById('pv-'+p.id);if(pv)pv.textContent=p.bool?(pr[p.id]?'Yes':'No'):pr[p.id];});updateCalc();}

// ── ADMIN ──
function loadAdminConfig(){
  api('/api/summary').then(d=>{
    const ca=document.getElementById('cfg-assets');const cs=document.getElementById('cfg-state');
    if(ca)ca.textContent=JSON.stringify(d.assets?.map(a=>({ip:a.ip,role:a.role,cbrs:a.new_score,safe_ips:a.safe_ips})),null,2);
    if(cs)cs.textContent=JSON.stringify({shifted_assets:d.shifted_assets,active_safe_ips:d.active_safe_ips,last_seen_alert_ids:d.last_seen_alert_ids},null,2);
    // Update pfSense alias map live values
    const activeIps=d.active_safe_ips||{};
    const wEl=document.getElementById('adm-pf-web');
    const dEl=document.getElementById('adm-pf-db');
    if(wEl)wEl.textContent=activeIps['10.0.0.10']||'10.0.0.10';
    if(dEl)dEl.textContent=activeIps['10.0.0.20']||'10.0.0.20';
  });
  api('/api/blocked-attackers').then(bd=>{
    const atk=bd.attackers||[];
    const webB=atk.filter(a=>a.status==='blocked'&&(a.asset_role==='web_server'||a.asset_role==='all')).map(a=>a.ip);
    const dbB =atk.filter(a=>a.status==='blocked'&&(a.asset_role==='db_server' ||a.asset_role==='all')).map(a=>a.ip);
    const bwEl=document.getElementById('adm-block-web');
    const bdEl=document.getElementById('adm-block-db');
    if(bwEl)bwEl.innerHTML=webB.length?webB.map(ip=>`<code style="color:var(--red);">${ip}</code>`).join(', '):'<span style="color:var(--text3);">(empty)</span>';
    if(bdEl)bdEl.innerHTML=dbB.length ?dbB.map(ip=>`<code style="color:var(--red);">${ip}</code>`).join(', '):'<span style="color:var(--text3);">(empty)</span>';
  });
}
function loadIncidents(){
  api('/api/incidents').then(d=>{
    const el=document.getElementById('incident-log-admin');if(!el)return;
    const incidents=d.incidents||[];
    el.innerHTML=incidents.length?incidents.map(inc=>`
      <div style="border:1px solid rgba(255,107,0,.25);border-radius:10px;padding:12px;margin-bottom:10px;background:rgba(6,14,26,.8);">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;flex-wrap:wrap;gap:6px;">
          <div style="font-size:13px;font-weight:700;color:var(--orange);">Defense: ${inc.asset_ip} (${inc.role})</div>
          <div style="display:flex;gap:5px;flex-wrap:wrap;">
            <span class="lv lv-h">CBRS: ${inc.cbrs}</span>
            <span class="lv lv-c">${inc.alert_count} alerts</span>
            <span class="lv ${inc.rollback_time?'lv-l':'lv-info'}">${inc.rollback_time?'Done':'Active'}</span>
          </div>
        </div>
        <div style="font-size:11px;display:flex;gap:16px;flex-wrap:wrap;">
          <span>Original: <code style="color:var(--cyan);">${inc.asset_ip}</code></span>
          <span>Safe IP: <code style="color:var(--yellow);">${inc.safe_ip}</code></span>
          <span>Duration: <code style="color:var(--green);">${inc.duration}</code></span>
        </div>
      </div>`).join('')
    :'<div style="color:var(--text3);font-size:12px;padding:8px;">No defense incidents yet.</div>';
  });
}

// ── MAIN LOOP ──
let lastBlocked=0;
async function refreshAll(){
  fetch('/api/record-cbrs',{method:'POST',cache:'no-store'}).catch(()=>{});
  const data=await api('/api/summary');
  renderHome(data);
  const cd=await api('/api/blocked-attackers');
  const active=(cd.attackers||[]).filter(a=>a.status==='blocked').length;
  if(active>lastBlocked&&lastBlocked>=0)showToast(`${active-lastBlocked} attacker(s) blocked!`);
  lastBlocked=active;
  document.getElementById('h-blocked').textContent=active;
  const activePg=document.querySelector('.nb.act')?.id;
  if(activePg==='nb-containment')loadContainment();
  if(activePg==='nb-analytics')loadAnalytics();
}

refreshAll();
setInterval(refreshAll,4000);
document.addEventListener('click',e=>{if(!e.target.closest('.overlay')&&!e.target.closest('.ib'))document.querySelectorAll('.overlay').forEach(o=>o.classList.remove('open'));});
</script>
</body>
</html>"""


# ============================================================
# ROUTES
# ============================================================
@app.before_request
def restrict_demo_actions():
    if request.method == "POST" and os.environ.get("MORPHYNX_LIVE") != "1":
        return jsonify({"error": "Live actions are disabled in the local preview."}), 403


@app.route("/")
def index():
    return HTML

@app.route("/api/summary")
def api_summary():
    assets = get_asset_rows()
    alert_s = get_alert_summary()
    state   = get_state()
    actions = load_json(ACTIONS_LOG, [])
    if not isinstance(actions, list): actions = []
    return jsonify({
        "assets": assets, "alert_total": alert_s["total"],
        "recent_alerts": alert_s["recent"], "actions_count": len(actions),
        "recent_actions": get_recent_actions(8), "monitor_running": is_monitor_running(),
        "state": state, "shifted_assets": state.get("shifted_assets",[]),
        "last_seen_alert_ids": state.get("last_seen_alert_ids",{}),
        "active_safe_ips": state.get("active_safe_ips",{}),
        "monitor_output": read_last_lines(MONITOR_LOG, 120),
        "last_action": get_last_action(), "alert_rate": get_alert_rate(),
        "blocked_attackers_count": len([x for x in get_blocked_attackers() if x.get("status")=="blocked"]),
    })

@app.route("/api/analytics")
def api_analytics():
    return jsonify(get_analytics_data())

@app.route("/api/cbrs-history")
def api_cbrs_history():
    return jsonify(get_cbrs_history())

@app.route("/api/record-cbrs", methods=["POST"])
def api_record_cbrs():
    record_cbrs_snapshot()
    return jsonify({"ok": True})

@app.route("/api/incidents")
def api_incidents():
    return jsonify({"incidents": get_incident_log()})

@app.route("/api/monitor/start", methods=["POST"])
def api_monitor_start():
    ok, msg = start_monitor()
    return jsonify({"ok": ok, "message": msg})

@app.route("/api/monitor/stop", methods=["POST"])
def api_monitor_stop():
    ok, msg = stop_monitor()
    return jsonify({"ok": ok, "message": msg})

@app.route("/api/rollback", methods=["POST"])
def api_rollback():
    ok, output = run_rollback()
    return jsonify({"ok": ok, "output": output})

@app.route("/api/blocked-attackers")
def api_blocked_attackers():
    return jsonify({"attackers": get_blocked_attackers()})

@app.route("/api/unblock/<attacker_ip>", methods=["POST"])
def api_unblock(attacker_ip):
    ok = unblock_attacker_dashboard(attacker_ip)
    return jsonify({"ok": ok, "ip": attacker_ip,
                    "message": f"{'Unblocked' if ok else 'Failed'} {attacker_ip}"})

@app.route("/api/block-manual", methods=["POST"])
def api_block_manual():
    data        = request.get_json(silent=True) or {}
    attacker_ip = (data.get("ip") or "").strip()
    role        = data.get("role")
    if not attacker_ip:
        return jsonify({"ok": False, "message": "IP is required"})
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", attacker_ip):
        return jsonify({"ok": False, "message": "Invalid IP format"})
    ok, results = block_attacker_iptables(attacker_ip, role=role)
    blocked = load_json(BLOCKED_ATTACKERS_FILE, [])
    if not isinstance(blocked, list): blocked = []
    if not any(e.get("ip") == attacker_ip and e.get("status") == "blocked" for e in blocked):
        blocked.append({"ip": attacker_ip, "blocked_at": datetime.utcnow().isoformat()+"Z",
                        "target_asset": "manual", "asset_role": role or "all",
                        "status": "blocked" if ok else "failed",
                        "block_results": results, "source": "dashboard_manual"})
        save_json(BLOCKED_ATTACKERS_FILE, blocked)
    if ok:
        append_action("ATTACKER_BLOCKED_MANUAL", {"attacker_ip": attacker_ip, "role": role or "all"})
    succeeded = [r["host"] for r in results if r["ok"]]
    failed    = [r["host"] for r in results if not r["ok"]]
    msg = f"Blocked {attacker_ip} on: {', '.join(succeeded)}" if succeeded else f"Failed to block {attacker_ip}"
    if failed: msg += f" | Failed: {', '.join(failed)}"
    return jsonify({"ok": ok, "ip": attacker_ip, "message": msg, "results": results})

@app.route("/api/export/assets.csv")
def export_assets_csv():
    assets = get_asset_rows()
    lines  = ["IP,Role,Old Score,CBRS Score,Active Safe IP,Severity,Status,Exploit"]
    for a in assets:
        lines.append(f"{a['ip']},{a['role']},{a['old_score']},{a['new_score']},{a['active_safe_ip']},{a['severity']},{a['status']},{a['exploit_available']}")
    return Response("\n".join(lines), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=assets.csv"})

@app.route("/api/export/data.json")
def export_json():
    data = {"assets": get_asset_rows(), "state": get_state(),
            "actions": load_json(ACTIONS_LOG, []),
            "alerts": load_json(WAZUH_FILE, {}).get("alerts", [])}
    return Response(json.dumps(data, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": "attachment;filename=morphynx_data.json"})


if __name__ == "__main__":
    if not STATE_FILE.exists():
        save_json(STATE_FILE, get_default_state())
    print("[*] MORPHYNX Dashboard starting on http://127.0.0.1:5050")
    app.run(host="127.0.0.1", port=5050, debug=False)