
from collections import Counter, defaultdict


SEVERITY_COLORS = {
    "critical": "#ef4444",
    "high": "#f59e0b",
    "medium": "#3b82f6",
    "low": "#22c55e",
    "info": "#94a3b8",
}


def run_all_detections(events):
    """
    Run all behavioral detection rules against the event set.
    Returns list of detection alerts.
    """
    detections = []
    detections.extend(detect_brute_force_success(events))
    detections.extend(detect_priv_escalation_chain(events))
    detections.extend(detect_rare_processes(events))
    detections.extend(detect_suspicious_parent_child(events))
    detections.extend(detect_outbound_anomalies(events))
    detections.extend(detect_lateral_movement(events))
    detections.extend(detect_data_staging(events))
    detections.extend(detect_defense_evasion(events))
    return detections


# ─────────────────────────────────────────────────
# Detection 1: Brute Force → Successful Login
# ─────────────────────────────────────────────────
def detect_brute_force_success(events):
    """Detect multiple failed logins followed by a successful login."""
    alerts = []
    user_fails = defaultdict(list)
    user_success = defaultdict(list)

    for e in events:
        user = e.get("user") or "unknown"
        if e["type"] == "AUTH_FAIL":
            user_fails[user].append(e)
        elif e["type"] == "AUTH_SUCCESS":
            user_success[user].append(e)

    for user, fails in user_fails.items():
        if len(fails) >= 3 and user in user_success:
            alerts.append({
                "rule": "Brute Force → Successful Login",
                "severity": "critical",
                "color": SEVERITY_COLORS["critical"],
                "description": (
                    f"User '{user}' had {len(fails)} failed login attempts "
                    f"followed by a successful login. This pattern indicates "
                    f"potential credential compromise."
                ),
                "evidence_count": len(fails) + len(user_success[user]),
                "entities": {"user": user},
                "mitre": ["T1110 – Brute Force", "T1078 – Valid Accounts"],
                "events": [e["raw"] for e in (fails[:3] + user_success[user][:1])],
            })
        elif len(fails) >= 5:
            alerts.append({
                "rule": "Sustained Brute Force Attack",
                "severity": "high",
                "color": SEVERITY_COLORS["high"],
                "description": (
                    f"User '{user}' had {len(fails)} failed login attempts "
                    f"without success. Ongoing credential attack."
                ),
                "evidence_count": len(fails),
                "entities": {"user": user},
                "mitre": ["T1110 – Brute Force"],
                "events": [e["raw"] for e in fails[:5]],
            })

    return alerts


# ─────────────────────────────────────────────────
# Detection 2: Privilege Escalation Chain
# ─────────────────────────────────────────────────
def detect_priv_escalation_chain(events):
    """Detect login followed by privilege escalation."""
    alerts = []
    has_auth = any(e["type"] in ("AUTH_SUCCESS", "AUTH_FAIL") for e in events)
    has_priv = any(e["type"] == "PRIV_ESCALATION" for e in events)
    priv_events = [e for e in events if e["type"] == "PRIV_ESCALATION"]

    if has_auth and has_priv:
        alerts.append({
            "rule": "Authentication → Privilege Escalation",
            "severity": "critical",
            "color": SEVERITY_COLORS["critical"],
            "description": (
                f"Detected {len(priv_events)} privilege escalation event(s) "
                f"following authentication activity. This suggests an attacker "
                f"gained access and elevated privileges."
            ),
            "evidence_count": len(priv_events),
            "entities": {
                "users": list(set(e.get("user", "?") for e in priv_events if e.get("user")))
            },
            "mitre": ["T1548 – Abuse Elevation Control", "T1078 – Valid Accounts"],
            "events": [e["raw"] for e in priv_events[:3]],
        })

    return alerts


# ─────────────────────────────────────────────────
# Detection 3: Rare / Suspicious Process Execution
# ─────────────────────────────────────────────────
SUSPICIOUS_PROCESSES = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "bitsadmin.exe", "msiexec.exe", "whoami.exe", "net.exe", "net1.exe",
    "mimikatz.exe", "procdump.exe", "psexec.exe",
    "python", "python3", "perl", "ruby", "nc", "ncat", "nmap",
}


def detect_rare_processes(events):
    """Flag rare or known-suspicious process executions."""
    alerts = []
    process_events = [e for e in events if e.get("process")]
    process_counts = Counter(e["process"].lower().split("\\")[-1].split("/")[-1]
                             for e in process_events)

    for e in process_events:
        proc_name = e["process"].lower().split("\\")[-1].split("/")[-1]
        if proc_name in SUSPICIOUS_PROCESSES:
            alerts.append({
                "rule": "Suspicious Process Execution",
                "severity": "high",
                "color": SEVERITY_COLORS["high"],
                "description": (
                    f"Suspicious process '{proc_name}' was executed. "
                    f"This binary is commonly used in attack chains."
                ),
                "evidence_count": 1,
                "entities": {
                    "process": proc_name,
                    "user": e.get("user"),
                    "hostname": e.get("hostname"),
                    "commandline": (e.get("commandline") or "")[:200],
                },
                "mitre": ["T1059 – Command and Scripting Interpreter"],
                "events": [e["raw"]],
            })

    # Rare process (seen only once)
    for proc, count in process_counts.items():
        if count == 1 and proc not in SUSPICIOUS_PROCESSES:
            rare_event = next(
                (e for e in process_events
                 if e["process"].lower().endswith(proc)),
                None
            )
            if rare_event:
                alerts.append({
                    "rule": "Rare Process Execution",
                    "severity": "medium",
                    "color": SEVERITY_COLORS["medium"],
                    "description": (
                        f"Process '{proc}' was observed only once. "
                        f"Rare processes may indicate attacker tooling."
                    ),
                    "evidence_count": 1,
                    "entities": {"process": proc, "user": rare_event.get("user")},
                    "mitre": ["T1059 – Command and Scripting Interpreter"],
                    "events": [rare_event["raw"]],
                })

    return alerts


# ─────────────────────────────────────────────────
# Detection 4: Suspicious Parent-Child Process
# ─────────────────────────────────────────────────
SUSPICIOUS_PARENT_CHILD = [
    ("winword.exe", "cmd.exe"),
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("outlook.exe", "powershell.exe"),
    ("explorer.exe", "mshta.exe"),
    ("svchost.exe", "cmd.exe"),
    ("services.exe", "cmd.exe"),
    ("wmiprvse.exe", "powershell.exe"),
]


def detect_suspicious_parent_child(events):
    """Detect suspicious parent-child process relationships."""
    alerts = []

    for e in events:
        parent = (e.get("parent_process") or "").lower().split("\\")[-1].split("/")[-1]
        child = (e.get("process") or "").lower().split("\\")[-1].split("/")[-1]

        if not parent or not child:
            continue

        for sus_parent, sus_child in SUSPICIOUS_PARENT_CHILD:
            if parent == sus_parent and child == sus_child:
                alerts.append({
                    "rule": "Suspicious Parent-Child Process",
                    "severity": "critical",
                    "color": SEVERITY_COLORS["critical"],
                    "description": (
                        f"Suspicious process chain: {parent} → {child}. "
                        f"This pattern often indicates macro-based malware "
                        f"or living-off-the-land techniques."
                    ),
                    "evidence_count": 1,
                    "entities": {
                        "parent": parent, "child": child,
                        "user": e.get("user"),
                        "commandline": (e.get("commandline") or "")[:200],
                    },
                    "mitre": ["T1059 – Command and Scripting Interpreter"],
                    "events": [e["raw"]],
                })

    return alerts


# ─────────────────────────────────────────────────
# Detection 5: Outbound Network Anomalies
# ─────────────────────────────────────────────────
KNOWN_BAD_PORTS = {4444, 5555, 8888, 1234, 9999, 31337, 6667, 6697}


def detect_outbound_anomalies(events):
    """Detect suspicious outbound network activity."""
    alerts = []
    network_events = [e for e in events if e["type"] in ("NETWORK_CONN", "FIREWALL")]
    dest_ips = Counter(e.get("dest_ip") or e.get("ip") for e in network_events)

    # High-volume outbound to single IP
    for ip, count in dest_ips.items():
        if ip and count >= 10:
            alerts.append({
                "rule": "High-Volume Outbound Connection",
                "severity": "high",
                "color": SEVERITY_COLORS["high"],
                "description": (
                    f"Detected {count} outbound connections to {ip}. "
                    f"Repetitive beaconing may indicate C2 activity."
                ),
                "evidence_count": count,
                "entities": {"dest_ip": ip},
                "mitre": ["T1071 – Application Layer Protocol"],
                "events": [],
            })

    # Suspicious ports
    for e in network_events:
        port = e.get("port")
        if port and int(port) in KNOWN_BAD_PORTS:
            alerts.append({
                "rule": "Suspicious Port Communication",
                "severity": "high",
                "color": SEVERITY_COLORS["high"],
                "description": (
                    f"Communication detected on suspicious port {port}. "
                    f"This port is commonly associated with attack tools."
                ),
                "evidence_count": 1,
                "entities": {"port": port, "dest_ip": e.get("dest_ip") or e.get("ip")},
                "mitre": ["T1071 – Application Layer Protocol"],
                "events": [e["raw"]],
            })

    return alerts


# ─────────────────────────────────────────────────
# Detection 6: Lateral Movement
# ─────────────────────────────────────────────────
def detect_lateral_movement(events):
    """Detect potential lateral movement patterns."""
    alerts = []
    unique_hosts = set()
    auth_events = [e for e in events if e["type"] in ("AUTH_SUCCESS", "AUTH_FAIL")]

    for e in auth_events:
        host = e.get("hostname")
        if host:
            unique_hosts.add(host)

    if len(unique_hosts) >= 3:
        alerts.append({
            "rule": "Potential Lateral Movement",
            "severity": "high",
            "color": SEVERITY_COLORS["high"],
            "description": (
                f"Authentication events detected across {len(unique_hosts)} "
                f"unique hosts: {', '.join(list(unique_hosts)[:5])}. "
                f"Multiple host access may indicate lateral movement."
            ),
            "evidence_count": len(auth_events),
            "entities": {"hosts": list(unique_hosts)},
            "mitre": ["T1021 – Remote Services"],
            "events": [],
        })

    return alerts


# ─────────────────────────────────────────────────
# Detection 7: Data Staging / Exfiltration
# ─────────────────────────────────────────────────
def detect_data_staging(events):
    """Detect file copy followed by network activity."""
    alerts = []
    has_file_copy = any(e["type"] == "FILE_COPY" for e in events)
    has_network = any(e["type"] in ("NETWORK_CONN",) for e in events)

    if has_file_copy and has_network:
        alerts.append({
            "rule": "Data Staging → Exfiltration Pattern",
            "severity": "critical",
            "color": SEVERITY_COLORS["critical"],
            "description": (
                "File copy operations detected alongside outbound network "
                "connections. This pattern is consistent with data staging "
                "and potential exfiltration."
            ),
            "evidence_count": sum(1 for e in events
                                  if e["type"] in ("FILE_COPY", "NETWORK_CONN")),
            "entities": {},
            "mitre": ["T1005 – Data from Local System",
                      "T1041 – Exfiltration Over C2"],
            "events": [],
        })

    return alerts


# ─────────────────────────────────────────────────
# Detection 8: Defense Evasion
# ─────────────────────────────────────────────────
def detect_defense_evasion(events):
    """Detect log clearing and other defense evasion techniques."""
    alerts = []
    delete_events = [e for e in events if e["type"] == "FILE_DELETE"]

    if len(delete_events) >= 3:
        alerts.append({
            "rule": "Mass File Deletion – Possible Trace Removal",
            "severity": "critical",
            "color": SEVERITY_COLORS["critical"],
            "description": (
                f"Detected {len(delete_events)} file deletion events. "
                f"Mass deletion may indicate an attempt to remove forensic "
                f"traces or cover attack tracks."
            ),
            "evidence_count": len(delete_events),
            "entities": {},
            "mitre": ["T1070 – Indicator Removal"],
            "events": [e["raw"] for e in delete_events[:3]],
        })

    return alerts


# ─────────────────────────────────────────────────
# Entity graph builder
# ─────────────────────────────────────────────────
def build_entity_graph(events):
    """
    Build an entity relationship graph.
    Returns nodes (entities) and edges (relationships).
    """
    nodes = {}
    edges = []
    edge_set = set()

    def add_node(entity_type, value):
        if not value:
            return None
        node_id = f"{entity_type}:{value}"
        if node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "type": entity_type,
                "value": value,
                "event_count": 0,
            }
        nodes[node_id]["event_count"] += 1
        return node_id

    def add_edge(src, dst, relation):
        if src and dst and src != dst:
            key = f"{src}→{dst}"
            if key not in edge_set:
                edge_set.add(key)
                edges.append({
                    "source": src,
                    "target": dst,
                    "relation": relation,
                })

    for e in events:
        user_id = add_node("user", e.get("user"))
        ip_id = add_node("ip", e.get("ip"))
        dest_ip_id = add_node("ip", e.get("dest_ip"))
        process_id = add_node("process", e.get("process"))
        host_id = add_node("hostname", e.get("hostname"))

        add_edge(user_id, ip_id, "authenticated_from")
        add_edge(user_id, host_id, "active_on")
        add_edge(ip_id, dest_ip_id, "connected_to")
        add_edge(user_id, process_id, "executed")
        add_edge(process_id, host_id, "ran_on")

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
    }


# ─────────────────────────────────────────────────
# Process tree builder
# ─────────────────────────────────────────────────
def build_process_tree(events):
    """
    Build a process tree from parent-child relationships.
    Returns list of tree nodes.
    """
    processes = {}

    for e in events:
        pid = e.get("pid")
        ppid = e.get("ppid")
        proc = e.get("process")

        if pid and proc:
            processes[pid] = {
                "pid": pid,
                "ppid": ppid,
                "name": proc.split("\\")[-1].split("/")[-1],
                "full_path": proc,
                "user": e.get("user"),
                "commandline": (e.get("commandline") or ""),
                "timestamp": e.get("timestamp"),
                "children": [],
            }

    # Build tree
    roots = []
    for pid, proc in processes.items():
        ppid = proc["ppid"]
        if ppid and ppid in processes:
            processes[ppid]["children"].append(proc)
        else:
            roots.append(proc)

    return roots
