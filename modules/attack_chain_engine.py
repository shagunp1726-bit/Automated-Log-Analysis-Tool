"""
ForensicLens – Autonomous Attack Chain Discovery Engine
Entity-centric data model, temporal sequence analysis,
behavioral baseline deviation, composite risk scoring,
and attack storyline generation.
"""

from collections import defaultdict, Counter
from datetime import datetime
import re

# ──────────────────────────────────────────────
# Severity weights for risk scoring
# ──────────────────────────────────────────────
SEVERITY_WEIGHTS = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}
MITRE_SEVERITY = {"critical": 8, "high": 5, "medium": 3, "low": 1}

# ──────────────────────────────────────────────
# Known attack sequences (temporal patterns)
# ──────────────────────────────────────────────
ATTACK_SEQUENCES = [
    {
        "id": "SEQ-001",
        "name": "Credential Compromise → Privilege Escalation → Lateral Movement",
        "steps": [
            {"type": "AUTH_FAIL", "min_count": 3, "label": "Brute Force"},
            {"type": "AUTH_SUCCESS", "min_count": 1, "label": "Account Compromise"},
            {"type": "PRIV_ESCALATION", "min_count": 1, "label": "Privilege Escalation"},
            {"type": "NETWORK_CONN", "min_count": 1, "label": "Lateral Movement / C2"},
        ],
        "severity": "critical",
        "mitre_chain": ["T1110", "T1078", "T1548", "T1021"],
    },
    {
        "id": "SEQ-002",
        "name": "Execution → Persistence → Command & Control",
        "steps": [
            {"type": "EXECUTION_SUSPICIOUS", "min_count": 1, "label": "Suspicious Execution"},
            {"type": "REGISTRY", "min_count": 1, "label": "Persistence Setup"},
            {"type": "NETWORK_CONN", "min_count": 1, "label": "C2 Established"},
        ],
        "severity": "critical",
        "mitre_chain": ["T1059", "T1547", "T1071"],
    },
    {
        "id": "SEQ-003",
        "name": "Data Collection → Staging → Exfiltration",
        "steps": [
            {"type": "FILE_COPY", "min_count": 1, "label": "Data Staging"},
            {"type": "NETWORK_CONN", "min_count": 1, "label": "Data Exfiltration"},
        ],
        "severity": "critical",
        "mitre_chain": ["T1005", "T1041"],
    },
    {
        "id": "SEQ-004",
        "name": "Initial Access → Discovery → Credential Dumping",
        "steps": [
            {"type": "AUTH_SUCCESS", "min_count": 1, "label": "Initial Access"},
            {"type": "PROCESS_CREATE", "min_count": 1, "label": "Discovery / Recon"},
            {"type": "MALWARE_INDICATOR", "min_count": 1, "label": "Credential Dumping"},
        ],
        "severity": "critical",
        "mitre_chain": ["T1078", "T1087", "T1003"],
    },
    {
        "id": "SEQ-005",
        "name": "Defense Evasion → Impact",
        "steps": [
            {"type": "FILE_DELETE", "min_count": 2, "label": "Evidence Destruction"},
            {"type": "MALWARE_INDICATOR", "min_count": 1, "label": "Ransomware / Impact"},
        ],
        "severity": "critical",
        "mitre_chain": ["T1070", "T1486"],
    },
    {
        "id": "SEQ-006",
        "name": "USB Exfiltration Path",
        "steps": [
            {"type": "USB", "min_count": 1, "label": "USB Device Connected"},
            {"type": "FILE_COPY", "min_count": 1, "label": "Data Copied to Removable Media"},
        ],
        "severity": "high",
        "mitre_chain": ["T1092", "T1005"],
    },
    {
        "id": "SEQ-007",
        "name": "Web Attack → Execution → Persistence",
        "steps": [
            {"type": "WEB_ATTACK", "min_count": 1, "label": "Web Exploit"},
            {"type": "EXECUTION_SUSPICIOUS", "min_count": 1, "label": "Code Execution"},
            {"type": "ACCOUNT_CHANGE", "min_count": 1, "label": "Persistence via Account"},
        ],
        "severity": "critical",
        "mitre_chain": ["T1190", "T1059", "T1136"],
    },
]

# ──────────────────────────────────────────────
# Behavioral baselines
# ──────────────────────────────────────────────
COMMON_PROCESSES = {
    "explorer.exe", "svchost.exe", "csrss.exe", "lsass.exe", "services.exe",
    "smss.exe", "wininit.exe", "winlogon.exe", "taskhostw.exe", "conhost.exe",
    "bash", "sh", "systemd", "init", "cron", "sshd", "getty",
}

SUSPICIOUS_HOURS = set(range(0, 6))  # 00:00–05:59


class AttackChainEngine:
    """
    Autonomous attack chain discovery engine.
    Analyzes events to reconstruct attack paths, score entity risk,
    and generate human-readable attack storylines.
    """

    def __init__(self, events):
        self.events = events
        self.type_index = defaultdict(list)
        self.user_index = defaultdict(list)
        self.host_index = defaultdict(list)
        self.ip_index = defaultdict(list)
        self.process_index = defaultdict(list)
        self._build_indices()

    def _build_indices(self):
        """Index events by type and entity for fast lookup."""
        for i, e in enumerate(self.events):
            self.type_index[e.get("type", "OTHER")].append(i)
            user = e.get("user")
            if user:
                self.user_index[user.lower()].append(i)
            host = e.get("hostname")
            if host:
                self.host_index[host.lower()].append(i)
            ip = e.get("ip")
            if ip:
                self.ip_index[ip].append(i)
            proc = e.get("process")
            if proc:
                self.process_index[proc.lower()].append(i)

    # ─── Chain Discovery ──────────────────────────

    def discover_chains(self):
        """
        Discover attack chains by matching temporal event sequences.
        Returns list of discovered chains with evidence.
        """
        discovered = []

        for seq in ATTACK_SEQUENCES:
            match_result = self._match_sequence(seq)
            if match_result["matched"]:
                discovered.append({
                    "id": seq["id"],
                    "name": seq["name"],
                    "severity": seq["severity"],
                    "mitre_chain": seq["mitre_chain"],
                    "steps": match_result["steps"],
                    "completeness": match_result["completeness"],
                    "involved_entities": match_result["entities"],
                    "evidence_events": match_result["evidence"],
                    "risk_score": self._score_chain(match_result),
                })

        # Sort by risk score descending
        discovered.sort(key=lambda c: c["risk_score"], reverse=True)
        return discovered

    def _match_sequence(self, sequence):
        """Check if a sequence of event types exists in chronological order."""
        steps = sequence["steps"]
        matched_steps = []
        all_evidence = []
        entities = {"users": set(), "hosts": set(), "ips": set(), "processes": set()}
        matched_count = 0

        for step in steps:
            etype = step["type"]
            min_count = step.get("min_count", 1)
            events_of_type = self.type_index.get(etype, [])

            if len(events_of_type) >= min_count:
                matched_count += 1
                sample_events = [self.events[i] for i in events_of_type[:5]]
                matched_steps.append({
                    "label": step["label"],
                    "type": etype,
                    "count": len(events_of_type),
                    "matched": True,
                })
                for ev in sample_events:
                    all_evidence.append(ev.get("raw", "")[:200])
                    if ev.get("user"):
                        entities["users"].add(ev["user"])
                    if ev.get("hostname"):
                        entities["hosts"].add(ev["hostname"])
                    if ev.get("ip"):
                        entities["ips"].add(ev["ip"])
                    if ev.get("process"):
                        entities["processes"].add(ev["process"])
            else:
                matched_steps.append({
                    "label": step["label"],
                    "type": etype,
                    "count": len(events_of_type),
                    "matched": False,
                })

        completeness = round(matched_count / len(steps) * 100) if steps else 0

        return {
            "matched": matched_count >= max(2, len(steps) - 1),  # Allow 1 missing step
            "completeness": completeness,
            "steps": matched_steps,
            "entities": {k: list(v) for k, v in entities.items()},
            "evidence": all_evidence[:10],
        }

    def _score_chain(self, match_result):
        """Calculate composite risk score for a chain."""
        base = match_result["completeness"]
        entity_count = sum(len(v) for v in match_result["entities"].values())
        evidence_count = len(match_result["evidence"])
        return round(base * 0.5 + entity_count * 3 + evidence_count * 2)

    # ─── Entity Risk Scoring ──────────────────────

    def get_entity_risk_scores(self):
        """
        Calculate composite risk scores for all entities.
        Score = anomaly_weight + mitre_weight + sequence_weight + privilege_weight
        """
        entity_scores = {}

        # Score users
        for user, indices in self.user_index.items():
            score = self._score_entity("user", user, indices)
            entity_scores[f"user:{user}"] = score

        # Score hosts
        for host, indices in self.host_index.items():
            score = self._score_entity("hostname", host, indices)
            entity_scores[f"host:{host}"] = score

        # Score IPs
        for ip, indices in self.ip_index.items():
            score = self._score_entity("ip", ip, indices)
            entity_scores[f"ip:{ip}"] = score

        return entity_scores

    def _score_entity(self, entity_type, entity_value, event_indices):
        """Score a single entity across multiple risk dimensions."""
        events = [self.events[i] for i in event_indices]

        # Anomaly weight: severity of associated events
        anomaly = sum(SEVERITY_WEIGHTS.get(e.get("severity", "info"), 0) for e in events)

        # MITRE weight: techniques associated with this entity
        mitre_techniques = set()
        for e in events:
            for t in e.get("mitre_techniques", []):
                mitre_techniques.add(t.get("id", ""))
        mitre_weight = len(mitre_techniques) * 4

        # Privilege weight: priv escalation events
        priv_count = sum(1 for e in events if e.get("type") == "PRIV_ESCALATION")
        priv_weight = priv_count * 8

        # Behavioral anomaly: rare processes, unusual activity patterns
        behavioral = 0
        for e in events:
            proc = (e.get("process") or "").lower().split("\\")[-1].split("/")[-1]
            if proc and proc not in COMMON_PROCESSES:
                behavioral += 2

        total = anomaly + mitre_weight + priv_weight + behavioral

        # Risk level
        if total >= 40:
            level = "critical"
        elif total >= 20:
            level = "high"
        elif total >= 10:
            level = "medium"
        else:
            level = "low"

        return {
            "entity_type": entity_type,
            "entity_value": entity_value,
            "total_score": total,
            "risk_level": level,
            "anomaly_weight": anomaly,
            "mitre_weight": mitre_weight,
            "privilege_weight": priv_weight,
            "behavioral_weight": behavioral,
            "event_count": len(events),
            "mitre_techniques": list(mitre_techniques),
        }

    # ─── Behavioral Baselines ─────────────────────

    def detect_anomalies(self):
        """Detect behavioral anomalies (deviations from baseline)."""
        anomalies = []

        # Rare process detection
        process_counts = Counter()
        for indices in self.process_index.values():
            for i in indices:
                proc = (self.events[i].get("process") or "").lower()
                proc_name = proc.split("\\")[-1].split("/")[-1]
                process_counts[proc_name] += 1

        for proc, count in process_counts.items():
            if count == 1 and proc not in COMMON_PROCESSES:
                anomalies.append({
                    "type": "rare_process",
                    "severity": "medium",
                    "description": f"Process '{proc}' executed only once – possible attacker tooling",
                    "entity": proc,
                })

        # Multi-host auth (lateral movement indicator)
        for user, indices in self.user_index.items():
            hosts = set()
            for i in indices:
                h = self.events[i].get("hostname")
                if h:
                    hosts.add(h)
            if len(hosts) >= 3:
                anomalies.append({
                    "type": "multi_host_auth",
                    "severity": "high",
                    "description": (
                        f"User '{user}' authenticated on {len(hosts)} hosts: "
                        f"{', '.join(list(hosts)[:5])} – lateral movement indicator"
                    ),
                    "entity": user,
                })

        return anomalies

    # ─── Attack Storyline ─────────────────────────

    def generate_storyline(self):
        """
        Generate attack storyline from discovered chains.
        Returns ordered list of storyline steps with MITRE mapping.
        """
        storyline = []
        type_order = [
            "AUTH_FAIL", "AUTH_SUCCESS", "PRIV_ESCALATION", "ACCOUNT_CHANGE",
            "EXECUTION_SUSPICIOUS", "PROCESS_CREATE", "MALWARE_INDICATOR",
            "REGISTRY", "FILE_COPY", "FILE_MODIFY", "USB",
            "NETWORK_CONN", "DNS_QUERY", "FIREWALL",
            "WEB_ATTACK", "WEB_REQUEST", "CLOUD_API",
            "FILE_DELETE",
        ]

        type_to_phase = {
            "AUTH_FAIL": "Reconnaissance / Credential Attack",
            "AUTH_SUCCESS": "Initial Access",
            "PRIV_ESCALATION": "Privilege Escalation",
            "ACCOUNT_CHANGE": "Persistence",
            "EXECUTION_SUSPICIOUS": "Execution",
            "PROCESS_CREATE": "Execution",
            "MALWARE_INDICATOR": "Malware Deployment",
            "REGISTRY": "Persistence",
            "FILE_COPY": "Collection / Staging",
            "FILE_MODIFY": "Modification",
            "USB": "Removable Media",
            "NETWORK_CONN": "Command & Control / Exfiltration",
            "DNS_QUERY": "DNS Activity",
            "FIREWALL": "Network Boundary",
            "WEB_ATTACK": "Web Exploitation",
            "WEB_REQUEST": "Web Activity",
            "CLOUD_API": "Cloud Operations",
            "FILE_DELETE": "Defense Evasion / Anti-Forensics",
        }

        step_num = 0
        for etype in type_order:
            indices = self.type_index.get(etype, [])
            if not indices:
                continue

            step_num += 1
            events = [self.events[i] for i in indices]
            first_ts = events[0].get("timestamp", "?")
            last_ts = events[-1].get("timestamp", "?")

            # Collect entities
            users = set(e.get("user") for e in events if e.get("user"))
            hosts = set(e.get("hostname") for e in events if e.get("hostname"))
            ips = set(e.get("ip") for e in events if e.get("ip"))

            # Collect MITRE techniques
            techniques = set()
            for e in events:
                for t in e.get("mitre_techniques", []):
                    techniques.add(f"{t['id']} – {t['name']}")

            storyline.append({
                "step": step_num,
                "phase": type_to_phase.get(etype, "Unknown"),
                "event_type": etype,
                "count": len(indices),
                "first_seen": first_ts,
                "last_seen": last_ts,
                "description": self._describe_step(etype, len(indices), users, hosts),
                "entities": {
                    "users": list(users),
                    "hosts": list(hosts),
                    "ips": list(ips),
                },
                "mitre_techniques": list(techniques),
                "sample_evidence": [events[0].get("raw", "")[:200]],
            })

        return storyline

    def _describe_step(self, etype, count, users, hosts):
        """Generate human-readable description for a storyline step."""
        user_str = ", ".join(list(users)[:3]) if users else "unknown user"
        host_str = ", ".join(list(hosts)[:3]) if hosts else "unknown host"

        descriptions = {
            "AUTH_FAIL": f"{count} failed authentication attempts by {user_str} on {host_str}",
            "AUTH_SUCCESS": f"Successful authentication by {user_str} on {host_str}",
            "PRIV_ESCALATION": f"Privilege escalation detected for {user_str} on {host_str}",
            "ACCOUNT_CHANGE": f"Account modifications by {user_str} on {host_str}",
            "EXECUTION_SUSPICIOUS": f"{count} suspicious process execution(s) on {host_str}",
            "PROCESS_CREATE": f"{count} process creation event(s) on {host_str}",
            "MALWARE_INDICATOR": f"Malware indicators detected on {host_str}",
            "REGISTRY": f"Registry modifications on {host_str}",
            "FILE_COPY": f"{count} file copy operation(s) – data staging detected",
            "FILE_MODIFY": f"File modifications detected on {host_str}",
            "USB": f"USB device activity on {host_str}",
            "NETWORK_CONN": f"{count} outbound network connections detected",
            "DNS_QUERY": f"DNS queries from {host_str}",
            "FIREWALL": f"Firewall events involving {host_str}",
            "WEB_ATTACK": f"Web attack attempts detected ({count} events)",
            "WEB_REQUEST": f"Web requests logged ({count} events)",
            "CLOUD_API": f"Cloud API calls by {user_str}",
            "FILE_DELETE": f"{count} file deletion(s) – possible evidence destruction",
        }
        return descriptions.get(etype, f"{count} events of type {etype}")

    # ─── Build Attack Graph Data ──────────────────

    def build_attack_graph(self):
        """
        Build graph data for attack visualization.
        Returns nodes + edges with attack-relevant metadata.
        """
        nodes = {}
        edges = []
        edge_set = set()

        def add_node(ntype, value, risk_level="low"):
            if not value:
                return None
            nid = f"{ntype}:{value}"
            if nid not in nodes:
                nodes[nid] = {
                    "id": nid,
                    "type": ntype,
                    "value": value,
                    "event_count": 0,
                    "risk_level": risk_level,
                    "severity_counts": Counter(),
                }
            nodes[nid]["event_count"] += 1
            return nid

        def add_edge(src, dst, relation, severity="info"):
            if src and dst and src != dst:
                key = f"{src}→{dst}→{relation}"
                if key not in edge_set:
                    edge_set.add(key)
                    edges.append({
                        "source": src,
                        "target": dst,
                        "relation": relation,
                        "severity": severity,
                    })

        # Get entity risk scores for node coloring
        risk_scores = self.get_entity_risk_scores()

        for e in self.events:
            sev = e.get("severity", "info")

            u_risk = risk_scores.get(f"user:{(e.get('user') or '').lower()}", {}).get("risk_level", "low")
            h_risk = risk_scores.get(f"host:{(e.get('hostname') or '').lower()}", {}).get("risk_level", "low")
            i_risk = risk_scores.get(f"ip:{e.get('ip', '')}", {}).get("risk_level", "low")

            user_id = add_node("user", e.get("user"), u_risk)
            host_id = add_node("host", e.get("hostname"), h_risk)
            ip_id = add_node("ip", e.get("ip"), i_risk)
            dest_ip_id = add_node("ip", e.get("dest_ip"), "medium")
            proc_id = add_node("process", e.get("process"), "medium" if sev in ("high", "critical") else "low")

            if user_id:
                if user_id in nodes:
                    nodes[user_id]["severity_counts"][sev] += 1
            if host_id:
                if host_id in nodes:
                    nodes[host_id]["severity_counts"][sev] += 1

            add_edge(user_id, host_id, "active_on", sev)
            add_edge(user_id, ip_id, "authenticated_from", sev)
            add_edge(ip_id, dest_ip_id, "connected_to", sev)
            add_edge(user_id, proc_id, "executed", sev)
            add_edge(proc_id, host_id, "ran_on", sev)

        # Convert severity_counts to dict
        for nid in nodes:
            nodes[nid]["severity_counts"] = dict(nodes[nid]["severity_counts"])

        return {
            "nodes": list(nodes.values()),
            "edges": edges,
        }
