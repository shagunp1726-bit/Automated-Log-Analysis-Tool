"""
ForensicLens – Narrative & Attack Storyline Generator
Generates human-readable forensic narratives, attack storyline
summaries, and MITRE tactic progression reports.
"""


def generate_narrative(timeline, incident_type, severity, attacks):
    """Generate forensic investigation narrative."""
    if not timeline:
        return "No suspicious activity was detected during the investigation."

    event_types = [e["type"] for e in timeline]
    narrative = []

    narrative.append(
        f"The forensic investigation identified a {incident_type.lower()} "
        f"with an overall severity classified as {severity.lower()}."
    )

    if "AUTH_FAIL" in event_types:
        fail_count = event_types.count("AUTH_FAIL")
        narrative.append(
            f"{fail_count} failed authentication attempts were observed, "
            "suggesting a credential attack."
        )

    if "AUTH_SUCCESS" in event_types and "AUTH_FAIL" in event_types:
        narrative.append(
            "A successful login following multiple failures indicates "
            "probable credential compromise."
        )

    if "PRIV_ESCALATION" in event_types:
        narrative.append(
            "Privilege escalation activity was detected, indicating the "
            "attacker gained elevated access."
        )

    if "EXECUTION_SUSPICIOUS" in event_types or "PROCESS_CREATE" in event_types:
        narrative.append(
            "Suspicious process execution was observed, potentially "
            "involving attacker tools or malware."
        )

    if "MALWARE_INDICATOR" in event_types:
        narrative.append(
            "Malware indicators were identified, including credential "
            "dumping tools or ransomware artifacts."
        )

    if "REGISTRY" in event_types:
        narrative.append(
            "Registry modifications suggest persistence mechanisms "
            "were established."
        )

    if "USB" in event_types:
        narrative.append("Unauthorized USB device activity was detected.")

    if "FILE_COPY" in event_types:
        narrative.append("Sensitive file copy operations indicate potential data staging.")

    if "FILE_DELETE" in event_types:
        narrative.append("File deletion activity suggests possible anti-forensic measures.")

    if "NETWORK_CONN" in event_types:
        narrative.append(
            "Outbound network connections raise concerns of command-and-control "
            "communication or data exfiltration."
        )

    if "WEB_ATTACK" in event_types:
        narrative.append(
            "Web application attack attempts were detected, including "
            "SQL injection or directory traversal."
        )

    if "CLOUD_API" in event_types:
        narrative.append(
            "Cloud API calls were observed, potentially accessing "
            "sensitive resources or credentials."
        )

    if "ACCOUNT_CHANGE" in event_types:
        narrative.append(
            "Account modifications were detected, which may indicate "
            "backdoor creation or privilege manipulation."
        )

    if attacks:
        narrative.append(
            "Detected attack patterns include: " + ", ".join(attacks) + "."
        )

    narrative.append(
        f"The activity timeline began at {timeline[0]['timestamp']} "
        "and demonstrates escalation rather than isolated events."
    )

    return " ".join(narrative)


def generate_attack_storyline(events, chains=None, techniques=None):
    """
    Generate structured attack storyline from events and chain analysis.
    Returns list of storyline chapters with evidence.
    """
    chapters = []
    type_groups = {}

    for e in events:
        etype = e.get("type", "OTHER")
        if etype not in type_groups:
            type_groups[etype] = []
        type_groups[etype].append(e)

    phase_map = {
        "AUTH_FAIL": ("Reconnaissance", "Credential brute-force attack initiated"),
        "AUTH_SUCCESS": ("Initial Access", "Account access obtained"),
        "PRIV_ESCALATION": ("Privilege Escalation", "Elevated privileges acquired"),
        "EXECUTION_SUSPICIOUS": ("Execution", "Adversary tools deployed"),
        "PROCESS_CREATE": ("Execution", "Processes launched for attack operations"),
        "MALWARE_INDICATOR": ("Malware Deployment", "Malicious software indicators detected"),
        "REGISTRY": ("Persistence", "Registry-based persistence established"),
        "ACCOUNT_CHANGE": ("Persistence", "Account-based persistence created"),
        "FILE_COPY": ("Collection", "Data staged for exfiltration"),
        "USB": ("Exfiltration", "Removable media used for data transfer"),
        "NETWORK_CONN": ("C2 / Exfiltration", "Network channels established"),
        "DNS_QUERY": ("Discovery", "DNS reconnaissance performed"),
        "WEB_ATTACK": ("Initial Access", "Web exploitation attempted"),
        "FILE_DELETE": ("Defense Evasion", "Evidence destruction detected"),
        "FIREWALL": ("Defense Evasion", "Firewall rules modified"),
        "CLOUD_API": ("Cloud Operations", "Cloud resources accessed"),
    }

    phase_order = [
        "Reconnaissance", "Initial Access", "Execution",
        "Privilege Escalation", "Persistence", "Malware Deployment",
        "Defense Evasion", "Discovery", "Collection",
        "C2 / Exfiltration", "Exfiltration", "Cloud Operations",
    ]

    # Build chapters in phase order
    seen = set()
    order = 0
    for phase in phase_order:
        for etype, (p, desc) in phase_map.items():
            if p == phase and etype in type_groups and etype not in seen:
                seen.add(etype)
                evts = type_groups[etype]
                order += 1
                users = list(set(e.get("user") for e in evts if e.get("user")))
                hosts = list(set(e.get("hostname") for e in evts if e.get("hostname")))

                chapters.append({
                    "order": order,
                    "phase": phase,
                    "event_type": etype,
                    "title": desc,
                    "count": len(evts),
                    "first_seen": evts[0].get("timestamp", "?"),
                    "users": users[:5],
                    "hosts": hosts[:5],
                    "evidence": evts[0].get("raw", "")[:200],
                })

    return chapters
