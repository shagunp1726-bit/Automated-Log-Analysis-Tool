"""
ForensicLens – AI-Assisted Threat Hunting Module
Natural language query translation, investigation summaries,
risk scoring, detection suggestions
(Rule-based AI – no external API dependencies)
"""

import re
from collections import Counter, defaultdict


# ──────────────────────────────────────────────
# Natural Language → Query Translation
# ──────────────────────────────────────────────
NL_PATTERNS = [
    # Authentication queries
    (r"(?:show|find|get)\s+(?:all\s+)?failed\s+(?:login|auth|logon)s?",
     'type:AUTH_FAIL'),
    (r"(?:show|find|get)\s+(?:all\s+)?successful\s+(?:login|auth|logon)s?",
     'type:AUTH_SUCCESS'),
    (r"failed\s+(?:login|auth)s?\s+(?:for|by|from)\s+(?:user\s+)?(\S+)",
     'type:AUTH_FAIL AND user:{0}'),
    (r"(?:show|find)\s+(?:all\s+)?(?:admin|administrator)\s+(?:login|activity)",
     'user:admin'),
    (r"(?:brute\s*force|credential)\s+(?:attack|attempt)s?",
     'type:AUTH_FAIL'),
    (r"(?:show|find)\s+(?:all\s+)?privilege\s+escalation",
     'type:PRIV_ESCALATION'),

    # Network queries
    (r"(?:show|find)\s+(?:all\s+)?(?:outbound|external)\s+(?:connection|traffic|network)",
     'type:NETWORK_CONN'),
    (r"(?:show|find)\s+(?:all\s+)?(?:c2|command\s+and\s+control|beacon)",
     'category:threat'),
    (r"(?:show|find)\s+(?:all\s+)?(?:dns|domain)\s+(?:query|request|lookup)s?",
     'type:DNS_QUERY'),
    (r"(?:connections?|traffic)\s+(?:to|from)\s+(\d+\.\d+\.\d+\.\d+)",
     'ip:{0}'),
    (r"(?:show|find)\s+(?:all\s+)?exfiltration",
     'type:NETWORK_CONN'),

    # Process queries
    (r"(?:show|find)\s+(?:all\s+)?powershell\s+(?:execution|activity|command)s?",
     'process:powershell*'),
    (r"(?:show|find)\s+(?:all\s+)?(?:suspicious|malicious)\s+(?:process|execution)",
     'type:EXECUTION_SUSPICIOUS'),
    (r"(?:show|find)\s+(?:all\s+)?(?:process)\s+(?:creation|created|start)",
     'type:PROCESS_CREATE'),
    (r"(?:show|find)\s+encoded\s+commands?",
     'commandline:*encoded*'),

    # File queries
    (r"(?:show|find)\s+(?:all\s+)?(?:file\s+)?(?:deletion|deleted)",
     'type:FILE_DELETE'),
    (r"(?:show|find)\s+(?:all\s+)?(?:file\s+)?(?:copy|copied|staging)",
     'type:FILE_COPY'),
    (r"(?:show|find)\s+(?:all\s+)?usb\s+(?:activity|event|device)",
     'type:USB'),

    # Severity queries
    (r"(?:show|find)\s+(?:all\s+)?critical\s+(?:event|alert|incident)s?",
     'severity:critical'),
    (r"(?:show|find)\s+(?:all\s+)?high\s+(?:severity|risk)\s+(?:event|alert)s?",
     'severity:high'),

    # MITRE queries
    (r"(?:show|find)\s+(?:all\s+)?mitre\s+(?:technique\s+)?(T\d{4}(?:\.\d{3})?)",
     'mitre.technique:{0}'),
    (r"(?:events?|activity)\s+(?:for|from|by)\s+(?:user\s+)?(\S+)",
     'user:{0}'),
    (r"(?:events?|activity)\s+(?:for|from|on)\s+(?:host\s+)?(\S+)",
     'hostname:{0}'),

    # Compound queries
    (r"failed\s+(?:login|auth)s?\s+followed\s+by\s+(?:outbound|network)\s+(?:traffic|connection)",
     'type:AUTH_FAIL OR type:NETWORK_CONN'),
    (r"(?:show|find)\s+(?:all\s+)?(?:lateral\s+movement)",
     'category:authentication'),
    (r"(?:show|find)\s+(?:all\s+)?(?:data\s+)?(?:exfiltration|staging)\s+(?:pattern|activity)",
     'type:FILE_COPY OR type:NETWORK_CONN'),
]


def translate_nl_query(natural_language):
    """
    Translate a natural language query to the SIEM query DSL.
    Returns (translated_query, confidence, explanation).
    """
    nl = natural_language.strip().lower()

    for pattern, query_template in NL_PATTERNS:
        match = re.search(pattern, nl, re.IGNORECASE)
        if match:
            groups = match.groups()
            query = query_template
            for i, group in enumerate(groups):
                query = query.replace(f"{{{i}}}", group)
            explanation = f"Interpreted as: searching for events matching '{query}'"
            return query, 0.85, explanation

    # Fallback: use as raw text search
    return natural_language, 0.4, (
        f"No specific pattern matched. Performing full-text search for '{natural_language}'."
    )


# ──────────────────────────────────────────────
# Investigation Summary Generator
# ──────────────────────────────────────────────
def generate_investigation_summary(events, detections, mitre_techniques, entity_summary):
    """
    Generate an AI-style investigation summary.
    """
    total = len(events)
    if total == 0:
        return {
            "summary": "No events to analyze.",
            "risk_assessment": "None",
            "key_findings": [],
            "recommendations": [],
        }

    # Count by severity
    sev_counts = Counter(e.get("severity", "info") for e in events)
    type_counts = Counter(e.get("type", "OTHER") for e in events)
    category_counts = Counter(e.get("category", "other") for e in events)

    # Key findings
    findings = []

    critical_count = sev_counts.get("critical", 0)
    high_count = sev_counts.get("high", 0)

    if critical_count > 0:
        findings.append(
            f"🔴 {critical_count} critical-severity events detected requiring immediate attention."
        )
    if high_count > 0:
        findings.append(
            f"🟠 {high_count} high-severity events detected indicating active threats."
        )

    # Auth analysis
    auth_fails = type_counts.get("AUTH_FAIL", 0)
    auth_success = type_counts.get("AUTH_SUCCESS", 0)
    if auth_fails >= 5:
        findings.append(
            f"🔑 {auth_fails} failed authentication attempts detected – "
            f"possible brute force attack."
        )
    if auth_fails > 0 and auth_success > 0:
        findings.append(
            "⚠️ Failed logins followed by successful authentication – "
            "potential credential compromise."
        )

    # Process analysis
    suspicious_exec = type_counts.get("EXECUTION_SUSPICIOUS", 0)
    if suspicious_exec > 0:
        findings.append(
            f"💀 {suspicious_exec} suspicious execution events detected – "
            f"possible malware or attacker tooling."
        )

    # Network analysis
    network_events = type_counts.get("NETWORK_CONN", 0)
    if network_events > 0 and type_counts.get("FILE_COPY", 0) > 0:
        findings.append(
            "📡 File copy operations combined with network activity – "
            "possible data exfiltration pattern."
        )

    # Detection alerts
    if detections:
        for det in detections[:3]:
            findings.append(
                f"🚨 Detection: {det['rule']} (Severity: {det['severity']})"
            )

    # MITRE coverage
    if mitre_techniques:
        findings.append(
            f"🎯 {len(mitre_techniques)} MITRE ATT&CK techniques identified in event data."
        )

    # Recommendations
    recommendations = []
    if critical_count > 0 or len(detections) > 0:
        recommendations.append("Immediately escalate to incident response team.")
    if auth_fails >= 5:
        recommendations.append("Implement account lockout policies and review affected accounts.")
    if suspicious_exec > 0:
        recommendations.append("Isolate affected endpoints and run full malware scan.")
    if network_events > 5:
        recommendations.append("Review outbound network connections for C2 indicators.")
    if type_counts.get("USB", 0) > 0:
        recommendations.append("Investigate USB activity and enforce removable media policies.")
    if type_counts.get("PRIV_ESCALATION", 0) > 0:
        recommendations.append("Audit privilege escalation events and verify authorization.")

    if not recommendations:
        recommendations.append("Continue monitoring – no critical actions required at this time.")

    # Overall risk
    risk_score = (
        critical_count * 10 + high_count * 5 +
        sev_counts.get("medium", 0) * 2 +
        len(detections) * 8
    )

    if risk_score >= 50:
        risk_assessment = "CRITICAL – Active threat detected"
    elif risk_score >= 25:
        risk_assessment = "HIGH – Significant risk indicators present"
    elif risk_score >= 10:
        risk_assessment = "MEDIUM – Suspicious activity warrants investigation"
    else:
        risk_assessment = "LOW – Normal activity patterns"

    # Build narrative summary
    summary_parts = [
        f"Analysis of {total} events across {len(category_counts)} categories."
    ]
    if findings:
        summary_parts.append(f"Identified {len(findings)} key findings.")
    if detections:
        summary_parts.append(
            f"{len(detections)} behavioral detections triggered."
        )
    summary_parts.append(f"Overall risk assessment: {risk_assessment}.")

    return {
        "summary": " ".join(summary_parts),
        "risk_assessment": risk_assessment,
        "risk_score": risk_score,
        "key_findings": findings,
        "recommendations": recommendations,
        "stats": {
            "total_events": total,
            "severity_breakdown": dict(sev_counts),
            "type_breakdown": dict(type_counts.most_common(10)),
            "category_breakdown": dict(category_counts),
        }
    }


# ──────────────────────────────────────────────
# Detection Suggestions
# ──────────────────────────────────────────────
def generate_detection_suggestions(events, detections):
    """
    Suggest additional detection rules based on observed patterns.
    """
    suggestions = []
    type_counts = Counter(e.get("type", "OTHER") for e in events)

    # Suggest based on what's in the data
    if type_counts.get("AUTH_FAIL", 0) > 0 and type_counts.get("AUTH_SUCCESS", 0) > 0:
        suggestions.append({
            "title": "Credential Spray Detection",
            "description": (
                "Create a rule to detect the same password being tried across "
                "multiple accounts within a short time window."
            ),
            "query": "type:AUTH_FAIL | count by user",
            "priority": "high",
        })

    if type_counts.get("PROCESS_CREATE", 0) > 0:
        suggestions.append({
            "title": "LOLBin Execution Monitoring",
            "description": (
                "Monitor for Living-off-the-Land binary executions "
                "(certutil, mshta, regsvr32, rundll32)."
            ),
            "query": 'process:certutil* OR process:mshta* OR process:regsvr32*',
            "priority": "high",
        })

    if type_counts.get("NETWORK_CONN", 0) > 0:
        suggestions.append({
            "title": "Beacon Detection",
            "description": (
                "Detect periodic outbound connections that may indicate "
                "C2 beaconing. Look for regular interval patterns."
            ),
            "query": "type:NETWORK_CONN | count by dest_ip",
            "priority": "medium",
        })

    if type_counts.get("DNS_QUERY", 0) > 0:
        suggestions.append({
            "title": "DNS Tunneling Detection",
            "description": (
                "Monitor for unusually long DNS queries that may indicate "
                "data exfiltration via DNS tunneling."
            ),
            "query": "type:DNS_QUERY",
            "priority": "medium",
        })

    if type_counts.get("FILE_DELETE", 0) > 0:
        suggestions.append({
            "title": "Anti-Forensics Detection",
            "description": (
                "Create a rule for mass file deletion events that may "
                "indicate trace removal activity."
            ),
            "query": "type:FILE_DELETE | count by user",
            "priority": "high",
        })

    suggestions.append({
        "title": "After-Hours Activity",
        "description": (
            "Monitor for authentication and process creation events "
            "occurring outside normal business hours."
        ),
        "query": "type:AUTH_SUCCESS OR type:PROCESS_CREATE",
        "priority": "medium",
    })

    return suggestions
