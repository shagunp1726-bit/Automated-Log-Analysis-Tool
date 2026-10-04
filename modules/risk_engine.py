"""
ForensicLens – Multi-Factor Risk Scoring Engine
Composite entity risk scoring, risk accumulation over time,
and severity classification.
"""


SEVERITY_WEIGHTS = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}

TYPE_WEIGHTS = {
    "AUTH_FAIL": 2, "AUTH_SUCCESS": 1, "PRIV_ESCALATION": 8,
    "NETWORK_CONN": 3, "USB": 2, "FILE_COPY": 3, "FILE_DELETE": 4,
    "EXECUTION_SUSPICIOUS": 6, "MALWARE_INDICATOR": 8,
    "PROCESS_CREATE": 2, "REGISTRY": 4, "WEB_ATTACK": 7,
    "ACCOUNT_CHANGE": 5, "CLOUD_API": 2, "DNS_QUERY": 1,
    "FIREWALL": 2, "WEB_REQUEST": 1,
}


def calculate_risk(events, attacks):
    """
    Multi-factor risk scoring.
    Factors: event severity weights, MITRE technique count,
    attack chain count, behavioral detection count.
    """
    score = 0

    # Event type-based scoring
    for e in events:
        etype = e.get("type", "OTHER")
        score += TYPE_WEIGHTS.get(etype, 1)

    # Severity-based scoring
    for e in events:
        score += SEVERITY_WEIGHTS.get(e.get("severity", "info"), 0)

    # Attack chain multiplier
    score += len(attacks) * 5

    # MITRE technique diversity bonus
    unique_techniques = set()
    for e in events:
        for t in e.get("mitre_techniques", []):
            unique_techniques.add(t.get("id", ""))
    score += len(unique_techniques) * 3

    # Determine severity
    if score >= 100:
        severity = "Critical"
    elif score >= 50:
        severity = "High"
    elif score >= 20:
        severity = "Medium"
    else:
        severity = "Low"

    return score, severity


def calculate_entity_risk_timeline(events):
    """
    Build risk accumulation timeline per entity.
    Returns dict: entity -> list of {timestamp, cumulative_risk, event_type}.
    """
    from collections import defaultdict
    timelines = defaultdict(list)
    entity_scores = defaultdict(int)

    for e in events:
        etype = e.get("type", "OTHER")
        ts = e.get("timestamp", "?")
        weight = TYPE_WEIGHTS.get(etype, 1) + SEVERITY_WEIGHTS.get(e.get("severity", "info"), 0)

        # Track per user
        user = e.get("user")
        if user:
            entity_scores[f"user:{user}"] += weight
            timelines[f"user:{user}"].append({
                "timestamp": ts,
                "cumulative_risk": entity_scores[f"user:{user}"],
                "event_type": etype,
                "delta": weight,
            })

        # Track per host
        host = e.get("hostname")
        if host:
            entity_scores[f"host:{host}"] += weight
            timelines[f"host:{host}"].append({
                "timestamp": ts,
                "cumulative_risk": entity_scores[f"host:{host}"],
                "event_type": etype,
                "delta": weight,
            })

        # Track per IP
        ip = e.get("ip")
        if ip:
            entity_scores[f"ip:{ip}"] += weight
            timelines[f"ip:{ip}"].append({
                "timestamp": ts,
                "cumulative_risk": entity_scores[f"ip:{ip}"],
                "event_type": etype,
                "delta": weight,
            })

    return dict(timelines)
