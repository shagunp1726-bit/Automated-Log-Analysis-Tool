

def detect_attacks(events):
    """Detect attack patterns from parsed events."""
    attacks = []

    auth_fail_count = sum(1 for e in events if e.get("type") == "AUTH_FAIL")
    auth_success_count = sum(1 for e in events if e.get("type") == "AUTH_SUCCESS")
    priv_esc_count = sum(1 for e in events if e.get("type") == "PRIV_ESCALATION")

    if auth_fail_count >= 5:
        attacks.append("Brute Force Login Attempt")

    if auth_fail_count >= 3 and auth_success_count >= 1:
        attacks.append("Credential Compromise Detected")

    if priv_esc_count >= 1:
        attacks.append("Privilege Escalation Activity")

    for e in events:
        etype = e.get("type", "")
        if etype == "USB":
            attacks.append("Unauthorized USB Usage")
            break

    for e in events:
        if e.get("type") == "FILE_COPY":
            attacks.append("Suspicious File Copy Activity")
            break

    for e in events:
        if e.get("type") in ("NETWORK_CONN", "MALWARE_INDICATOR"):
            attacks.append("Suspicious Network Communication")
            break

    for e in events:
        if e.get("type") == "EXECUTION_SUSPICIOUS":
            attacks.append("Suspicious Command Execution")
            break

    for e in events:
        if e.get("type") == "WEB_ATTACK":
            attacks.append("Web Application Attack")
            break

    for e in events:
        if e.get("type") == "FILE_DELETE":
            attacks.append("Evidence Tampering / File Deletion")
            break

    return list(set(attacks))
