def classify_incident(events, attacks):
    types = {e["type"] for e in events}

    if "Brute Force Login Attempt" in attacks:
        return "Authentication Attack (Brute Force)"

    if "AUTH_FAIL" in types and "AUTH_SUCCESS" in types:
        return "Credential Compromise"

    if "USB" in types and "FILE_COPY" in types:
        return "Insider Data Theft"

    if "NETWORK" in types and "FILE_COPY" in types:
        return "Data Exfiltration"

    if "NETWORK" in types:
        return "Suspicious Network Activity"

    if "USB" in types:
        return "Policy Violation (Unauthorized USB Usage)"

    if types - {"OTHER"}:
        return "Suspicious Activity"

    return "No Incident Detected"
