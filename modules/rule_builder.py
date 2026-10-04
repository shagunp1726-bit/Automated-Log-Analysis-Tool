"""
ForensicLens – Sigma-like Detection Rule Builder
Create, evaluate, and manage behavioral detection rules
using the existing query DSL engine.
"""

import re
import uuid
from datetime import datetime
from collections import Counter


# ──────────────────────────────────────────────
# Default detection rules (pre-built library)
# ──────────────────────────────────────────────
DEFAULT_RULES = [
    {
        "id": "RULE-001",
        "title": "Brute Force Attack (5+ Failed Logins)",
        "description": "Detects brute force attacks with 5 or more failed login attempts for a single user.",
        "severity": "high",
        "condition": "type:AUTH_FAIL",
        "threshold": {"field": "user", "min_count": 5},
        "mitre": ["T1110"],
        "tags": ["authentication", "brute-force"],
        "enabled": True,
    },
    {
        "id": "RULE-002",
        "title": "Credential Compromise (Failed → Success)",
        "description": "Detects a successful login following multiple failed attempts, indicating credential compromise.",
        "severity": "critical",
        "condition": "type:AUTH_FAIL OR type:AUTH_SUCCESS",
        "threshold": None,
        "custom_logic": "brute_force_success",
        "mitre": ["T1110", "T1078"],
        "tags": ["authentication", "credential-compromise"],
        "enabled": True,
    },
    {
        "id": "RULE-003",
        "title": "Encoded PowerShell Execution",
        "description": "Detects execution of PowerShell with encoded commands, a common attacker technique.",
        "severity": "critical",
        "condition": "process:powershell* AND commandline:*encoded*",
        "threshold": None,
        "mitre": ["T1059.001", "T1027"],
        "tags": ["execution", "powershell", "obfuscation"],
        "enabled": True,
    },
    {
        "id": "RULE-004",
        "title": "LOLBin Execution",
        "description": "Detects Living-off-the-Land binary executions commonly used in attacks.",
        "severity": "high",
        "condition": "process:certutil* OR process:mshta* OR process:regsvr32* OR process:rundll32*",
        "threshold": None,
        "mitre": ["T1105", "T1218"],
        "tags": ["execution", "lolbin", "defense-evasion"],
        "enabled": True,
    },
    {
        "id": "RULE-005",
        "title": "Privilege Escalation Detected",
        "description": "Detects privilege escalation events including sudo, runas, and UAC bypass.",
        "severity": "critical",
        "condition": "type:PRIV_ESCALATION",
        "threshold": None,
        "mitre": ["T1548"],
        "tags": ["privilege-escalation"],
        "enabled": True,
    },
    {
        "id": "RULE-006",
        "title": "Mass File Deletion (Anti-Forensics)",
        "description": "Detects mass file deletion events indicating possible evidence destruction.",
        "severity": "critical",
        "condition": "type:FILE_DELETE",
        "threshold": {"field": "type", "min_count": 3},
        "mitre": ["T1070"],
        "tags": ["defense-evasion", "anti-forensics"],
        "enabled": True,
    },
    {
        "id": "RULE-007",
        "title": "Data Staging via File Copy",
        "description": "Detects file copy operations that may indicate data staging for exfiltration.",
        "severity": "high",
        "condition": "type:FILE_COPY",
        "threshold": None,
        "mitre": ["T1005"],
        "tags": ["collection", "data-staging"],
        "enabled": True,
    },
    {
        "id": "RULE-008",
        "title": "USB Device Activity",
        "description": "Detects USB device connections, potential data exfiltration via removable media.",
        "severity": "high",
        "condition": "type:USB",
        "threshold": None,
        "mitre": ["T1092"],
        "tags": ["exfiltration", "removable-media"],
        "enabled": True,
    },
    {
        "id": "RULE-009",
        "title": "Credential Dumping Tool Detected",
        "description": "Detects known credential dumping tools like Mimikatz, procdump.",
        "severity": "critical",
        "condition": "process:mimikatz* OR process:procdump*",
        "threshold": None,
        "mitre": ["T1003"],
        "tags": ["credential-access", "credential-dumping"],
        "enabled": True,
    },
    {
        "id": "RULE-010",
        "title": "Web Application Attack",
        "description": "Detects SQL injection, XSS, and directory traversal attempts.",
        "severity": "critical",
        "condition": "type:WEB_ATTACK",
        "threshold": None,
        "mitre": ["T1190"],
        "tags": ["web", "exploitation"],
        "enabled": True,
    },
    {
        "id": "RULE-011",
        "title": "Outbound C2 Beacon Pattern",
        "description": "Detects repetitive outbound connections that may indicate C2 beaconing.",
        "severity": "high",
        "condition": "type:NETWORK_CONN",
        "threshold": {"field": "dest_ip", "min_count": 5},
        "mitre": ["T1071"],
        "tags": ["c2", "network"],
        "enabled": True,
    },
    {
        "id": "RULE-012",
        "title": "New Account Creation",
        "description": "Detects creation of new accounts that may be used for persistence.",
        "severity": "high",
        "condition": "type:ACCOUNT_CHANGE",
        "threshold": None,
        "mitre": ["T1136"],
        "tags": ["persistence", "account"],
        "enabled": True,
    },
]


class RuleEngine:
    """
    Sigma-like detection rule engine.
    Supports creating, evaluating, and managing detection rules.
    """

    def __init__(self):
        self.rules = {}

    def add_rule(self, rule):
        """Add or update a detection rule."""
        rule_id = rule.get("id") or f"RULE-{str(uuid.uuid4())[:8].upper()}"
        rule["id"] = rule_id
        rule.setdefault("created_at", datetime.utcnow().isoformat())
        rule.setdefault("enabled", True)
        rule.setdefault("tags", [])
        rule.setdefault("mitre", [])
        rule.setdefault("threshold", None)
        self.rules[rule_id] = rule
        return rule

    def remove_rule(self, rule_id):
        """Remove a detection rule."""
        return self.rules.pop(rule_id, None)

    def get_rules(self):
        """Get all rules."""
        return list(self.rules.values())

    def evaluate_all(self, events):
        """
        Evaluate all enabled rules against events.
        Returns list of triggered rules with matching events.
        """
        results = []
        for rule in self.rules.values():
            if not rule.get("enabled", True):
                continue
            result = self.evaluate_rule(rule, events)
            if result["triggered"]:
                results.append(result)
        results.sort(key=lambda r: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(r.get("severity", "info"), 0), reverse=True)
        return results

    def evaluate_rule(self, rule, events):
        """
        Evaluate a single rule against events.
        Returns match result with evidence.
        """
        condition = rule.get("condition", "")
        threshold = rule.get("threshold")
        custom = rule.get("custom_logic")

        # Custom logic handlers
        if custom == "brute_force_success":
            return self._eval_brute_force_success(rule, events)

        # Standard query-based evaluation
        matched_events = self._match_condition(events, condition)

        # Apply threshold if present
        triggered = len(matched_events) > 0
        if threshold and triggered:
            field = threshold.get("field", "type")
            min_count = threshold.get("min_count", 1)
            counts = Counter(str(e.get(field, "")) for e in matched_events)
            triggered = any(c >= min_count for c in counts.values())

        return {
            "rule_id": rule["id"],
            "title": rule["title"],
            "description": rule["description"],
            "severity": rule["severity"],
            "mitre": rule.get("mitre", []),
            "tags": rule.get("tags", []),
            "triggered": triggered,
            "match_count": len(matched_events),
            "sample_events": [e.get("raw", "")[:200] for e in matched_events[:5]],
            "condition": condition,
        }

    def _match_condition(self, events, condition):
        """Match events against a query condition string."""
        if not condition:
            return []

        matched = []
        for event in events:
            if self._event_matches_condition(event, condition):
                matched.append(event)
        return matched

    def _event_matches_condition(self, event, condition):
        """Evaluate condition string against single event."""
        condition = condition.strip()

        # Handle OR
        if " OR " in condition:
            parts = condition.split(" OR ")
            return any(self._event_matches_condition(event, p.strip()) for p in parts)

        # Handle AND
        if " AND " in condition:
            parts = condition.split(" AND ")
            return all(self._event_matches_condition(event, p.strip()) for p in parts)

        # Handle NOT
        if condition.startswith("NOT "):
            return not self._event_matches_condition(event, condition[4:])

        # Handle field:value
        m = re.match(r'^(\w+):(.+)$', condition)
        if m:
            field = m.group(1)
            pattern = m.group(2).strip('"').strip("'")

            # Field aliases
            if field == "event_type":
                field = "type"
            if field == "source_ip":
                field = "ip"

            value = str(event.get(field, "") or "")
            if not value:
                return False

            # Wildcard matching
            if "*" in pattern:
                import fnmatch
                return fnmatch.fnmatch(value.lower(), pattern.lower())

            return value.lower() == pattern.lower()

        # Full text search fallback
        return condition.lower() in (event.get("raw") or "").lower()

    def _eval_brute_force_success(self, rule, events):
        """Custom logic: detect brute force followed by success."""
        from collections import defaultdict
        user_fails = defaultdict(int)
        user_success = defaultdict(int)

        for e in events:
            user = e.get("user", "")
            if e.get("type") == "AUTH_FAIL":
                user_fails[user] += 1
            elif e.get("type") == "AUTH_SUCCESS":
                user_success[user] += 1

        triggered_users = [u for u in user_fails if user_fails[u] >= 3 and user_success.get(u, 0) > 0]

        return {
            "rule_id": rule["id"],
            "title": rule["title"],
            "description": rule["description"],
            "severity": rule["severity"],
            "mitre": rule.get("mitre", []),
            "tags": rule.get("tags", []),
            "triggered": len(triggered_users) > 0,
            "match_count": sum(user_fails[u] + user_success[u] for u in triggered_users),
            "sample_events": [f"User {u}: {user_fails[u]} fails → {user_success[u]} success" for u in triggered_users],
            "condition": rule.get("condition", ""),
        }
