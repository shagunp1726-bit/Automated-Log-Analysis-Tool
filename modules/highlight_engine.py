


# ──────────────────────────────────────────────
# Keyword categories with severity and tooltips
# ──────────────────────────────────────────────
HIGHLIGHT_RULES = {
    # Authentication keywords
    "auth": {
        "severity": "medium", "color": "#3b82f6",
        "tooltip": "Authentication-related event – monitor for anomalies"
    },
    "login": {
        "severity": "medium", "color": "#3b82f6",
        "tooltip": "Login event – check for unauthorized access"
    },
    "failed": {
        "severity": "high", "color": "#f59e0b",
        "tooltip": "Failed operation – may indicate attack attempts"
    },
    "denied": {
        "severity": "high", "color": "#f59e0b",
        "tooltip": "Access denied – potential unauthorized access attempt"
    },
    "unauthorized": {
        "severity": "high", "color": "#ef4444",
        "tooltip": "Unauthorized activity detected – investigate immediately"
    },
    "privilege escalation": {
        "severity": "critical", "color": "#ef4444",
        "tooltip": "Privilege escalation – critical security event"
    },
    "sudo": {
        "severity": "high", "color": "#f59e0b",
        "tooltip": "Superuser command execution – verify authorization"
    },
    "admin": {
        "severity": "medium", "color": "#3b82f6",
        "tooltip": "Administrator activity – privileged account usage"
    },
    "root": {
        "severity": "high", "color": "#f59e0b",
        "tooltip": "Root access – highest privilege level"
    },
    "brute force": {
        "severity": "critical", "color": "#ef4444",
        "tooltip": "Brute force attack – systematic credential guessing"
    },
    "mfa": {
        "severity": "medium", "color": "#3b82f6",
        "tooltip": "Multi-factor authentication event"
    },

    # Malware / Execution indicators
    "powershell": {
        "severity": "high", "color": "#f59e0b",
        "tooltip": "PowerShell execution – commonly used in attacks (T1059.001)"
    },
    "encoded": {
        "severity": "critical", "color": "#ef4444",
        "tooltip": "Encoded content – potential obfuscation technique (T1027)"
    },
    "injection": {
        "severity": "critical", "color": "#ef4444",
        "tooltip": "Injection attack indicator – code/SQL/command injection"
    },
    "persistence": {
        "severity": "high", "color": "#f59e0b",
        "tooltip": "Persistence mechanism – adversary maintaining access (TA0003)"
    },
    "exploit": {
        "severity": "critical", "color": "#ef4444",
        "tooltip": "Exploit activity – vulnerability exploitation attempt"
    },
    "ransomware": {
        "severity": "critical", "color": "#ef4444",
        "tooltip": "Ransomware indicator – data encryption for impact (T1486)"
    },
    "mimikatz": {
        "severity": "critical", "color": "#ef4444",
        "tooltip": "Mimikatz – credential dumping tool (T1003)"
    },
    "certutil": {
        "severity": "high", "color": "#f59e0b",
        "tooltip": "Certutil abuse – LOLBin for file download (T1105)"
    },
    "rundll32": {
        "severity": "high", "color": "#f59e0b",
        "tooltip": "Rundll32 execution – potential defense evasion"
    },
    "regsvr32": {
        "severity": "high", "color": "#f59e0b",
        "tooltip": "Regsvr32 execution – potential AppLocker bypass"
    },
    "mshta": {
        "severity": "high", "color": "#f59e0b",
        "tooltip": "MSHTA execution – HTML application proxy execution"
    },
    "wscript": {
        "severity": "high", "color": "#f59e0b",
        "tooltip": "WScript execution – script host potentially abused"
    },
    "cmd.exe": {
        "severity": "medium", "color": "#3b82f6",
        "tooltip": "Command prompt execution – monitor command content"
    },

    # Network indicators
    "beacon": {
        "severity": "critical", "color": "#ef4444",
        "tooltip": "C2 beacon – command and control communication (T1071)"
    },
    "c2": {
        "severity": "critical", "color": "#ef4444",
        "tooltip": "Command and Control activity – active adversary communication"
    },
    "exfiltration": {
        "severity": "critical", "color": "#ef4444",
        "tooltip": "Data exfiltration – sensitive data being removed (TA0010)"
    },
    "suspicious": {
        "severity": "high", "color": "#f59e0b",
        "tooltip": "Suspicious activity flagged – requires analyst review"
    },
    "lateral movement": {
        "severity": "critical", "color": "#ef4444",
        "tooltip": "Lateral movement – adversary spreading through network (TA0008)"
    },
    "outbound": {
        "severity": "medium", "color": "#3b82f6",
        "tooltip": "Outbound connection – verify destination is legitimate"
    },
    "dns": {
        "severity": "low", "color": "#22c55e",
        "tooltip": "DNS activity – check for tunneling or suspicious domains"
    },
    "firewall": {
        "severity": "medium", "color": "#3b82f6",
        "tooltip": "Firewall event – access control enforcement"
    },

    # File indicators
    "file copied": {
        "severity": "high", "color": "#f59e0b",
        "tooltip": "File copy operation – potential data staging (T1005)"
    },
    "file deleted": {
        "severity": "high", "color": "#f59e0b",
        "tooltip": "File deletion – possible evidence removal (T1070)"
    },
    "usb": {
        "severity": "high", "color": "#f59e0b",
        "tooltip": "USB device activity – removable media risk"
    },
    "registry": {
        "severity": "medium", "color": "#3b82f6",
        "tooltip": "Registry modification – potential persistence or config change"
    },
}


def get_highlight_rules():
    """Return the keyword highlighting rules for the frontend."""
    return HIGHLIGHT_RULES


def get_highlight_rules_json():
    """Return rules formatted for JavaScript consumption."""
    rules = []
    for keyword, config in HIGHLIGHT_RULES.items():
        rules.append({
            "keyword": keyword,
            "severity": config["severity"],
            "color": config["color"],
            "tooltip": config["tooltip"],
        })
    # Sort by keyword length descending (match longer phrases first)
    rules.sort(key=lambda r: len(r["keyword"]), reverse=True)
    return rules
