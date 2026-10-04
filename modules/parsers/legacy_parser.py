import re
import json
from typing import Dict, Any
from .base import BaseParser

# ──────────────────────────────────────────────
# Timestamp patterns
# ──────────────────────────────────────────────
TIMESTAMP_PATTERNS = [
    # ISO 8601
    re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"),
    # Standard datetime
    re.compile(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}(?::\d{2})?)"),
    # Syslog style (e.g. Feb 25 14:30:01)
    re.compile(r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"),
    # Windows Event Log style
    re.compile(r"(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})"),
    # Epoch
    re.compile(r"\b(\d{10}(?:\.\d+)?)\b"),
]

# ──────────────────────────────────────────────
# Entity extraction patterns
# ──────────────────────────────────────────────
ENTITY_PATTERNS = {
    "user": [
        re.compile(r"(?:user|username|account|uid|login)[=:\s]+['\"]?([a-zA-Z0-9_.\-\\]+)", re.I),
        re.compile(r"for\s+(?:user\s+)?([a-zA-Z0-9_.\-]+)\s+from", re.I),
        re.compile(r"session\s+(?:opened|closed)\s+for\s+(?:user\s+)?([a-zA-Z0-9_.\-]+)", re.I),
    ],
    "ip": [
        re.compile(r"(?:source[_\s]?ip|src[_\s]?ip|ip|from|addr|address|remote)[=:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", re.I),
        re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
    ],
    "dest_ip": [
        re.compile(r"(?:dest[_\s]?ip|dst[_\s]?ip|destination|to)[=:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", re.I),
    ],
    "process": [
        re.compile(r"(?:process|image|exe|program|command)[=:\s]+['\"]?([a-zA-Z0-9_.\-/\\]+\.(?:exe|bin|sh|py|ps1|bat|cmd))", re.I),
        re.compile(r"(?:process|image|exe)[=:\s]+['\"]?([a-zA-Z0-9_.\-/\\]+)", re.I),
    ],
    "pid": [
        re.compile(r"(?:pid|processid|process_id)[=:\s]+(\d+)", re.I),
    ],
    "ppid": [
        re.compile(r"(?:ppid|parentprocessid|parent_pid)[=:\s]+(\d+)", re.I),
    ],
    "parent_process": [
        re.compile(r"(?:parent[_\s]?(?:image|process|command))[=:\s]+['\"]?([a-zA-Z0-9_.\-/\\]+)", re.I),
    ],
    "commandline": [
        re.compile(r"(?:commandline|command_line|cmdline|cmd)[=:\s]+['\"]?(.+?)(?:['\"]?\s*$|['\"]?\s+\w+=)", re.I),
    ],
    "hash_md5": [
        re.compile(r"(?:md5|hash_md5)[=:\s]+([a-fA-F0-9]{32})", re.I),
        re.compile(r"\b([a-fA-F0-9]{32})\b"),
    ],
    "hash_sha256": [
        re.compile(r"(?:sha256|hash_sha256)[=:\s]+([a-fA-F0-9]{64})", re.I),
        re.compile(r"\b([a-fA-F0-9]{64})\b"),
    ],
    "hostname": [
        re.compile(r"(?:hostname|host|computer|machine|workstation)[=:\s]+['\"]?([a-zA-Z0-9_.\-]+)", re.I),
    ],
    "domain": [
        re.compile(r"(?:domain|realm)[=:\s]+['\"]?([a-zA-Z0-9_.\-]+\.[a-zA-Z]{2,})", re.I),
    ],
    "port": [
        re.compile(r"(?:port|dst_port|dest_port|src_port|source_port)[=:\s]+(\d{1,5})", re.I),
    ],
    "protocol": [
        re.compile(r"(?:protocol|proto)[=:\s]+([a-zA-Z]+)", re.I),
    ],
    "url": [
        re.compile(r"(https?://[^\s\"']+)", re.I),
    ],
}

# ──────────────────────────────────────────────
# Event type classification rules
# ──────────────────────────────────────────────
EVENT_RULES = [
    # Auth events
    {"type": "AUTH_FAIL", "severity": "high", "category": "authentication",
     "keywords": ["failed login", "failed password", "authentication failure", "login failed",
                  "invalid user", "access denied", "logon failure", "event_id=4625",
                  "failed-logon", "invalid credentials"]},
    {"type": "AUTH_SUCCESS", "severity": "info", "category": "authentication",
     "keywords": ["login successful", "logged in successfully", "session opened",
                  "accepted password", "event_id=4624", "successful-logon",
                  "authenticated successfully"]},
    {"type": "PRIV_ESCALATION", "severity": "critical", "category": "privilege",
     "keywords": ["privilege escalation", "sudo", "su ", "runas", "event_id=4672",
                  "special privileges assigned", "elevated", "root access",
                  "admin privilege", "setuid"]},
    {"type": "ACCOUNT_CHANGE", "severity": "high", "category": "authentication",
     "keywords": ["password changed", "account created", "account deleted",
                  "user added", "group membership changed", "event_id=4720",
                  "event_id=4726", "account modified"]},

    # Process events
    {"type": "PROCESS_CREATE", "severity": "info", "category": "endpoint",
     "keywords": ["process created", "event_id=1", "new process", "process start",
                  "execve", "createprocess"]},
    {"type": "PROCESS_TERMINATE", "severity": "info", "category": "endpoint",
     "keywords": ["process terminated", "event_id=5", "process exit", "process end"]},

    # Network events
    {"type": "NETWORK_CONN", "severity": "medium", "category": "network",
     "keywords": ["external ip", "outbound connection", "connection to",
                  "event_id=3", "network connection", "tcp connect",
                  "established connection", "dns query"]},
    {"type": "DNS_QUERY", "severity": "low", "category": "network",
     "keywords": ["dns query", "dns request", "name resolution", "event_id=22",
                  "nslookup", "dig "]},
    {"type": "FIREWALL", "severity": "medium", "category": "network",
     "keywords": ["firewall", "blocked connection", "dropped packet",
                  "deny ", "rule match", "iptables", "netfilter"]},

    # File events
    {"type": "FILE_CREATE", "severity": "low", "category": "file",
     "keywords": ["file created", "event_id=11", "file write"]},
    {"type": "FILE_MODIFY", "severity": "medium", "category": "file",
     "keywords": ["file modified", "file changed", "event_id=2"]},
    {"type": "FILE_DELETE", "severity": "high", "category": "file",
     "keywords": ["file deleted", "event_id=23", "file removed", "unlink"]},
    {"type": "FILE_COPY", "severity": "high", "category": "file",
     "keywords": ["file copied", "file copied from", "copy operation"]},

    # USB / Removable media
    {"type": "USB", "severity": "high", "category": "endpoint",
     "keywords": ["usb insert", "usb inserted", "usb mount", "removable media",
                  "mass storage", "usb device"]},

    # Registry (Windows)
    {"type": "REGISTRY", "severity": "medium", "category": "endpoint",
     "keywords": ["registry", "reg add", "reg delete", "event_id=12",
                  "event_id=13", "registry value set"]},

    # Malware / Suspicious indicators
    {"type": "MALWARE_INDICATOR", "severity": "critical", "category": "threat",
     "keywords": ["malware", "trojan", "ransomware", "crypto", "miner",
                  "backdoor", "rootkit", "keylogger", "rat ", "c2 beacon",
                  "command and control"]},
    {"type": "EXECUTION_SUSPICIOUS", "severity": "critical", "category": "threat",
     "keywords": ["powershell -enc", "powershell -e ", "encoded command",
                  "invoke-expression", "downloadstring", "certutil -urlcache",
                  "bitsadmin /transfer", "mshta ", "regsvr32 ",
                  "rundll32 ", "wscript ", "cscript "]},

    # Cloud
    {"type": "CLOUD_API", "severity": "medium", "category": "cloud",
     "keywords": ["api call", "sts:assumerole", "iam:", "s3:getobject",
                  "cloudtrail", "azure activity", "gcp audit"]},

    # Web
    {"type": "WEB_REQUEST", "severity": "low", "category": "web",
     "keywords": ["get /", "post /", "put /", "delete /", "http/1",
                  "http/2", "status=200", "status=404", "status=500"]},
    {"type": "WEB_ATTACK", "severity": "critical", "category": "web",
     "keywords": ["sql injection", "xss", "directory traversal", "../",
                  "union select", "<script>", "cmd=", "exec("]},
]

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

class LegacyParser(BaseParser):
    def __init__(self):
        super().__init__()
        self.parser_name = "legacy_parser"
        self.parser_version = "1.0"
        self.platform = "windows"  # Default assumption for legacy
        
    def _extract_timestamp(self, line: str) -> str:
        for pattern in TIMESTAMP_PATTERNS:
            m = pattern.search(line)
            if m:
                return m.group(1)
        return "UNKNOWN_TIME"

    def _classify_event(self, message: str):
        msg_lower = message.lower()
        best_match = None
        best_severity = -1

        for rule in EVENT_RULES:
            for kw in rule["keywords"]:
                if kw in msg_lower:
                    sev = SEVERITY_ORDER.get(rule["severity"], 0)
                    if sev > best_severity:
                        best_severity = sev
                        best_match = rule
                    break

        if best_match:
            return best_match["type"], best_match["severity"], best_match["category"]

        return "OTHER", "info", "other"

    def _extract_entities(self, line: str) -> Dict[str, str]:
        entities = {}
        for entity_name, patterns in ENTITY_PATTERNS.items():
            for pattern in patterns:
                m = pattern.search(line)
                if m:
                    entities[entity_name] = m.group(1)
                    break
        return entities

    def _detect_source_type(self, filename: str, line: str) -> str:
        fn = filename.lower()
        ln = line.lower()

        if "sysmon" in fn or "event_id=" in ln:
            return "sysmon"
        if "auth" in fn or "secure" in fn or any(x in ln for x in ["pam_unix", "sshd", "login"]):
            return "auth"
        if "firewall" in fn or "iptables" in fn:
            return "firewall"
        if "dns" in fn:
            return "dns"
        if "access" in fn and ("get /" in ln or "post /" in ln):
            return "web"
        if "cloud" in fn or "audit" in fn:
            return "cloud"
        if "edr" in fn or "endpoint" in fn:
            return "edr"
        if "network" in fn or "conn" in fn:
            return "network"
        return "generic"

    def _try_parse_json(self, line: str):
        try:
            data = json.loads(line)
            if isinstance(data, dict):
                flat = {}
                for k, v in data.items():
                    if isinstance(v, dict):
                        for k2, v2 in v.items():
                            flat[f"{k}.{k2}"] = str(v2)
                    else:
                        flat[k] = str(v)
                return flat
        except (json.JSONDecodeError, ValueError):
            pass
        return None

    def parse_line(self, line: str, line_num: int, filename: str) -> Dict[str, Any]:
        event = self.create_base_event(line, line_num, filename)
        
        json_data = self._try_parse_json(line)
        timestamp = self._extract_timestamp(line)
        event_type, severity, category = self._classify_event(line)
        entities = self._extract_entities(line)
        source_type = self._detect_source_type(filename, line)
        
        event.update({
            "timestamp": timestamp,
            "type": event_type,
            "severity": severity,
            "category": category,
            "source_type": source_type,
            "log_type": source_type,
            "json_data": json_data,
            "entities": entities,
        })
        
        # Merge entities
        for k, v in entities.items():
            if v: event[k] = v
            
        # JSON fallback
        if json_data:
            for k in ["user", "ip", "process", "hostname", "pid"]:
                if k in json_data and not event.get(k):
                    event[k] = json_data[k]
                    
        return event
