import re
from typing import Dict, Any
from .base import BaseParser
from datetime import datetime, timezone

class LinuxParser(BaseParser):
    def __init__(self):
        super().__init__()
        self.parser_name = "linux_parser"
        self.parser_version = "1.0"
        self.platform = "linux"

        # Standard syslog/auth.log line
        # e.g., Sep 11 10:42:13 server sshd[1234]: Failed password...
        self.syslog_pattern = re.compile(
            r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
            r"(?P<hostname>\S+)\s+"
            r"(?P<process>[a-zA-Z0-9_\-]+)(?:\[(?P<pid>\d+)\])?:\s+"
            r"(?P<message>.*)$"
        )

        # Audit log pattern
        # e.g., type=USER_LOGIN msg=audit(1630000000.123:456): ...
        self.audit_pattern = re.compile(
            r"^type=(?P<audit_type>[A-Z_]+)\s+msg=audit\((?P<timestamp>\d+\.\d+):\d+\):\s+(?P<message>.*)$"
        )

        # SSH Specific Patterns
        self.ssh_failed_pattern = re.compile(r"Failed (?:password|none|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
        self.ssh_accepted_pattern = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
        self.ssh_invalid_user_pattern = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")
        self.ssh_disconnect_pattern = re.compile(r"(?:Disconnected from|Connection closed by|Received disconnect from) (?:invalid user )?(?P<ip>\S+) port (?P<port>\d+)")
        
        # Sudo pattern
        self.sudo_pattern = re.compile(r"^\s*(?P<user>\S+) : TTY=(?P<tty>\S+) ; PWD=(?P<pwd>\S+) ; USER=(?P<runas>\S+) ; COMMAND=(?P<command>.*)$")

        # Session pattern
        self.session_open = re.compile(r"pam_unix\([^:]+:[^)]+\): session opened for user (?P<user>\S+)")
        self.session_close = re.compile(r"pam_unix\([^:]+:[^)]+\): session closed for user (?P<user>\S+)")

    def parse_line(self, line: str, line_num: int, filename: str) -> Dict[str, Any]:
        event = self.create_base_event(line, line_num, filename)
        
        # Try Syslog Format
        m_syslog = self.syslog_pattern.match(line)
        if m_syslog:
            return self._handle_syslog(m_syslog, event)
            
        # Try Audit Format
        m_audit = self.audit_pattern.match(line)
        if m_audit:
            return self._handle_audit(m_audit, event)
            
        # Unrecognized Linux line format, still return but log_type unknown
        event["timestamp_confidence"] = "low"
        event["message"] = line
        return event

    def _handle_syslog(self, match: re.Match, event: Dict[str, Any]) -> Dict[str, Any]:
        d = match.groupdict()
        event["timestamp"] = d["timestamp"]
        event["timestamp_raw"] = d["timestamp"]
        event["hostname"] = d["hostname"]
        event["process"] = d["process"]
        event["pid"] = d["pid"]
        event["message"] = d["message"]
        
        proc = (d["process"] or "").lower()
        msg = d["message"]

        # Classification based on process
        if "sshd" in proc:
            event["log_type"] = "authentication"
            event["category"] = "authentication"
            
            m_fail = self.ssh_failed_pattern.search(msg)
            if m_fail:
                event["type"] = "AUTH_FAIL"
                event["event_type"] = "ssh_login_failed"
                event["severity"] = "high"
                event["status"] = "failure"
                event.update(m_fail.groupdict())
                return event
                
            m_acc = self.ssh_accepted_pattern.search(msg)
            if m_acc:
                event["type"] = "AUTH_SUCCESS"
                event["event_type"] = "ssh_login_success"
                event["severity"] = "info"
                event["status"] = "success"
                event.update(m_acc.groupdict())
                return event
                
            m_inv = self.ssh_invalid_user_pattern.search(msg)
            if m_inv:
                event["type"] = "AUTH_FAIL"
                event["event_type"] = "ssh_invalid_user"
                event["severity"] = "medium"
                event.update(m_inv.groupdict())
                return event

            m_disc = self.ssh_disconnect_pattern.search(msg)
            if m_disc:
                event["type"] = "NETWORK_CONN"
                event["event_type"] = "ssh_disconnect"
                event["severity"] = "info"
                event.update(m_disc.groupdict())
                return event

        elif "sudo" in proc:
            event["log_type"] = "authentication"
            event["category"] = "privilege"
            
            m_sudo = self.sudo_pattern.search(msg)
            if m_sudo:
                event["type"] = "PRIV_ESCALATION"
                event["event_type"] = "sudo_usage"
                event["severity"] = "high"
                sd = m_sudo.groupdict()
                event["user"] = sd["user"]
                event["commandline"] = sd["command"]
                return event
                
        elif "kernel" in proc:
            event["log_type"] = "kernel"
            event["category"] = "system"
            event["type"] = "SYSTEM_EVENT"
            event["severity"] = "info"
            
        elif "crond" in proc or "cron" in proc:
            event["log_type"] = "syslog"
            event["category"] = "endpoint"
            event["type"] = "PROCESS_CREATE"
            
        else:
            event["log_type"] = "syslog"
            event["category"] = "system"

        # Check for sessions
        m_sess_o = self.session_open.search(msg)
        if m_sess_o:
            event["log_type"] = "authentication"
            event["type"] = "AUTH_SUCCESS"
            event["event_type"] = "session_opened"
            event["user"] = m_sess_o.group("user")
            
        m_sess_c = self.session_close.search(msg)
        if m_sess_c:
            event["log_type"] = "authentication"
            event["type"] = "AUTH_SUCCESS"
            event["event_type"] = "session_closed"
            event["user"] = m_sess_c.group("user")
            event["severity"] = "info"
            
        return event

    def _handle_audit(self, match: re.Match, event: Dict[str, Any]) -> Dict[str, Any]:
        d = match.groupdict()
        
        try:
            ts_float = float(d["timestamp"])
            event["timestamp"] = datetime.fromtimestamp(ts_float, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        except:
            event["timestamp"] = d["timestamp"]
            
        event["timestamp_raw"] = d["timestamp"]
        event["log_type"] = "audit"
        event["message"] = d["message"]
        
        audit_type = d["audit_type"]
        msg = d["message"]
        
        event["event_type"] = f"audit_{audit_type.lower()}"
        
        # Parse key-value pairs in audit msg
        kv_pairs = dict(re.findall(r'(\w+)=("[^"]*"|\S+)', msg))
        
        if "pid" in kv_pairs: event["pid"] = kv_pairs["pid"]
        if "uid" in kv_pairs: event["user"] = kv_pairs["uid"]
        if "exe" in kv_pairs: event["process"] = kv_pairs["exe"].strip('"')
        
        if audit_type in ["USER_LOGIN", "USER_AUTH"]:
            event["category"] = "authentication"
            if kv_pairs.get("res") == "success":
                event["type"] = "AUTH_SUCCESS"
                event["severity"] = "info"
            else:
                event["type"] = "AUTH_FAIL"
                event["severity"] = "medium"
        elif audit_type == "EXECVE":
            event["category"] = "endpoint"
            event["type"] = "PROCESS_CREATE"
            event["severity"] = "info"
        else:
            event["category"] = "system"
            event["type"] = "OTHER"
            
        return event
