import re
from typing import Dict, Any
from .base import BaseParser

class AndroidParser(BaseParser):
    def __init__(self):
        super().__init__()
        self.parser_name = "android_logcat"
        self.parser_version = "1.0"
        self.platform = "android"

        # Threadtime format: MM-DD HH:MM:SS.mmm PID TID LEVEL TAG: MESSAGE
        # Example: 09-11 10:42:13.123  1234  5678 I ActivityManager: Start proc 1234:com.example.app/u0a123
        self.threadtime_pattern = re.compile(
            r"^(?P<timestamp>\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+"
            r"(?P<pid>\d+)\s+"
            r"(?P<tid>\d+)\s+"
            r"(?P<level>[VDIWEF])\s+"
            r"(?P<tag>.*?):\s+"
            r"(?P<message>.*)$"
        )

        # Brief format: LEVEL/TAG(PID): MESSAGE
        # Example: I/ActivityManager( 1234): Start proc ...
        self.brief_pattern = re.compile(
            r"^(?P<level>[VDIWEF])/(?P<tag>[^\(]+)\(\s*(?P<pid>\d+)\):\s+(?P<message>.*)$"
        )

        # Application/Package events
        self.app_start_pattern = re.compile(r"Start proc\s+\d+:(?P<package>[a-zA-Z0-9_\.]+)")
        self.pkg_install_pattern = re.compile(r"installPackageLI.*(?P<package>[a-zA-Z0-9_\.]+)")
        self.pkg_remove_pattern = re.compile(r"deletePackageX.*(?P<package>[a-zA-Z0-9_\.]+)")
        
    def parse_line(self, line: str, line_num: int, filename: str) -> Dict[str, Any]:
        event = self.create_base_event(line, line_num, filename)
        
        m_thread = self.threadtime_pattern.match(line)
        if m_thread:
            return self._handle_logcat(m_thread.groupdict(), event)
            
        m_brief = self.brief_pattern.match(line)
        if m_brief:
            return self._handle_logcat(m_brief.groupdict(), event)
            
        event["timestamp_confidence"] = "low"
        event["message"] = line
        return event

    def _handle_logcat(self, d: Dict[str, str], event: Dict[str, Any]) -> Dict[str, Any]:
        event["log_type"] = "logcat"
        
        # Timestamp (if available)
        ts = d.get("timestamp")
        if ts:
            event["timestamp_raw"] = ts
            event["timestamp"] = ts  # Ideally prepend current year if known, but keep raw for now
            event["timestamp_confidence"] = "low" # Missing year
            
        if "pid" in d: event["pid"] = d["pid"]
        if "tid" in d: event["tid"] = d["tid"]
        
        level = d.get("level", "I")
        event["log_level"] = level
        
        tag = d.get("tag", "").strip()
        event["tag"] = tag
        
        msg = d.get("message", "")
        event["message"] = msg
        
        # Map Android Log Levels to Severity
        level_map = {
            "V": "info",
            "D": "info",
            "I": "low",
            "W": "medium",
            "E": "high",
            "F": "critical"
        }
        event["severity"] = level_map.get(level, "info")
        event["category"] = "system"
        event["type"] = "SYSTEM_EVENT"
        event["event_type"] = "application_activity"

        # Inspect specific tags
        if tag == "ActivityManager":
            event["category"] = "endpoint"
            m_start = self.app_start_pattern.search(msg)
            if m_start:
                event["type"] = "PROCESS_CREATE"
                event["event_type"] = "application_launch"
                event["package_name"] = m_start.group("package")
                event["application"] = m_start.group("package")
        elif tag == "PackageManager":
            event["category"] = "endpoint"
            m_inst = self.pkg_install_pattern.search(msg)
            if m_inst:
                event["type"] = "FILE_CREATE"
                event["event_type"] = "package_installed"
                event["package_name"] = m_inst.group("package")
            m_rem = self.pkg_remove_pattern.search(msg)
            if m_rem:
                event["type"] = "FILE_DELETE"
                event["event_type"] = "package_removed"
                event["package_name"] = m_rem.group("package")
        elif tag in ["vold", "installd", "keystore"]:
            event["category"] = "system"
        elif tag == "SELinux":
            event["category"] = "privilege"
            if "denied" in msg.lower():
                event["type"] = "AUTH_FAIL"
                event["event_type"] = "selinux_denial"
                event["severity"] = "high"

        return event
