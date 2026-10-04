import re
from typing import Dict, Any, List

class BaseParser:
    """Base class for all ForensicLens parsers."""
    
    def __init__(self):
        self.parser_name = "base_parser"
        self.parser_version = "1.0"
        self.platform = "unknown"
        
    def parse_line(self, line: str, line_num: int, filename: str) -> Dict[str, Any]:
        """
        Parse a single line. Must return an event dict or None if unknown.
        """
        raise NotImplementedError()
        
    def create_base_event(self, raw_line: str, line_num: int, filename: str) -> Dict[str, Any]:
        """Create a standardized event dictionary with default fields."""
        return {
            "timestamp": "UNKNOWN_TIME",
            "timestamp_raw": None,
            "timestamp_confidence": "high",
            
            "type": "OTHER",
            "severity": "info",
            "category": "other",
            
            "raw": raw_line,
            "line_num": line_num,
            "source_file": filename,
            "source_type": "generic",
            
            "platform": self.platform,
            "log_type": "unknown",
            
            "parser": self.parser_name,
            "parser_version": self.parser_version,
            
            # Entities
            "user": None,
            "ip": None,
            "dest_ip": None,
            "process": None,
            "pid": None,
            "ppid": None,
            "parent_process": None,
            "commandline": None,
            "hash_md5": None,
            "hash_sha256": None,
            "hostname": None,
            "domain": None,
            "port": None,
            "protocol": None,
            "url": None,
            
            # Android Specific / Extended
            "tid": None,
            "log_level": None,
            "tag": None,
            "application": None,
            "package_name": None,
            
            "action": None,
            "status": None,
            "message": None,
            
            "entities": {},
            "json_data": None,
            
            "mitre_tactics": [],
            "mitre_techniques": [],
        }
