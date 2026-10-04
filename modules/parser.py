import os
import time
from typing import List, Dict, Any, Tuple

from modules.parsers.detector import ParserDetector
from modules.parsers.legacy_parser import LegacyParser
from modules.parsers.linux_parser import LinuxParser
from modules.parsers.android_parser import AndroidParser

def get_parser_instance(parser_name: str):
    if parser_name == "linux_parser":
        return LinuxParser()
    elif parser_name == "android_parser":
        return AndroidParser()
    else:
        return LegacyParser()

def parse_logs(file_paths: List[str], manual_platform: str = None, manual_log_type: str = None) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Parse and normalize log files into structured events.
    Returns: (events, diagnostics)
    """
    events = []
    diagnostics = []
    detector = ParserDetector()

    for file_path in file_paths:
        filename = os.path.basename(file_path)
        
        # 1. Detect platform and parser
        detect_result = detector.detect(file_path)
        
        # Manual overrides
        platform = manual_platform if manual_platform and manual_platform != "auto" else detect_result["platform"]
        log_type = manual_log_type if manual_log_type and manual_log_type != "auto" else detect_result["log_type"]
        
        parser_name = detect_result["parser_name"]
        if manual_platform == "linux":
            parser_name = "linux_parser"
        elif manual_platform == "android":
            parser_name = "android_parser"
        elif manual_platform == "windows" or manual_platform == "generic":
            parser_name = "legacy_parser"

        parser = get_parser_instance(parser_name)
        parser.platform = platform
        
        diag = {
            "file": filename,
            "detected_platform": platform,
            "detected_log_type": log_type,
            "confidence": detect_result["confidence"],
            "lines_total": 0,
            "parsed_count": 0,
            "unknown_lines": 0,
            "events_count": 0,
            "parser_used": parser_name,
            "status": "SUCCESS",
            "error": None
        }

        try:
            with open(file_path, "r", errors="replace") as f:
                for line_num, line in enumerate(f, 1):
                    raw_line = line.strip()
                    if not raw_line:
                        continue
                        
                    diag["lines_total"] += 1
                    
                    try:
                        event = parser.parse_line(raw_line, line_num, filename)
                        
                        if event:
                            import hashlib
                            event["event_id"] = f"EVT-{hashlib.md5(f'{filename}:{line_num}:{raw_line}'.encode()).hexdigest()[:8].upper()}"
                            
                            # Override log type if manually specified
                            if manual_log_type and manual_log_type != "auto":
                                event["log_type"] = manual_log_type
                                
                            if event.get("type") == "OTHER" and event.get("severity") == "info" and event.get("timestamp_confidence") == "low":
                                diag["unknown_lines"] += 1
                                # We still append the event to not lose evidence
                            else:
                                diag["parsed_count"] += 1
                            
                            events.append(event)
                            diag["events_count"] += 1
                    except Exception as e:
                        diag["unknown_lines"] += 1
        except Exception as e:
            diag["status"] = "FAILED"
            diag["error"] = str(e)
            
        diagnostics.append(diag)

    return events, diagnostics
