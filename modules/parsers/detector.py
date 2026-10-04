import re
from typing import Dict, Any

class ParserDetector:
    def __init__(self):
        # Heuristics
        self.linux_keywords = [
            r"sshd\[\d+\]:", r"sudo:", r"type=USER_LOGIN", r"msg=audit\(",
            r"pam_unix\(", r"CRON\[", r"kernel: \[", r"Accepted password",
            r"Failed password"
        ]
        
        self.android_keywords = [
            r"ActivityManager", r"PackageManager", r"installd", 
            r"vold", r"system_server", r"AndroidRuntime"
        ]
        
        self.android_threadtime = re.compile(r"^\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\d+\s+\d+\s+[VDIWEF]\s+")
        self.android_brief = re.compile(r"^[VDIWEF]/[^\(]+\(\s*\d+\):")

    def detect(self, file_path: str, max_lines=500) -> Dict[str, Any]:
        """
        Samples the file and returns a detected platform and parser name.
        """
        counts = {
            "linux": 0,
            "android": 0,
            "legacy": 0
        }
        
        total_lines = 0
        try:
            with open(file_path, 'r', errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    total_lines += 1
                    if total_lines > max_lines:
                        break
                        
                    # Check Android
                    if self.android_threadtime.match(line) or self.android_brief.match(line):
                        counts["android"] += 5
                    elif any(re.search(kw, line) for kw in self.android_keywords):
                        counts["android"] += 1
                        
                    # Check Linux
                    elif any(re.search(kw, line) for kw in self.linux_keywords):
                        counts["linux"] += 2
                        
                    # Check JSON (likely legacy/generic)
                    elif line.startswith("{") and line.endswith("}"):
                        counts["legacy"] += 1
                        
        except Exception as e:
            pass
            
        if total_lines == 0:
            return {"platform": "unknown", "log_type": "unknown", "parser_name": "legacy_parser", "confidence": 0}
            
        # Decide winner
        winner = max(counts, key=counts.get)
        max_score = counts[winner]
        
        # Calculate a pseudo confidence based on score / total lines
        # if max_score is high enough relative to lines checked
        confidence = min((max_score / (total_lines + 1)) * 100, 100.0)
        
        # For legacy, we just fallback if confidence is too low for others
        if winner == "android" and confidence > 5:
            return {"platform": "android", "log_type": "logcat", "parser_name": "android_parser", "confidence": confidence}
        elif winner == "linux" and confidence > 5:
            return {"platform": "linux", "log_type": "syslog_or_audit", "parser_name": "linux_parser", "confidence": confidence}
        else:
            return {"platform": "windows", "log_type": "legacy", "parser_name": "legacy_parser", "confidence": confidence if winner == "legacy" else 10.0}
