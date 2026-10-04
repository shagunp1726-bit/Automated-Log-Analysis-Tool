"""
ForensicLens – IOC Enrichment & Threat Intelligence Module
Built-in IOC database, reputation scoring, auto-matching,
and simulated GeoIP tagging.
"""

import re
from collections import defaultdict

KNOWN_BAD_IPS = {
    "10.0.0.50": {"reputation": 15, "tags": ["c2-server", "malware-distribution"],
                  "description": "Known C2 server – malware distribution hub"},
    "203.0.113.50": {"reputation": 10, "tags": ["data-exfiltration", "suspicious"],
                     "description": "Suspected exfiltration endpoint"},
    "198.51.100.22": {"reputation": 20, "tags": ["botnet", "c2"],
                      "description": "Active botnet C2 infrastructure"},
    "45.33.32.156": {"reputation": 40, "tags": ["scanner", "recon"],
                     "description": "Known network scanner"},
}

KNOWN_BAD_DOMAINS = {
    "c2-beacon.evil.com": {"reputation": 5, "tags": ["c2", "beacon"],
                           "description": "Command and control beacon domain"},
    "malware-cdn.xyz": {"reputation": 10, "tags": ["malware", "distribution"],
                        "description": "Malware distribution CDN"},
    "data-drop.ru": {"reputation": 5, "tags": ["exfiltration", "data-drop"],
                     "description": "Data exfiltration drop point"},
}

KNOWN_BAD_USER_AGENTS = {
    "sqlmap": {"reputation": 5, "tags": ["web-attack", "sqli"],
               "description": "SQLMap automated SQL injection tool"},
    "nikto": {"reputation": 10, "tags": ["web-scanner"],
              "description": "Nikto web vulnerability scanner"},
    "nmap": {"reputation": 20, "tags": ["port-scanner", "recon"],
             "description": "Nmap network scanner"},
}

SUSPICIOUS_PORTS = {
    4444: "Meterpreter default", 5555: "Common reverse shell",
    8888: "Alternative HTTP", 8443: "Alternative HTTPS / C2",
    31337: "Elite hacker", 6667: "IRC (C2)", 1337: "Leet port",
}

GEOIP_DATA = {
    "192.168.": {"country": "Internal", "city": "LAN", "asn": "RFC1918"},
    "10.": {"country": "Internal", "city": "LAN", "asn": "RFC1918"},
    "203.0.113.": {"country": "Russia", "city": "Moscow", "asn": "AS12345"},
    "198.51.100.": {"country": "China", "city": "Beijing", "asn": "AS67890"},
    "45.33.32.": {"country": "United States", "city": "San Jose", "asn": "AS63949"},
}


class IOCEngine:
    """IOC Enrichment Engine. Scans events against built-in threat intel."""

    def __init__(self):
        self.matches = []

    def scan_events(self, events):
        self.matches = []
        for i, event in enumerate(events):
            self._check_ip(event, i)
            self._check_domain(event, i)
            self._check_user_agent(event, i)
            self._check_port(event, i)
        self.matches.sort(key=lambda m: m["reputation"])
        return self.matches

    def _check_ip(self, event, idx):
        for ip_field in ["ip", "dest_ip"]:
            ip = event.get(ip_field)
            if ip and ip in KNOWN_BAD_IPS:
                ioc = KNOWN_BAD_IPS[ip]
                self.matches.append({
                    "event_index": idx, "ioc_type": "ip", "ioc_value": ip,
                    "reputation": ioc["reputation"], "tags": ioc["tags"],
                    "description": ioc["description"], "geo": self._geoip(ip),
                    "event_raw": event.get("raw", "")[:200],
                    "timestamp": event.get("timestamp"),
                    "severity": "critical" if ioc["reputation"] <= 15 else "high",
                })

    def _check_domain(self, event, idx):
        raw = (event.get("raw") or "").lower()
        for domain, ioc in KNOWN_BAD_DOMAINS.items():
            if domain in raw:
                self.matches.append({
                    "event_index": idx, "ioc_type": "domain", "ioc_value": domain,
                    "reputation": ioc["reputation"], "tags": ioc["tags"],
                    "description": ioc["description"], "geo": None,
                    "event_raw": event.get("raw", "")[:200],
                    "timestamp": event.get("timestamp"),
                    "severity": "critical" if ioc["reputation"] <= 15 else "high",
                })

    def _check_user_agent(self, event, idx):
        raw = (event.get("raw") or "").lower()
        for ua, ioc in KNOWN_BAD_USER_AGENTS.items():
            if ua.lower() in raw:
                self.matches.append({
                    "event_index": idx, "ioc_type": "user_agent", "ioc_value": ua,
                    "reputation": ioc["reputation"], "tags": ioc["tags"],
                    "description": ioc["description"], "geo": None,
                    "event_raw": event.get("raw", "")[:200],
                    "timestamp": event.get("timestamp"), "severity": "high",
                })

    def _check_port(self, event, idx):
        port = event.get("port")
        if port:
            try:
                port_int = int(port)
                if port_int in SUSPICIOUS_PORTS:
                    self.matches.append({
                        "event_index": idx, "ioc_type": "port",
                        "ioc_value": str(port_int), "reputation": 25,
                        "tags": ["suspicious-port"],
                        "description": SUSPICIOUS_PORTS[port_int],
                        "geo": None, "event_raw": event.get("raw", "")[:200],
                        "timestamp": event.get("timestamp"), "severity": "high",
                    })
            except (ValueError, TypeError):
                pass

    def _geoip(self, ip):
        if not ip:
            return None
        for prefix, geo in GEOIP_DATA.items():
            if ip.startswith(prefix):
                return geo
        return {"country": "Unknown", "city": "Unknown", "asn": "Unknown"}

    def get_enrichment_summary(self, events):
        if not self.matches:
            self.scan_events(events)
        summary = {"total_matches": len(self.matches), "by_type": defaultdict(int),
                    "by_severity": defaultdict(int), "unique_iocs": set()}
        for m in self.matches:
            summary["by_type"][m["ioc_type"]] += 1
            summary["by_severity"][m["severity"]] += 1
            summary["unique_iocs"].add(f"{m['ioc_type']}:{m['ioc_value']}")
        summary["by_type"] = dict(summary["by_type"])
        summary["by_severity"] = dict(summary["by_severity"])
        summary["unique_iocs"] = len(summary["unique_iocs"])
        return summary
