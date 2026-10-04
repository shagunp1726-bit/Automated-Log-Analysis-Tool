"""
ForensicLens – AI Splunk Hunter Chatbot Engine
Context-aware Splunk Search Processing Language (SPL) generator powered by Gemini.
Leverages active case telemetry (incident type, entities, MITRE TTPs, log samples)
to generate production-ready Splunk queries and hunting playbooks.
"""

import re
import json
import logging
from typing import Dict, List, Any
# pyrefly: ignore [missing-import]
from google.genai import types

from .gemini_client import GeminiClient

logger = logging.getLogger("ForensicLens.SplunkBot")

SPLUNK_RESPONSE_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "message": {
            "type": "STRING",
            "description": "Clear forensic explanation, threat hunting rationale, and instructions for running the query."
        },
        "query_title": {
            "type": "STRING",
            "description": "Short descriptive title of the Splunk query (e.g., 'Brute Force Detection with Failure Threshold')."
        },
        "splunk_query": {
            "type": "STRING",
            "description": "The exact, production-ready Splunk SPL query. Single or multi-line formatted."
        },
        "sourcetypes": {
            "type": "STRING",
            "description": "Recommended Splunk sourcetype(s), index, or data model (e.g., 'index=windows sourcetype=WinEventLog:Security')."
        },
        "pipeline_stages": {
            "type": "ARRAY",
            "description": "Step-by-step breakdown of each SPL pipeline command explaining its purpose in the hunt.",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "stage": {"type": "STRING", "description": "The command or pipeline segment (e.g. '| stats count by user, src_ip')"},
                    "purpose": {"type": "STRING", "description": "What this stage achieves in the hunt"}
                },
                "required": ["stage", "purpose"]
            }
        },
        "mitre_technique": {
            "type": "STRING",
            "description": "Associated MITRE ATT&CK technique ID and name (e.g. 'T1110.001 - Password Guessing') if applicable."
        },
        "suggested_pivots": {
            "type": "ARRAY",
            "description": "2 to 4 recommended follow-up hunting questions or query refinements the analyst can click next.",
            "items": {"type": "STRING"}
        }
    },
    "required": ["message", "query_title", "splunk_query", "sourcetypes", "pipeline_stages", "suggested_pivots"]
}


class SplunkQueryBot:
    def __init__(self):
        self.client = GeminiClient()

    def build_case_context(self, case_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extracts key telemetry and entity data from the case to ground the bot's responses.
        """
        events = case_data.get("events", [])
        entity_summary = case_data.get("entity_summary", {})

        # Extract top entities
        users = [u.get("value") for u in entity_summary.get("user", []) if u.get("value")][:8]
        ips = [i.get("value") for i in entity_summary.get("ip", []) if i.get("value")][:8]
        processes = [p.get("value") for p in entity_summary.get("process", []) if p.get("value")][:8]

        # If entity summary is empty, extract from events
        if not users:
            seen_u = set()
            for e in events:
                u = e.get("user")
                if u and u not in ("–", "SYSTEM", "LOCAL SERVICE") and u not in seen_u:
                    seen_u.add(u)
                    users.append(u)
                if len(users) >= 8:
                    break

        if not ips:
            seen_ip = set()
            for e in events:
                ip = e.get("ip")
                if ip and ip != "–" and ip not in seen_ip:
                    seen_ip.add(ip)
                    ips.append(ip)
                if len(ips) >= 8:
                    break

        # Event types & categories present in the case
        event_types = list({e.get("type") for e in events if e.get("type")})[:15]
        categories = list({e.get("category") for e in events if e.get("category")})[:10]

        # MITRE techniques
        mitre_techs = []
        for t in case_data.get("mitre_techniques", [])[:15]:
            if isinstance(t, dict):
                mitre_techs.append(f"{t.get('technique_id', '')} ({t.get('name', '')})")
            elif isinstance(t, str):
                mitre_techs.append(t)

        # Detections triggered
        detections = []
        for d in case_data.get("detections", [])[:8]:
            if isinstance(d, dict):
                detections.append(d.get("name") or d.get("rule_name") or str(d))
            else:
                detections.append(str(d))

        # Sample raw event snippets showing field structures
        sample_logs = []
        for e in events[:5]:
            sample_logs.append({
                "type": e.get("type"),
                "user": e.get("user"),
                "ip": e.get("ip"),
                "process": e.get("process"),
                "raw": (e.get("raw") or e.get("message", ""))[:120]
            })

        return {
            "case_id": case_data.get("case_id"),
            "incident_type": case_data.get("incident_type", "Unknown Incident"),
            "severity": case_data.get("severity", "MEDIUM"),
            "risk_score": case_data.get("risk_score", 50),
            "total_events": len(events),
            "event_types": event_types,
            "categories": categories,
            "top_users": users,
            "top_ips": ips,
            "top_processes": processes,
            "mitre_techniques": mitre_techs,
            "triggered_detections": detections,
            "sample_logs": sample_logs
        }

    def _build_system_instruction(self, context: Dict[str, Any]) -> str:
        return f"""You are an elite Splunk SOC Threat Hunter, Detection Engineer, and Digital Forensics Expert embedded inside the ForensicLens SIEM platform.

Your primary purpose is to generate production-ready Splunk Search Processing Language (SPL) queries, detection searches, and threat hunting commands tailored to the user's forensic investigation.

CURRENT CASE TELEMETRY CONTEXT:
- Case ID: {context.get('case_id')}
- Incident Type: {context.get('incident_type')} (Severity: {context.get('severity')}, Risk: {context.get('risk_score')})
- Discovered MITRE ATT&CK Techniques: {', '.join(context.get('mitre_techniques', [])) or 'None recorded'}
- Key Users in Evidence: {', '.join(context.get('top_users', [])) or 'admin, SYSTEM'}
- Key Network IPs in Evidence: {', '.join(context.get('top_ips', [])) or 'Internal/External IPs'}
- Key Processes Observed: {', '.join(context.get('top_processes', [])) or 'powershell.exe, cmd.exe'}
- Event Types Detected: {', '.join(context.get('event_types', [])) or 'AUTH_FAIL, PROCESS_CREATE, NETWORK_CONN'}
- Detections Triggered: {', '.join(context.get('triggered_detections', [])) or 'None'}

GUIDELINES FOR SPLUNK QUERY CREATION:
1. Ground the queries in the specific entities (usernames, IPs, hosts, process names) and event types found in this case whenever applicable.
2. Produce syntactically valid Splunk Search Processing Language (SPL) following best practices (filter as early as possible before the first pipe).
3. Support both standard index searches and CIM/Data Model accelerated searches (`| tstats`) when appropriate.
4. When the user asks to refine or filter an existing query (e.g. 'group by user', 'add a 5 minute threshold', 'convert to timechart', 'show only critical'), maintain conversational context from prior turns.
5. Provide a detailed step-by-step pipeline breakdown explaining what each pipe stage achieves.
6. Suggest 2-4 tactical next pivot queries that the threat hunter should run next to trace lateral movement, persistence, or data staging.
7. Always respond in valid JSON matching the specified schema.
"""

    def chat(self, case_data: Dict[str, Any], user_message: str, history: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Processes a user message in the context of the case and conversation history.
        Returns a structured Splunk response dict.
        """
        history = history or []
        context = self.build_case_context(case_data)
        system_instr = self._build_system_instruction(context)

        # Build contents list for Gemini multi-turn
        contents = []

        # Add existing conversation turns
        for item in history:
            role = item.get("role")
            content_text = item.get("content", "")
            if role == "user":
                contents.append(types.Content(role="user", parts=[types.Part.from_text(text=content_text)]))
            elif role == "assistant":
                # If assistant turn has structured splunk query or JSON
                if isinstance(item.get("data"), dict):
                    assistant_str = json.dumps(item.get("data"))
                else:
                    assistant_str = json.dumps({
                        "message": content_text,
                        "query_title": item.get("query_title", "Previous Query"),
                        "splunk_query": item.get("splunk_query", ""),
                        "sourcetypes": item.get("sourcetypes", "index=*"),
                        "pipeline_stages": item.get("pipeline_stages", []),
                        "suggested_pivots": item.get("suggested_pivots", [])
                    })
                contents.append(types.Content(role="model", parts=[types.Part.from_text(text=assistant_str)]))

        # Add current user prompt
        prompt_with_context = user_message.strip()
        contents.append(types.Content(role="user", parts=[types.Part.from_text(text=prompt_with_context)]))

        # Attempt Gemini call
        if self.client.is_available():
            try:
                result = self.client.analyze_chat(system_instr, contents, SPLUNK_RESPONSE_SCHEMA)
                if isinstance(result, dict) and "splunk_query" in result and not result.get("error"):
                    return self._clean_result(result, context)
                elif isinstance(result, dict) and result.get("error"):
                    logger.warning(f"Gemini returned error, falling back to rule engine: {result.get('error')}")
            except Exception as e:
                logger.error(f"Error calling Gemini for Splunk chat: {e}")

        # Fallback if Gemini is offline or unavailable
        return self._generate_fallback(user_message, context, history)

    def _clean_result(self, result: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Ensures all expected fields exist and have proper defaults."""
        result.setdefault("message", "Generated Splunk hunting query based on case telemetry.")
        result.setdefault("query_title", "Splunk Threat Hunting Query")
        result.setdefault("splunk_query", "index=* | head 50")
        result.setdefault("sourcetypes", "index=windows sourcetype=WinEventLog:Security")
        result.setdefault("pipeline_stages", [
            {"stage": result.get("splunk_query", ""), "purpose": "Execute initial search filter"}
        ])
        result.setdefault("suggested_pivots", [
            "Aggregate by user and count occurrences",
            "Correlate with successful authentications within 10 minutes",
            "Group by destination IP and port"
        ])
        if not result.get("mitre_technique") and context.get("mitre_techniques"):
            result["mitre_technique"] = context["mitre_techniques"][0]
        return result

    def _generate_fallback(self, user_message: str, context: Dict[str, Any], history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        High-grade rule-based fallback that generates realistic, context-specific Splunk queries
        when external AI APIs are unreachable.
        """
        msg = user_message.lower()
        top_user = context.get("top_users", ["admin"])[0] if context.get("top_users") else "admin"
        top_ip = context.get("top_ips", ["192.168.1.50"])[0] if context.get("top_ips") else "192.168.1.50"
        top_process = context.get("top_processes", ["powershell.exe"])[0] if context.get("top_processes") else "powershell.exe"

        # 1. Failed Logins / Brute Force
        if any(w in msg for w in ["fail", "login", "auth", "brute", "password", "logon", "4625"]):
            return {
                "message": f"Hunting for failed authentications across the network. Specifically focusing on user accounts like '{top_user}' identified during telemetry analysis.",
                "query_title": "Windows Failed Logon Surge & Brute Force Hunt",
                "splunk_query": f'index=windows (sourcetype="WinEventLog:Security" EventCode=4625) OR (sourcetype="linux_secure" "Failed password")\\n| eval Target_User=coalesce(TargetUserName, user)\\n| eval Source_IP=coalesce(WorkstationName, src_ip, ip)\\n| stats count as failure_count, earliest(_time) as first_attempt, latest(_time) as last_attempt by Target_User, Source_IP\\n| where failure_count >= 5\\n| sort - failure_count\\n| fieldformat first_attempt=strftime(first_attempt, "%Y-%m-%d %H:%M:%S")\\n| fieldformat last_attempt=strftime(last_attempt, "%Y-%m-%d %H:%M:%S")',
                "sourcetypes": "index=windows sourcetype=WinEventLog:Security",
                "mitre_technique": "T1110.001 - Password Guessing",
                "pipeline_stages": [
                    {"stage": "index=windows EventCode=4625", "purpose": "Filter for Windows Event ID 4625 (An account failed to log on)"},
                    {"stage": "| eval Target_User=coalesce(...)", "purpose": "Normalize user and IP fields across Windows and Linux sourcetypes"},
                    {"stage": "| stats count as failure_count by Target_User, Source_IP", "purpose": "Aggregate attempts per account and originating IP"},
                    {"stage": "| where failure_count >= 5", "purpose": "Eliminate routine password typos by enforcing a 5+ failure threshold"},
                    {"stage": "| sort - failure_count", "purpose": "Rank the most heavily targeted accounts to prioritize response"}
                ],
                "suggested_pivots": [
                    f"Correlate failed logins with subsequent successful logons (EventCode 4624) for {top_user}",
                    "Convert this query to an accelerated tstats search for faster execution",
                    "Add timechart span=1h to visualize the attack distribution over time"
                ]
            }

        # 2. PowerShell / Execution
        elif any(w in msg for w in ["powershell", "encoded", "script", "cmd", "process", "exec"]):
            return {
                "message": f"Detecting suspicious process creation and obfuscated PowerShell invocations matching patterns discovered in case evidence.",
                "query_title": "Suspicious PowerShell & Process Creation Hunt",
                "splunk_query": f'index=windows ((sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell.exe") OR (sourcetype="WinEventLog:Security" EventCode=4688 NewProcessName="*powershell.exe"))\\n| search CommandLine="*-enc*" OR CommandLine="*-nop*" OR CommandLine="*downloadstring*" OR CommandLine="*bypass*" OR CommandLine="*invoke*"\\n| stats count earliest(_time) as first_seen latest(_time) as last_seen by host, user, ParentImage, CommandLine\\n| table host, user, ParentImage, CommandLine, count\\n| sort - count',
                "sourcetypes": "index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                "mitre_technique": "T1059.001 - PowerShell Execution",
                "pipeline_stages": [
                    {"stage": "index=windows EventCode=1 OR EventCode=4688", "purpose": "Target Sysmon Process Create (1) and Security Audit Process Tracking (4688)"},
                    {"stage": '| search CommandLine="*-enc*" OR ...', "purpose": "Identify evasive PowerShell arguments (-encodedcommand, -nop, DownloadString)"},
                    {"stage": "| stats count ... by host, user, ParentImage, CommandLine", "purpose": "Group identical executions to highlight anomalous parent-child relationships"}
                ],
                "suggested_pivots": [
                    "Decode base64 command lines using Splunk rex and base64 decode",
                    "Hunt for network connections spawned by this process (Sysmon EventCode 3)",
                    f"Filter specifically for user '{top_user}' and host '{context.get('case_id', 'HOST')[:8]}'"
                ]
            }

        # 3. Lateral Movement / PsExec / WMI
        elif any(w in msg for w in ["lateral", "psexec", "wmi", "smb", "share", "movement"]):
            return {
                "message": f"Hunting for lateral movement indicators such as remote service creation, network share access, and WMI invocations.",
                "query_title": "Lateral Movement & Remote Service Creation Hunt",
                "splunk_query": f'index=windows (sourcetype="WinEventLog:System" EventCode=7045) OR (sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=3)\\n| eval Service=coalesce(ServiceName, "N/A"), Target=coalesce(TargetUserName, user)\\n| stats count, values(Service) as Services, values(Target) as Users by host, src_ip\\n| where count > 1\\n| sort - count',
                "sourcetypes": "index=windows sourcetype=WinEventLog:System / Security",
                "mitre_technique": "T1021.002 - SMB/Windows Admin Shares",
                "pipeline_stages": [
                    {"stage": "EventCode=7045 OR (EventCode=4624 Logon_Type=3)", "purpose": "Correlate service installations with Network Logon Type 3 (common for PsExec/WMI)"},
                    {"stage": "| stats count, values(Service) as Services ... by host, src_ip", "purpose": "Identify which remote hosts are pushing new services or logging in over the network"}
                ],
                "suggested_pivots": [
                    "Filter out common Windows domain controllers from the source IP list",
                    "Examine file creation in ADMIN$ and C$ shares (EventCode 5145)",
                    "Build an entity relationship table of source-to-destination hosts"
                ]
            }

        # 4. Network Connections / C2 / Exfiltration
        elif any(w in msg for w in ["network", "traffic", "c2", "beacon", "exfiltration", "dns", "ip"]):
            return {
                "message": f"Investigating outbound connections and suspicious communication channels associated with observed IP {top_ip}.",
                "query_title": "Suspicious Outbound Network & Potential C2 Traffic",
                "splunk_query": f'index=network (sourcetype="pan:traffic" OR sourcetype="cisco:asa" OR sourcetype="suricata")\\n| search dest_ip="{top_ip}" OR (dest_port IN (4444, 1337, 8080, 8443, 9001))\\n| stats count, sum(bytes_out) as total_bytes_sent, dc(dest_port) as distinct_ports by src_ip, dest_ip, dest_port\\n| eval MB_Sent=round(total_bytes_sent/(1024*1024), 2)\\n| where count > 10\\n| sort - MB_Sent',
                "sourcetypes": "index=network sourcetype=pan:traffic",
                "mitre_technique": "T1071.001 - Web Protocols",
                "pipeline_stages": [
                    {"stage": "index=network ...", "purpose": "Search firewall and perimeter network telemetry"},
                    {"stage": f'| search dest_ip="{top_ip}" OR dest_port IN (...)', "purpose": "Target high-risk non-standard ports and suspect destination addresses"},
                    {"stage": "| stats count, sum(bytes_out) ...", "purpose": "Calculate data volume transferred to detect large exfiltration events"},
                    {"stage": "| eval MB_Sent=round(...)", "purpose": "Format bytes to Megabytes for analyst clarity"}
                ],
                "suggested_pivots": [
                    "Analyze beaconing intervals using standard deviation of connection times",
                    "Correlate destination IPs against threat intelligence feeds",
                    "Show DNS queries resolving to this IP block"
                ]
            }

        # 5. Generic / Default Case Investigation Hunt
        else:
            return {
                "message": f"Hunting across all telemetry indexed for case {context.get('case_id', 'CASE')}. Formulated query targeting key indicators and events matching '{user_message}'.",
                "query_title": f"Threat Telemetry Hunt: {user_message[:40]}",
                "splunk_query": f'index=* ("{user_message.strip()}" OR "{top_user}" OR "{top_ip}")\\n| stats count as match_count, values(sourcetype) as sourcetypes, values(host) as hosts by _time, user, ip\\n| sort - _time\\n| head 100',
                "sourcetypes": "index=* sourcetype=*",
                "mitre_technique": context.get("mitre_techniques", ["T1005 - Data from Local System"])[0] if context.get("mitre_techniques") else "T1005",
                "pipeline_stages": [
                    {"stage": 'index=* ("..." OR "...")', "purpose": "Free-text search across all indexes for case entities and inquiry terms"},
                    {"stage": "| stats count as match_count ... by _time, user, ip", "purpose": "Summarize hits per timeline bucket"},
                    {"stage": "| head 100", "purpose": "Limit output to the 100 most recent events for fast preview"}
                ],
                "suggested_pivots": [
                    f"Narrow search to index=windows with EventCode 4624/4625 for {top_user}",
                    "Aggregate by sourcetype to see which data source has the highest concentration of logs",
                    "Add timechart span=15m count by sourcetype"
                ]
            }
