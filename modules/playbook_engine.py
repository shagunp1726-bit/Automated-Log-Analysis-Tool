"""
ForensicLens – Playbook Engine
Static incident response playbooks + rule-based AI-assisted playbook suggestions.
"""

from collections import Counter


class PlaybookEngine:
    def __init__(self):
        self.playbooks = {

            # ── Authentication ────────────────────────────────────────────────
            "Authentication Attack (Brute Force)": {
                "title": "Brute Force Response Playbook",
                "severity": "High",
                "mitre_techniques": ["T1110"],
                "event_types": ["AUTH_FAIL"],
                "steps": [
                    {
                        "phase": "Containment",
                        "action": "Invoke account lockout for target user accounts.",
                        "details": "Threshold reached: 10+ failed attempts. Force password reset on recovery."
                    },
                    {
                        "phase": "Containment",
                        "action": "Block source IP addresses at the perimeter firewall.",
                        "details": "Identify top 5 source IPs from auth logs and blackhole them."
                    },
                    {
                        "phase": "Eradication",
                        "action": "Review successful logins from the same source IP.",
                        "details": "Check for any 'Auth Success' after a long chain of failures."
                    },
                    {
                        "phase": "Recovery",
                        "action": "Implement Multi-Factor Authentication (MFA).",
                        "details": "Mandatory enrollment for all high-risk accounts identified."
                    },
                    {
                        "phase": "Hardening",
                        "action": "Tune account lockout policy (e.g., 5 attempts, 15-min lockout).",
                        "details": "Apply across AD/LDAP for all user tiers."
                    }
                ],
                "contacts": ["Identity Team", "Security Operations Lead"]
            },

            "Credential Compromise": {
                "title": "Credential Compromise Response",
                "severity": "Critical",
                "mitre_techniques": ["T1078", "T1003", "T1110"],
                "event_types": ["AUTH_SUCCESS", "AUTH_FAIL", "PRIV_ESCALATION"],
                "steps": [
                    {
                        "phase": "Containment",
                        "action": "Disable affected user sessions globally.",
                        "details": "Clear all OAuth tokens and Kerberos tickets (TGT)."
                    },
                    {
                        "phase": "Eradication",
                        "action": "Force credential rotation for all system admins.",
                        "details": "Compromise detected in privilege escalation paths."
                    },
                    {
                        "phase": "Investigation",
                        "action": "Perform timeline analysis of the session.",
                        "details": "Identify every resource accessed during the compromised window."
                    },
                    {
                        "phase": "Hardening",
                        "action": "Enable Privileged Access Workstations (PAW) for admin accounts.",
                        "details": "Restrict admin sessions to hardened, monitored endpoints."
                    }
                ],
                "contacts": ["Active Directory Admin", "CISO Office"]
            },

            # ── Ransomware ────────────────────────────────────────────────────
            "Ransomware": {
                "title": "Ransomware Incident Response Playbook",
                "severity": "Critical",
                "mitre_techniques": ["T1486", "T1490", "T1059", "T1566"],
                "event_types": ["MALWARE_INDICATOR", "FILE_DELETE", "EXECUTION_SUSPICIOUS"],
                "steps": [
                    {
                        "phase": "Immediate Containment",
                        "action": "Isolate affected hosts from the network immediately.",
                        "details": "Pull network cables or apply ACL-based isolation at the switch level. Do NOT power off — preserve memory."
                    },
                    {
                        "phase": "Immediate Containment",
                        "action": "Disable shared drives and network shares accessible from affected hosts.",
                        "details": "Prevent lateral spread to unencrypted file shares."
                    },
                    {
                        "phase": "Assessment",
                        "action": "Determine ransomware family and encryption scope.",
                        "details": "Identify ransom note, encrypted file extensions, and impacted directories."
                    },
                    {
                        "phase": "Eradication",
                        "action": "Identify and terminate malicious processes.",
                        "details": "Kill processes responsible for encryption using memory forensics."
                    },
                    {
                        "phase": "Eradication",
                        "action": "Check and restore Volume Shadow Copies if not deleted.",
                        "details": "Run: vssadmin list shadows. If intact, restore from VSS."
                    },
                    {
                        "phase": "Recovery",
                        "action": "Restore from clean offline backups.",
                        "details": "Validate backup integrity before restoration. Do NOT restore from network-connected backups if they may be compromised."
                    },
                    {
                        "phase": "Post-Incident",
                        "action": "Report to relevant authorities (e.g., CERT, law enforcement).",
                        "details": "Document all evidence. Preserve encrypted samples for decryption research."
                    },
                    {
                        "phase": "Hardening",
                        "action": "Implement application whitelisting and disable macro execution.",
                        "details": "Block common ransomware delivery vectors (Office macros, script interpreters)."
                    }
                ],
                "contacts": ["CISO Office", "Legal/Compliance", "Backup & Recovery Team", "Law Enforcement (if required)"]
            },

            # ── Web Attacks ───────────────────────────────────────────────────
            "Web Application Attack (SQLi/XSS)": {
                "title": "Web Application Attack Response",
                "severity": "High",
                "mitre_techniques": ["T1190", "T1505"],
                "event_types": ["WEB_ATTACK"],
                "steps": [
                    {
                        "phase": "Containment",
                        "action": "Enable WAF (Web Application Firewall) blocking mode.",
                        "details": "Identify malicious payload patterns and apply virtual patching."
                    },
                    {
                        "phase": "Eradication",
                        "action": "Sanitize and validate all input fields.",
                        "details": "Check logs for successful SQL injection or XSS bypass."
                    },
                    {
                        "phase": "Investigation",
                        "action": "Review application logs for backend errors.",
                        "details": "Look for database error spikes correlating with the attack timeline."
                    },
                    {
                        "phase": "Investigation",
                        "action": "Scan web server filesystem for planted web shells.",
                        "details": "Search for .php, .aspx, .jsp files modified during the attack window."
                    },
                    {
                        "phase": "Hardening",
                        "action": "Enforce parameterized queries / prepared statements.",
                        "details": "Perform code review on all database interaction points."
                    }
                ],
                "contacts": ["AppSec Team", "Web Infrastructure Lead"]
            },

            "Webshell / Server Compromise": {
                "title": "Webshell & Server Compromise Response",
                "severity": "Critical",
                "mitre_techniques": ["T1505", "T1190", "T1059"],
                "event_types": ["WEB_ATTACK", "FILE_CREATE", "PROCESS_CREATE"],
                "steps": [
                    {
                        "phase": "Containment",
                        "action": "Take the web server offline or block external access.",
                        "details": "Move behind WAF in blocking mode; restrict direct internet exposure."
                    },
                    {
                        "phase": "Investigation",
                        "action": "Find and remove all webshell files.",
                        "details": "Search for files matching webshell signatures: eval(), base64_decode(), system() in PHP; Runtime.exec() in JSP."
                    },
                    {
                        "phase": "Investigation",
                        "action": "Review server access logs for the attacker's activity.",
                        "details": "Trace all POST requests to the webshell. Identify lateral movement attempts."
                    },
                    {
                        "phase": "Eradication",
                        "action": "Patch the vulnerability used to upload the webshell.",
                        "details": "Apply virtual patch at WAF while permanent code fix is developed."
                    },
                    {
                        "phase": "Recovery",
                        "action": "Restore server from a known-good image or snapshot.",
                        "details": "Do not attempt to clean an actively compromised server in place."
                    },
                    {
                        "phase": "Hardening",
                        "action": "Disable script execution in upload directories.",
                        "details": "Set web server config to deny execution of .php/.aspx in user-writable paths."
                    }
                ],
                "contacts": ["AppSec Team", "Web Infrastructure Lead", "Security Operations"]
            },

            # ── Lateral Movement ──────────────────────────────────────────────
            "Pass-the-Hash / Lateral Movement": {
                "title": "Pass-the-Hash / Lateral Movement Response",
                "severity": "Critical",
                "mitre_techniques": ["T1550", "T1021", "T1003"],
                "event_types": ["AUTH_SUCCESS", "PRIV_ESCALATION"],
                "steps": [
                    {
                        "phase": "Containment",
                        "action": "Isolate all hosts involved in lateral movement immediately.",
                        "details": "Block SMB (445), WinRM (5985/5986), RDP (3389) between internal segments."
                    },
                    {
                        "phase": "Eradication",
                        "action": "Invalidate all NTLM hashes for compromised accounts.",
                        "details": "Force password reset for all accounts used in pass-the-hash activity. Reset KRBTGT twice to invalidate Kerberos tickets."
                    },
                    {
                        "phase": "Investigation",
                        "action": "Enumerate all systems accessed using stolen credentials.",
                        "details": "Correlate Event ID 4624 (logon type 3) with lateral movement source IPs."
                    },
                    {
                        "phase": "Hardening",
                        "action": "Enable Credential Guard and disable NTLM where possible.",
                        "details": "Deploy Windows Defender Credential Guard via GPO."
                    },
                    {
                        "phase": "Hardening",
                        "action": "Implement Local Admin Password Solution (LAPS).",
                        "details": "Ensure unique local admin passwords per machine to prevent hash reuse."
                    }
                ],
                "contacts": ["Active Directory Admin", "Network Security Team", "CISO Office"]
            },

            # ── Privilege Escalation ──────────────────────────────────────────
            "Privilege Escalation": {
                "title": "Privilege Escalation Response Playbook",
                "severity": "Critical",
                "mitre_techniques": ["T1548", "T1068", "T1134"],
                "event_types": ["PRIV_ESCALATION"],
                "steps": [
                    {
                        "phase": "Containment",
                        "action": "Revoke elevated session immediately.",
                        "details": "Kill the privileged process tree. Revoke any sudo/admin tokens granted."
                    },
                    {
                        "phase": "Investigation",
                        "action": "Determine the escalation vector.",
                        "details": "Check for kernel exploits, sudo misconfigurations, SUID binaries, or UAC bypass techniques."
                    },
                    {
                        "phase": "Investigation",
                        "action": "Audit all actions taken under elevated privileges.",
                        "details": "Review audit logs for file access, process creation, and network connections made as root/SYSTEM."
                    },
                    {
                        "phase": "Eradication",
                        "action": "Patch the escalation vulnerability.",
                        "details": "Apply OS patches; remove unnecessary SUID bits; tighten sudoers."
                    },
                    {
                        "phase": "Hardening",
                        "action": "Implement least-privilege principle across all accounts.",
                        "details": "Audit group memberships. Remove unused admin rights."
                    }
                ],
                "contacts": ["System Administration", "Security Operations Lead"]
            },

            # ── Data Exfiltration ─────────────────────────────────────────────
            "Data Exfiltration": {
                "title": "Data Exfiltration Response",
                "severity": "Critical",
                "mitre_techniques": ["T1041", "T1048", "T1567"],
                "event_types": ["NETWORK_CONN", "FILE_COPY"],
                "steps": [
                    {
                        "phase": "Containment",
                        "action": "Terminate active network connections to external C2.",
                        "details": "Kill state on firewall for identified destination IPs."
                    },
                    {
                        "phase": "Containment",
                        "action": "Isolate evidence host from the network.",
                        "details": "Move to forensic VLAN to prevent further data egress."
                    },
                    {
                        "phase": "Eradication",
                        "action": "Analyze exfiltrated data volume and sensitivity.",
                        "details": "Check NetFlow data for total outbound bytes. Identify data classification of affected files."
                    },
                    {
                        "phase": "Notification",
                        "action": "Notify Privacy Officer and Legal for breach assessment.",
                        "details": "Determine if GDPR, HIPAA, or other regulatory notification requirements apply."
                    },
                    {
                        "phase": "Hardening",
                        "action": "Deploy Data Loss Prevention (DLP) policies.",
                        "details": "Block unauthorized outbound file transfers to cloud storage and personal email."
                    }
                ],
                "contacts": ["Network Security Team", "Privacy Officer", "Legal/Compliance"]
            },

            # ── Insider Threat ────────────────────────────────────────────────
            "Insider Data Theft": {
                "title": "Insider Threat Response Playbook",
                "severity": "Critical",
                "mitre_techniques": ["T1005", "T1560", "T1567"],
                "event_types": ["FILE_COPY", "USB"],
                "steps": [
                    {
                        "phase": "Containment",
                        "action": "Disable USB port access via Group Policy (GPO).",
                        "details": "Targeted deployment to the investigated host."
                    },
                    {
                        "phase": "Containment",
                        "action": "Suspend user network access accounts.",
                        "details": "Legal hold initiated. Do not delete data; preserve for forensics."
                    },
                    {
                        "phase": "Eradication",
                        "action": "Identify all files copied to external media.",
                        "details": "Review event ID 4663 and USB file system logs."
                    },
                    {
                        "phase": "Investigation",
                        "action": "Preserve forensic image of all involved devices.",
                        "details": "Use write-blockers during imaging. Maintain chain of custody."
                    }
                ],
                "contacts": ["HR Department", "Legal/Compliance", "Internal Audit"]
            },

            # ── DDoS / DoS ────────────────────────────────────────────────────
            "DDoS / Network Denial of Service": {
                "title": "DDoS / Network DoS Response Playbook",
                "severity": "Critical",
                "mitre_techniques": ["T1498", "T1499"],
                "event_types": ["NETWORK_CONN", "FIREWALL"],
                "steps": [
                    {
                        "phase": "Immediate Mitigation",
                        "action": "Enable DDoS scrubbing / upstream traffic filtering.",
                        "details": "Contact ISP or CDN provider to activate DDoS mitigation. Route traffic through scrubbing centers."
                    },
                    {
                        "phase": "Containment",
                        "action": "Apply rate limiting and IP reputation blocks.",
                        "details": "Configure firewall rate limits on affected services. Block known botnet IP ranges."
                    },
                    {
                        "phase": "Assessment",
                        "action": "Identify attack type (volumetric, protocol, application layer).",
                        "details": "Analyze NetFlow/PCAP. Distinguish SYN flood, UDP amplification, or HTTP flood."
                    },
                    {
                        "phase": "Recovery",
                        "action": "Restore affected services incrementally.",
                        "details": "Bring services back online behind additional protection layers."
                    },
                    {
                        "phase": "Hardening",
                        "action": "Implement anycast network diffusion and capacity planning.",
                        "details": "Distribute traffic globally to absorb future volumetric attacks."
                    }
                ],
                "contacts": ["Network Ops", "ISP / CDN Provider", "NOC Team"]
            },

            # ── Malware / C2 ──────────────────────────────────────────────────
            "Malware C2 Beacon": {
                "title": "C2 Beacon / Malware Response Playbook",
                "severity": "Critical",
                "mitre_techniques": ["T1071", "T1572", "T1573", "T1105"],
                "event_types": ["MALWARE_INDICATOR", "NETWORK_CONN"],
                "steps": [
                    {
                        "phase": "Containment",
                        "action": "Block identified C2 IP/domain at perimeter firewall and DNS.",
                        "details": "Add to firewall block list and DNS sinkhole. Monitor for reconnection to new IPs."
                    },
                    {
                        "phase": "Containment",
                        "action": "Isolate the infected host.",
                        "details": "Remove from network but keep powered on for memory forensics."
                    },
                    {
                        "phase": "Investigation",
                        "action": "Perform memory forensics to identify injected code.",
                        "details": "Use Volatility or Rekall to dump and analyze process memory. Look for injected shellcode."
                    },
                    {
                        "phase": "Eradication",
                        "action": "Identify and remove the malware dropper and persistence mechanism.",
                        "details": "Check registry Run keys, scheduled tasks, services, and startup folders."
                    },
                    {
                        "phase": "Recovery",
                        "action": "Reimage the host from a trusted golden image.",
                        "details": "Do not attempt in-place cleanup for sophisticated implants."
                    },
                    {
                        "phase": "Threat Intel",
                        "action": "Share C2 IOCs with threat intelligence platforms.",
                        "details": "Submit hashes, IPs, and domains to MISP, VirusTotal, and ISAC."
                    }
                ],
                "contacts": ["Security Operations", "Threat Intel Team", "Endpoint Team"]
            },

            # ── Defense Evasion ───────────────────────────────────────────────
            "Defense Evasion / Process Injection": {
                "title": "Process Injection & Defense Evasion Response",
                "severity": "Critical",
                "mitre_techniques": ["T1055", "T1562", "T1218", "T1070"],
                "event_types": ["PROCESS_CREATE", "EXECUTION_SUSPICIOUS"],
                "steps": [
                    {
                        "phase": "Detection",
                        "action": "Identify the injecting process using EDR telemetry.",
                        "details": "Look for CreateRemoteThread, VirtualAllocEx, WriteProcessMemory API calls."
                    },
                    {
                        "phase": "Containment",
                        "action": "Terminate the injecting and injected process.",
                        "details": "Kill the entire process tree. Collect memory dump before termination."
                    },
                    {
                        "phase": "Investigation",
                        "action": "Determine the infection vector that led to code injection.",
                        "details": "Trace parent process chain. Identify how the injector was loaded."
                    },
                    {
                        "phase": "Eradication",
                        "action": "Audit disabled security tools and re-enable them.",
                        "details": "Check if EDR/AV was tampered with via Event ID 4689 or service stop events."
                    },
                    {
                        "phase": "Hardening",
                        "action": "Enable Attack Surface Reduction (ASR) rules.",
                        "details": "Block process injection, credential theft, and LOLBAS via ASR policies."
                    }
                ],
                "contacts": ["Endpoint Security Team", "Security Operations"]
            },

            # ── Phishing ──────────────────────────────────────────────────────
            "Phishing / Initial Access": {
                "title": "Phishing & Initial Access Response Playbook",
                "severity": "High",
                "mitre_techniques": ["T1566", "T1204", "T1059"],
                "event_types": ["EXECUTION_SUSPICIOUS", "PROCESS_CREATE"],
                "steps": [
                    {
                        "phase": "Containment",
                        "action": "Pull the phishing email from all mailboxes.",
                        "details": "Use email gateway admin tools to purge by sender/subject/hash."
                    },
                    {
                        "phase": "Containment",
                        "action": "Block the sender domain and malicious attachment hash.",
                        "details": "Add to email gateway blocklist and endpoint file hash blocklist."
                    },
                    {
                        "phase": "Assessment",
                        "action": "Determine how many users opened the attachment or clicked the link.",
                        "details": "Review email gateway click-through logs. Identify all exposed users."
                    },
                    {
                        "phase": "Investigation",
                        "action": "Check exposed hosts for signs of payload execution.",
                        "details": "Look for macro execution, Office spawning PowerShell/cmd, or network callbacks."
                    },
                    {
                        "phase": "User Notification",
                        "action": "Notify exposed users and require password reset.",
                        "details": "Issue security advisory. Provide guidance on reporting suspicious emails."
                    },
                    {
                        "phase": "Hardening",
                        "action": "Enable DMARC, DKIM, SPF for all email domains.",
                        "details": "Block spoofed sender domains. Train users with phishing simulations."
                    }
                ],
                "contacts": ["Email Security Team", "Security Awareness Team", "IT Help Desk"]
            },

            # ── Supply Chain ──────────────────────────────────────────────────
            "Supply Chain Compromise": {
                "title": "Supply Chain Compromise Response",
                "severity": "Critical",
                "mitre_techniques": ["T1195", "T1071"],
                "event_types": ["EXECUTION_SUSPICIOUS", "NETWORK_CONN"],
                "steps": [
                    {
                        "phase": "Assessment",
                        "action": "Identify the compromised software/vendor and affected version.",
                        "details": "Cross-reference vendor advisory with installed software inventory."
                    },
                    {
                        "phase": "Containment",
                        "action": "Isolate all systems running the compromised software.",
                        "details": "Block network egress from affected systems while assessment is underway."
                    },
                    {
                        "phase": "Eradication",
                        "action": "Remove or quarantine the compromised software.",
                        "details": "Do not simply update — attackers may have left behind persistent backdoors."
                    },
                    {
                        "phase": "Investigation",
                        "action": "Audit all activity on affected systems since the software was installed.",
                        "details": "Check for lateral movement, data access, or new persistence mechanisms installed by the malicious update."
                    },
                    {
                        "phase": "Recovery",
                        "action": "Reinstall software from a verified clean source.",
                        "details": "Validate software hash against vendor-published checksums before deployment."
                    }
                ],
                "contacts": ["Vendor Management", "CISO Office", "IT Operations", "Legal/Compliance"]
            },

            # ── Cloud Abuse ───────────────────────────────────────────────────
            "Cloud API Abuse": {
                "title": "Cloud API Abuse & Credential Misuse Response",
                "severity": "High",
                "mitre_techniques": ["T1528", "T1078"],
                "event_types": ["CLOUD_API"],
                "steps": [
                    {
                        "phase": "Containment",
                        "action": "Revoke the compromised API keys and access tokens immediately.",
                        "details": "Rotate IAM credentials; revoke OAuth tokens and session tokens in the cloud console."
                    },
                    {
                        "phase": "Investigation",
                        "action": "Review CloudTrail / Azure Activity Logs for all actions taken.",
                        "details": "Identify resources created, accessed, or deleted. Check for IAM role changes."
                    },
                    {
                        "phase": "Eradication",
                        "action": "Delete any resources created by the attacker.",
                        "details": "Remove unauthorized IAM users, roles, EC2 instances, and storage buckets."
                    },
                    {
                        "phase": "Hardening",
                        "action": "Enforce MFA for all cloud console and API access.",
                        "details": "Apply AWS SCP / Azure Policy to deny access without MFA."
                    },
                    {
                        "phase": "Hardening",
                        "action": "Implement cloud-native anomaly detection.",
                        "details": "Enable AWS GuardDuty, Azure Sentinel, or GCP Security Command Center."
                    }
                ],
                "contacts": ["Cloud Platform Team", "Security Operations", "CISO Office"]
            },

            # ── Shadow Copy / Anti-Recovery ───────────────────────────────────
            "Anti-Forensics / Shadow Copy Deletion": {
                "title": "Anti-Forensics & Recovery Inhibition Response",
                "severity": "Critical",
                "mitre_techniques": ["T1490", "T1070", "T1485"],
                "event_types": ["EXECUTION_SUSPICIOUS", "FILE_DELETE"],
                "steps": [
                    {
                        "phase": "Assessment",
                        "action": "Determine what backup/recovery data has been destroyed.",
                        "details": "Check VSS availability: vssadmin list shadows. Audit backup logs."
                    },
                    {
                        "phase": "Containment",
                        "action": "Isolate affected systems to prevent further deletion.",
                        "details": "Network isolation preserves remaining data and prevents attacker commands from executing."
                    },
                    {
                        "phase": "Recovery",
                        "action": "Attempt recovery from offline/air-gapped backup systems.",
                        "details": "Prioritize backup sources that were not connected during the incident window."
                    },
                    {
                        "phase": "Investigation",
                        "action": "Identify the process and user that issued deletion commands.",
                        "details": "Correlate vssadmin/wbadmin/bcdedit execution with process creation logs."
                    },
                    {
                        "phase": "Hardening",
                        "action": "Implement immutable backup strategy (WORM storage).",
                        "details": "Use cloud backup with object lock / retention policies that cannot be altered by admin accounts."
                    }
                ],
                "contacts": ["Backup & Recovery Team", "Security Operations", "CISO Office"]
            },

            # ── Network / USB ─────────────────────────────────────────────────
            "Suspicious Network Activity": {
                "title": "Network Anomaly Investigation",
                "severity": "Medium",
                "mitre_techniques": ["T1071", "T1095", "T1572"],
                "event_types": ["NETWORK_CONN", "DNS_QUERY", "FIREWALL"],
                "steps": [
                    {
                        "phase": "Investigation",
                        "action": "DPI (Deep Packet Inspection) of traffic.",
                        "details": "Look for non-standard protocol usage on port 443 or 53."
                    },
                    {
                        "phase": "Investigation",
                        "action": "Analyze DNS query length and frequency for tunneling indicators.",
                        "details": "Unusually long subdomain queries or high query rates suggest DNS tunneling."
                    },
                    {
                        "phase": "Mitigation",
                        "action": "Update EDR/IDS signatures.",
                        "details": "Apply pattern matching for the identified traffic signature."
                    }
                ],
                "contacts": ["Network Ops", "Threat Intel Team"]
            },

            "Policy Violation (Unauthorized USB Usage)": {
                "title": "General Policy Violation",
                "severity": "Low",
                "mitre_techniques": ["T1092", "T1025"],
                "event_types": ["USB"],
                "steps": [
                    {
                        "phase": "Notification",
                        "action": "Email user regarding unauthorized peripheral usage.",
                        "details": "Automated security awareness training link included."
                    },
                    {
                        "phase": "Remediation",
                        "action": "Scan host for malware introduced via USB.",
                        "details": "Full system scan with deep heuristic analysis."
                    }
                ],
                "contacts": ["IT Support", "Security Education Team"]
            },

            # ── Generic ───────────────────────────────────────────────────────
            "Suspicious Activity": {
                "title": "Generic Security Incident Response",
                "severity": "Medium",
                "mitre_techniques": [],
                "event_types": [],
                "steps": [
                    {
                        "phase": "Initial Response",
                        "action": "Snapshot the virtual machine / host state.",
                        "details": "Capture memory and disk state before any intervention."
                    },
                    {
                        "phase": "Assessment",
                        "action": "Qualify severity and impact.",
                        "details": "Determine if this is a true positive or false positive."
                    }
                ],
                "contacts": ["On-call Analyst"]
            }
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Rule-based: get exact playbook for incident type
    # ──────────────────────────────────────────────────────────────────────────
    def get_playbook(self, incident_type: str, events: list) -> dict:
        pb = self.playbooks.get(incident_type, self.playbooks["Suspicious Activity"])

        # Inject context (impacted hosts, bad IPs)
        victims = list(set([e.get("hostname") for e in events if e.get("hostname")]))
        bad_ips = list(set([e.get("ip") for e in events if e.get("ip")]))

        # Deep-copy steps to avoid mutating the template
        import copy
        pb = copy.deepcopy(pb)

        if victims and pb["steps"]:
            pb["steps"][0]["details"] += f" (Impacted Hosts: {', '.join(victims[:3])})"
        if bad_ips:
            for step in pb["steps"]:
                if "IP" in step.get("action", "") or "IP" in step.get("details", ""):
                    step["details"] += f" (Identified IPs: {', '.join(bad_ips[:3])})"

        return pb

    # ──────────────────────────────────────────────────────────────────────────
    # Rule-based: score & rank all relevant playbooks for a case
    # ──────────────────────────────────────────────────────────────────────────
    def suggest_playbooks(self, events: list, incident_type: str, mitre_techniques: list) -> list:
        """
        Score every playbook against the current case's event types and MITRE
        techniques, returning a ranked list of suggestions with a match score.
        """
        import copy

        event_type_counts = Counter(e.get("type", "OTHER") for e in events)
        detected_event_types = set(event_type_counts.keys())
        detected_mitre = set()
        for t in mitre_techniques:
            # mitre_techniques is a list of strings like "T1110 – Brute Force"
            tid = t.split("–")[0].strip() if "–" in t else t.strip()
            detected_mitre.add(tid)

        suggestions = []

        for name, pb in self.playbooks.items():
            score = 0
            matched_event_types = []
            matched_mitre = []

            # Score: direct incident type match
            if name == incident_type:
                score += 50

            # Score: event type overlap
            for et in pb.get("event_types", []):
                if et in detected_event_types:
                    score += event_type_counts.get(et, 0) * 2
                    matched_event_types.append(et)

            # Score: MITRE technique overlap
            for tid in pb.get("mitre_techniques", []):
                if tid in detected_mitre:
                    score += 15
                    matched_mitre.append(tid)

            if score == 0:
                continue

            # Confidence: cap at 100%
            confidence = min(round((score / max(score, 60)) * 100), 99)

            suggestion = copy.deepcopy(pb)
            suggestion["playbook_name"] = name
            suggestion["match_score"] = score
            suggestion["confidence_pct"] = confidence
            suggestion["matched_event_types"] = matched_event_types
            suggestion["matched_mitre_techniques"] = matched_mitre

            # Inject contextual data
            victims = list(set([e.get("hostname") for e in events if e.get("hostname")]))
            bad_ips = list(set([e.get("ip") for e in events if e.get("ip")]))
            if victims and suggestion["steps"]:
                suggestion["steps"][0]["details"] += f" (Impacted Hosts: {', '.join(victims[:3])})"
            if bad_ips:
                for step in suggestion["steps"]:
                    if "IP" in step.get("action", "") or "IP" in step.get("details", ""):
                        step["details"] += f" (Identified IPs: {', '.join(bad_ips[:3])})"

            suggestions.append(suggestion)

        # Sort by score descending, return top 5
        suggestions.sort(key=lambda x: x["match_score"], reverse=True)
        return suggestions[:5]
