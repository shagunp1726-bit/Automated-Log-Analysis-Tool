

# ──────────────────────────────────────────────
# MITRE ATT&CK Tactic definitions
# ──────────────────────────────────────────────
TACTICS = {
    "TA0001": {"name": "Initial Access", "short": "initial-access"},
    "TA0002": {"name": "Execution", "short": "execution"},
    "TA0003": {"name": "Persistence", "short": "persistence"},
    "TA0004": {"name": "Privilege Escalation", "short": "priv-escalation"},
    "TA0005": {"name": "Defense Evasion", "short": "defense-evasion"},
    "TA0006": {"name": "Credential Access", "short": "credential-access"},
    "TA0007": {"name": "Discovery", "short": "discovery"},
    "TA0008": {"name": "Lateral Movement", "short": "lateral-movement"},
    "TA0009": {"name": "Collection", "short": "collection"},
    "TA0010": {"name": "Exfiltration", "short": "exfiltration"},
    "TA0011": {"name": "Command and Control", "short": "c2"},
    "TA0040": {"name": "Impact", "short": "impact"},
    "TA0042": {"name": "Resource Development", "short": "resource-dev"},
    "TA0043": {"name": "Reconnaissance", "short": "recon"},
}


# ──────────────────────────────────────────────
# Technique → Tactic mapping with detection rules
# ──────────────────────────────────────────────
TECHNIQUES = {
    # ── Reconnaissance (TA0043) ──────────────────────────────────────────────
    "T1595": {
        "name": "Active Scanning",
        "tactic_ids": ["TA0043"],
        "keywords": ["port scan", "nmap", "masscan", "shodan", "active scan",
                     "network scan", "vulnerability scan", "zmap"],
        "event_types": [],
        "severity": "medium",
        "description": "Adversaries scan victim infrastructure to gather actionable information."
    },
    "T1592": {
        "name": "Gather Victim Host Information",
        "tactic_ids": ["TA0043"],
        "keywords": ["host enumeration", "os fingerprint", "banner grab",
                     "service banner", "version detection"],
        "event_types": [],
        "severity": "low",
        "description": "Gathering information about victim hosts before attack."
    },
    "T1589": {
        "name": "Gather Victim Identity Information",
        "tactic_ids": ["TA0043"],
        "keywords": ["credential harvesting", "email harvesting", "linkedin",
                     "osint", "identity enumeration"],
        "event_types": [],
        "severity": "low",
        "description": "Collecting identity information (credentials, emails) about the victim."
    },
    "T1590": {
        "name": "Gather Victim Network Information",
        "tactic_ids": ["TA0043"],
        "keywords": ["whois", "dns enumeration", "network topology",
                     "ip range", "asn lookup", "traceroute"],
        "event_types": [],
        "severity": "low",
        "description": "Gathering information about the victim's network infrastructure."
    },

    # ── Resource Development (TA0042) ────────────────────────────────────────
    "T1583": {
        "name": "Acquire Infrastructure",
        "tactic_ids": ["TA0042"],
        "keywords": ["c2 server", "vps", "bulletproof hosting", "domain registration",
                     "infrastructure setup"],
        "event_types": [],
        "severity": "medium",
        "description": "Acquiring infrastructure (servers, domains) for operations."
    },
    "T1584": {
        "name": "Compromise Infrastructure",
        "tactic_ids": ["TA0042"],
        "keywords": ["compromised server", "hijacked domain", "botnet",
                     "third-party infrastructure"],
        "event_types": [],
        "severity": "high",
        "description": "Compromising third-party infrastructure for use in operations."
    },
    "T1588": {
        "name": "Obtain Capabilities",
        "tactic_ids": ["TA0042"],
        "keywords": ["exploit kit", "malware purchase", "tool download",
                     "exploit acquisition", "dark web"],
        "event_types": [],
        "severity": "medium",
        "description": "Obtaining tools, exploits, or malware for use in operations."
    },

    # ── Initial Access ───────────────────────────────────────────────────────
    "T1078": {
        "name": "Valid Accounts",
        "tactic_ids": ["TA0001", "TA0003", "TA0004", "TA0005"],
        "keywords": ["login successful", "accepted password", "valid credentials",
                     "authenticated successfully", "event_id=4624"],
        "event_types": ["AUTH_SUCCESS"],
        "severity": "medium",
        "description": "Adversaries may use valid accounts to gain initial access."
    },
    "T1133": {
        "name": "External Remote Services",
        "tactic_ids": ["TA0001", "TA0003"],
        "keywords": ["rdp", "ssh", "vpn", "remote desktop", "remote access"],
        "event_types": [],
        "severity": "medium",
        "description": "Leveraging external-facing remote services for access."
    },
    "T1566": {
        "name": "Phishing",
        "tactic_ids": ["TA0001"],
        "keywords": ["phishing", "spearphishing", "malicious attachment",
                     "suspicious email", "macro enabled"],
        "event_types": [],
        "severity": "high",
        "description": "Adversaries send phishing messages to gain access."
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic_ids": ["TA0001"],
        "keywords": ["sql injection", "rce", "remote code execution", "exploit",
                     "cve-", "webshell uploaded", "directory traversal", "../",
                     "union select", "log4j", "shellshock"],
        "event_types": ["WEB_ATTACK"],
        "severity": "critical",
        "description": "Exploiting a weakness in an internet-facing application."
    },
    "T1091": {
        "name": "Replication Through Removable Media",
        "tactic_ids": ["TA0001", "TA0008"],
        "keywords": ["usb autorun", "autorun.inf", "removable media execute",
                     "usb spread"],
        "event_types": ["USB"],
        "severity": "high",
        "description": "Spreading malware via removable media."
    },
    "T1195": {
        "name": "Supply Chain Compromise",
        "tactic_ids": ["TA0001"],
        "keywords": ["supply chain", "software update", "trojanized",
                     "compromised package", "dependency confusion"],
        "event_types": [],
        "severity": "critical",
        "description": "Compromising software supply chain to gain access."
    },

    # ── Execution ────────────────────────────────────────────────────────────
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic_ids": ["TA0002"],
        "keywords": ["powershell", "cmd.exe", "bash", "python", "wscript",
                     "cscript", "mshta", "invoke-expression"],
        "event_types": ["PROCESS_CREATE", "EXECUTION_SUSPICIOUS"],
        "severity": "high",
        "description": "Command-line interpreters used to execute commands."
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic_ids": ["TA0002"],
        "keywords": ["powershell", "pwsh", "invoke-", "downloadstring",
                     "-encodedcommand", "-enc ", "iex("],
        "event_types": ["EXECUTION_SUSPICIOUS"],
        "severity": "critical",
        "description": "PowerShell used for execution of commands and scripts."
    },
    "T1204": {
        "name": "User Execution",
        "tactic_ids": ["TA0002"],
        "keywords": ["user executed", "double-click", "opened attachment"],
        "event_types": [],
        "severity": "medium",
        "description": "Adversary relies on user to execute malicious content."
    },
    "T1569": {
        "name": "System Services",
        "tactic_ids": ["TA0002"],
        "keywords": ["sc exec", "service exec", "psexec", "winrm exec",
                     "service control", "at command"],
        "event_types": ["PROCESS_CREATE"],
        "severity": "high",
        "description": "Using system services or daemons to execute commands."
    },
    "T1106": {
        "name": "Native API",
        "tactic_ids": ["TA0002"],
        "keywords": ["winapi", "createprocess", "shellexecute",
                     "virtualalloc", "rtlcreateuserthread", "native api"],
        "event_types": ["PROCESS_CREATE"],
        "severity": "high",
        "description": "Directly invoking native OS APIs for execution."
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "tactic_ids": ["TA0002"],
        "keywords": ["cmd.exe", "command prompt", "cmd /c", "cmd /k",
                     "comspec"],
        "event_types": ["PROCESS_CREATE", "EXECUTION_SUSPICIOUS"],
        "severity": "high",
        "description": "Using cmd.exe to execute commands."
    },
    "T1059.004": {
        "name": "Unix Shell",
        "tactic_ids": ["TA0002"],
        "keywords": ["bash -c", "/bin/sh", "/bin/bash", "sh -i",
                     "bash -i", "reverse shell"],
        "event_types": ["PROCESS_CREATE"],
        "severity": "high",
        "description": "Using Unix shell interpreters to execute commands."
    },

    # ── Persistence ──────────────────────────────────────────────────────────
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic_ids": ["TA0002", "TA0003", "TA0004"],
        "keywords": ["scheduled task", "cron", "at job", "schtasks",
                     "systemd timer"],
        "event_types": [],
        "severity": "high",
        "description": "Abuse task scheduling for persistence or execution."
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic_ids": ["TA0003", "TA0004"],
        "keywords": ["autostart", "startup folder", "run key", "registry run",
                     "init.d", "systemd enable"],
        "event_types": ["REGISTRY"],
        "severity": "high",
        "description": "Configuring settings to execute on boot or logon."
    },
    "T1543": {
        "name": "Create or Modify System Process",
        "tactic_ids": ["TA0003", "TA0004"],
        "keywords": ["service created", "service installed", "sc create",
                     "systemctl", "daemon"],
        "event_types": [],
        "severity": "high",
        "description": "Creating system services for persistence."
    },
    "T1136": {
        "name": "Create Account",
        "tactic_ids": ["TA0003"],
        "keywords": ["useradd", "adduser", "net user /add", "new user created",
                     "account created", "event_id=4720", "create account"],
        "event_types": ["ACCOUNT_CHANGE"],
        "severity": "high",
        "description": "Creating accounts to maintain persistent access."
    },
    "T1098": {
        "name": "Account Manipulation",
        "tactic_ids": ["TA0003", "TA0004"],
        "keywords": ["group membership changed", "user added to group",
                     "admin group", "event_id=4728", "event_id=4732",
                     "account modified", "privilege granted"],
        "event_types": ["ACCOUNT_CHANGE"],
        "severity": "high",
        "description": "Manipulating accounts to maintain access."
    },
    "T1505": {
        "name": "Server Software Component",
        "tactic_ids": ["TA0003"],
        "keywords": ["webshell", "web shell", "aspx shell", "php shell",
                     "jsp shell", "chopper", "c99", "r57"],
        "event_types": ["FILE_CREATE", "WEB_ATTACK"],
        "severity": "critical",
        "description": "Installing web shells or backdoors on web servers."
    },
    "T1176": {
        "name": "Browser Extensions",
        "tactic_ids": ["TA0003"],
        "keywords": ["browser extension", "chrome extension", "firefox addon",
                     "extension install"],
        "event_types": [],
        "severity": "medium",
        "description": "Installing malicious browser extensions for persistence."
    },

    # ── Privilege Escalation ─────────────────────────────────────────────────
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic_ids": ["TA0004", "TA0005"],
        "keywords": ["sudo", "su ", "runas", "uac bypass", "setuid",
                     "privilege escalation", "elevated"],
        "event_types": ["PRIV_ESCALATION"],
        "severity": "critical",
        "description": "Bypassing elevation controls to gain higher privileges."
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic_ids": ["TA0004"],
        "keywords": ["local exploit", "kernel exploit", "privilege exploit",
                     "lpe", "dirty cow", "local privilege", "exploit priv"],
        "event_types": [],
        "severity": "critical",
        "description": "Exploiting vulnerabilities to gain elevated permissions."
    },
    "T1134": {
        "name": "Access Token Manipulation",
        "tactic_ids": ["TA0004", "TA0005"],
        "keywords": ["token impersonation", "token duplication", "impersonate",
                     "seimpersonateprivilege", "token manipulation", "runas token"],
        "event_types": ["PRIV_ESCALATION"],
        "severity": "critical",
        "description": "Manipulating access tokens to escalate privileges."
    },

    # ── Defense Evasion ──────────────────────────────────────────────────────
    "T1070": {
        "name": "Indicator Removal",
        "tactic_ids": ["TA0005"],
        "keywords": ["clear log", "delete log", "wevtutil cl", "rm -rf /var/log",
                     "event log cleared", "file deleted", "shred"],
        "event_types": ["FILE_DELETE"],
        "severity": "critical",
        "description": "Deleting or modifying artifacts to cover tracks."
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic_ids": ["TA0005"],
        "keywords": ["encoded", "base64", "obfuscated", "packed",
                     "encrypted payload"],
        "event_types": ["EXECUTION_SUSPICIOUS"],
        "severity": "high",
        "description": "Obfuscating content to evade security defenses."
    },
    "T1036": {
        "name": "Masquerading",
        "tactic_ids": ["TA0005"],
        "keywords": ["masquerade", "renamed binary", "fake process name"],
        "event_types": [],
        "severity": "high",
        "description": "Manipulating features of artifacts to look legitimate."
    },
    "T1055": {
        "name": "Process Injection",
        "tactic_ids": ["TA0005", "TA0004"],
        "keywords": ["process injection", "dll injection", "code injection",
                     "hollowing", "process hollow", "shellcode inject",
                     "createremotethread", "writeprocessmemory"],
        "event_types": ["PROCESS_CREATE"],
        "severity": "critical",
        "description": "Injecting code into processes to evade defenses."
    },
    "T1218": {
        "name": "System Binary Proxy Execution",
        "tactic_ids": ["TA0005"],
        "keywords": ["rundll32", "regsvr32", "mshta", "certutil",
                     "odbcconf", "ieexec", "mavinject", "wmic exec"],
        "event_types": ["EXECUTION_SUSPICIOUS"],
        "severity": "high",
        "description": "Using trusted system binaries as proxies for malicious execution."
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactic_ids": ["TA0005"],
        "keywords": ["disable antivirus", "disable firewall", "disable defender",
                     "tamper protection", "av disable", "security disabled",
                     "event_id=4689", "auditpol", "disable logging"],
        "event_types": [],
        "severity": "critical",
        "description": "Disabling or tampering with security tools and logging."
    },
    "T1112": {
        "name": "Modify Registry",
        "tactic_ids": ["TA0005"],
        "keywords": ["reg add", "reg delete", "registry modified", "regedit",
                     "regkey", "hkcu\\\\", "hklm\\\\", "event_id=4657"],
        "event_types": ["REGISTRY"],
        "severity": "high",
        "description": "Modifying the registry to hide or persist configurations."
    },
    "T1564": {
        "name": "Hide Artifacts",
        "tactic_ids": ["TA0005"],
        "keywords": ["hidden file", "attrib +h", "hidden attribute",
                     "alternate data stream", "ads", "hidden directory"],
        "event_types": ["FILE_CREATE"],
        "severity": "high",
        "description": "Hiding artifacts to evade detection."
    },

    # ── Credential Access ────────────────────────────────────────────────────
    "T1110": {
        "name": "Brute Force",
        "tactic_ids": ["TA0006"],
        "keywords": ["brute force", "failed login", "failed password",
                     "authentication failure", "multiple failed",
                     "invalid credentials", "event_id=4625"],
        "event_types": ["AUTH_FAIL"],
        "severity": "high",
        "description": "Systematically guessing credentials through brute force."
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic_ids": ["TA0006"],
        "keywords": ["mimikatz", "lsass", "sam dump", "credential dump",
                     "procdump", "sekurlsa", "hashdump"],
        "event_types": [],
        "severity": "critical",
        "description": "Dumping credentials from the operating system."
    },
    "T1555": {
        "name": "Credentials from Password Stores",
        "tactic_ids": ["TA0006"],
        "keywords": ["password store", "keychain", "credential store",
                     "browser password", "saved password", "keepass",
                     "lastpass", "1password"],
        "event_types": [],
        "severity": "high",
        "description": "Extracting credentials from password managers or keystores."
    },
    "T1056": {
        "name": "Input Capture",
        "tactic_ids": ["TA0006", "TA0009"],
        "keywords": ["keylogger", "keystroke", "keyboard capture",
                     "input capture", "credential intercept", "hooking"],
        "event_types": ["MALWARE_INDICATOR"],
        "severity": "critical",
        "description": "Capturing user input such as keystrokes or credentials."
    },
    "T1539": {
        "name": "Steal Web Session Cookie",
        "tactic_ids": ["TA0006"],
        "keywords": ["cookie theft", "session hijack", "stolen cookie",
                     "cookie exfil", "session token"],
        "event_types": [],
        "severity": "high",
        "description": "Stealing web session cookies to authenticate as a user."
    },
    "T1528": {
        "name": "Steal Application Access Token",
        "tactic_ids": ["TA0006"],
        "keywords": ["oauth token", "access token stolen", "api token",
                     "bearer token", "jwt stolen"],
        "event_types": [],
        "severity": "high",
        "description": "Stealing OAuth or application access tokens."
    },

    # ── Discovery ─────────────────────────────────────────────────────────────
    "T1087": {
        "name": "Account Discovery",
        "tactic_ids": ["TA0007"],
        "keywords": ["net user", "whoami", "id ", "getent passwd",
                     "ldap query", "enumeration"],
        "event_types": [],
        "severity": "medium",
        "description": "Attempting to enumerate accounts on the system."
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic_ids": ["TA0007"],
        "keywords": ["port scan", "nmap", "service scan", "network scan"],
        "event_types": [],
        "severity": "high",
        "description": "Scanning for network services running on remote hosts."
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic_ids": ["TA0007"],
        "keywords": ["systeminfo", "uname", "hostname", "os version",
                     "system information"],
        "event_types": [],
        "severity": "low",
        "description": "Gathering detailed system information."
    },
    "T1057": {
        "name": "Process Discovery",
        "tactic_ids": ["TA0007"],
        "keywords": ["tasklist", "ps aux", "process list", "get-process"],
        "event_types": [],
        "severity": "low",
        "description": "Gathering information about running processes."
    },
    "T1092": {
        "name": "Communication Through Removable Media",
        "tactic_ids": ["TA0011"],
        "keywords": ["usb", "removable media", "mass storage", "thumb drive"],
        "event_types": ["USB"],
        "severity": "high",
        "description": "Using removable media for command and control."
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic_ids": ["TA0007"],
        "keywords": ["dir /s", "ls -la", "find /", "tree /", "get-childitem",
                     "dir listing", "enumerate files"],
        "event_types": [],
        "severity": "low",
        "description": "Enumerating files and directories on the system."
    },
    "T1135": {
        "name": "Network Share Discovery",
        "tactic_ids": ["TA0007"],
        "keywords": ["net share", "net view", "smb share", "cifs",
                     "smbclient", "network share"],
        "event_types": [],
        "severity": "medium",
        "description": "Discovering network shares on remote systems."
    },
    "T1018": {
        "name": "Remote System Discovery",
        "tactic_ids": ["TA0007"],
        "keywords": ["net view", "ping sweep", "arp scan", "network discovery",
                     "host discovery", "nbtscan"],
        "event_types": [],
        "severity": "medium",
        "description": "Discovering remote systems on the network."
    },
    "T1049": {
        "name": "System Network Connections Discovery",
        "tactic_ids": ["TA0007"],
        "keywords": ["netstat", "ss -anp", "get-netconnection",
                     "network connections", "active connections"],
        "event_types": [],
        "severity": "low",
        "description": "Enumerating active network connections."
    },

    # ── Lateral Movement ─────────────────────────────────────────────────────
    "T1021": {
        "name": "Remote Services",
        "tactic_ids": ["TA0008"],
        "keywords": ["rdp session", "ssh to", "psexec", "winrm",
                     "lateral movement", "remote login"],
        "event_types": [],
        "severity": "high",
        "description": "Using remote services to move laterally."
    },
    "T1550": {
        "name": "Use Alternate Authentication Material",
        "tactic_ids": ["TA0008", "TA0005"],
        "keywords": ["pass the hash", "pass the ticket", "pth", "ptt",
                     "golden ticket", "silver ticket", "kerberoast",
                     "overpass the hash"],
        "event_types": [],
        "severity": "critical",
        "description": "Using stolen credentials/hashes for lateral movement."
    },
    "T1210": {
        "name": "Exploitation of Remote Services",
        "tactic_ids": ["TA0008"],
        "keywords": ["eternalblue", "ms17-010", "smb exploit",
                     "remote exploit", "lateral exploit"],
        "event_types": [],
        "severity": "critical",
        "description": "Exploiting remote services to move laterally."
    },

    # ── Collection ───────────────────────────────────────────────────────────
    "T1005": {
        "name": "Data from Local System",
        "tactic_ids": ["TA0009"],
        "keywords": ["file copied", "data collection", "staging",
                     "sensitive file", "data gathered"],
        "event_types": ["FILE_COPY"],
        "severity": "high",
        "description": "Collecting data from the local system."
    },
    "T1113": {
        "name": "Screen Capture",
        "tactic_ids": ["TA0009"],
        "keywords": ["screenshot", "screen capture", "printscreen",
                     "snipping tool", "screengrab"],
        "event_types": [],
        "severity": "medium",
        "description": "Capturing screenshots of the victim's screen."
    },
    "T1114": {
        "name": "Email Collection",
        "tactic_ids": ["TA0009"],
        "keywords": ["email collection", "mailbox access", "pst export",
                     "outlook data", "email exfil", "ews access"],
        "event_types": [],
        "severity": "high",
        "description": "Collecting email data from victims."
    },
    "T1560": {
        "name": "Archive Collected Data",
        "tactic_ids": ["TA0009"],
        "keywords": ["zip archive", "rar archive", "7zip", "tar compress",
                     "data archive", "compress before exfil"],
        "event_types": [],
        "severity": "medium",
        "description": "Compressing/archiving collected data before exfiltration."
    },
    "T1025": {
        "name": "Data from Removable Media",
        "tactic_ids": ["TA0009"],
        "keywords": ["usb data", "copy from usb", "removable media read"],
        "event_types": ["USB"],
        "severity": "high",
        "description": "Collecting data from connected removable media."
    },

    # ── Exfiltration ─────────────────────────────────────────────────────────
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic_ids": ["TA0010"],
        "keywords": ["exfiltration", "data transfer", "upload to",
                     "outbound data", "data exfil"],
        "event_types": ["NETWORK_CONN"],
        "severity": "critical",
        "description": "Stealing data over an existing C2 channel."
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic_ids": ["TA0010"],
        "keywords": ["dns tunnel", "dns exfil", "icmp tunnel", "ftp upload"],
        "event_types": [],
        "severity": "critical",
        "description": "Exfiltrating data over non-standard protocols."
    },
    "T1567": {
        "name": "Exfiltration Over Web Service",
        "tactic_ids": ["TA0010"],
        "keywords": ["dropbox upload", "pastebin", "github upload",
                     "google drive upload", "onedrive", "exfil web"],
        "event_types": ["NETWORK_CONN"],
        "severity": "high",
        "description": "Exfiltrating data to public web services."
    },
    "T1020": {
        "name": "Automated Exfiltration",
        "tactic_ids": ["TA0010"],
        "keywords": ["automated exfil", "bulk transfer", "scheduled upload",
                     "cron exfil", "timed transfer"],
        "event_types": [],
        "severity": "high",
        "description": "Automatically exfiltrating data using scripts or tasks."
    },

    # ── Command and Control ──────────────────────────────────────────────────
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic_ids": ["TA0011"],
        "keywords": ["http beacon", "https callback", "c2 communication",
                     "beacon", "c2", "command and control"],
        "event_types": ["NETWORK_CONN", "MALWARE_INDICATOR"],
        "severity": "critical",
        "description": "Using application protocols for C2 communication."
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic_ids": ["TA0011"],
        "keywords": ["download tool", "wget ", "curl ", "certutil",
                     "bitsadmin", "tool transfer"],
        "event_types": ["EXECUTION_SUSPICIOUS"],
        "severity": "high",
        "description": "Transferring tools or files from external systems."
    },
    "T1572": {
        "name": "Protocol Tunneling",
        "tactic_ids": ["TA0011"],
        "keywords": ["ssh tunnel", "ssl tunnel", "dns tunnel",
                     "http tunnel", "port forward", "ngrok", "chisel"],
        "event_types": ["NETWORK_CONN"],
        "severity": "high",
        "description": "Tunneling C2 traffic inside legitimate protocols."
    },
    "T1573": {
        "name": "Encrypted Channel",
        "tactic_ids": ["TA0011"],
        "keywords": ["ssl c2", "tls c2", "encrypted c2", "https beacon",
                     "custom encryption", "encrypted channel"],
        "event_types": ["MALWARE_INDICATOR"],
        "severity": "high",
        "description": "Using encrypted channels for C2 to evade detection."
    },
    "T1095": {
        "name": "Non-Application Layer Protocol",
        "tactic_ids": ["TA0011"],
        "keywords": ["icmp c2", "udp beacon", "raw socket",
                     "non-http c2", "tcp raw"],
        "event_types": ["NETWORK_CONN"],
        "severity": "high",
        "description": "Using non-standard protocols for C2 communication."
    },
    "T1008": {
        "name": "Fallback Channels",
        "tactic_ids": ["TA0011"],
        "keywords": ["fallback c2", "backup c2", "secondary channel",
                     "alternate c2", "domain fronting"],
        "event_types": [],
        "severity": "medium",
        "description": "Using backup C2 channels for resilience."
    },

    # ── Impact ───────────────────────────────────────────────────────────────
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic_ids": ["TA0040"],
        "keywords": ["ransomware", "encrypted files", "ransom note",
                     "file encryption"],
        "event_types": ["MALWARE_INDICATOR"],
        "severity": "critical",
        "description": "Encrypting data to interrupt availability."
    },
    "T1489": {
        "name": "Service Stop",
        "tactic_ids": ["TA0040"],
        "keywords": ["service stopped", "service disabled", "sc stop",
                     "systemctl stop", "kill process"],
        "event_types": [],
        "severity": "high",
        "description": "Stopping services to impair system functionality."
    },
    "T1485": {
        "name": "Data Destruction",
        "tactic_ids": ["TA0040"],
        "keywords": ["data destruction", "wipe disk", "shred", "rm -rf",
                     "format drive", "data wiped", "overwrite data"],
        "event_types": ["FILE_DELETE"],
        "severity": "critical",
        "description": "Permanently destroying data to impair availability."
    },
    "T1491": {
        "name": "Defacement",
        "tactic_ids": ["TA0040"],
        "keywords": ["defacement", "website defaced", "web defacement",
                     "page replaced", "index replaced"],
        "event_types": ["FILE_MODIFY", "WEB_ATTACK"],
        "severity": "high",
        "description": "Modifying visual content to send a message or intimidate."
    },
    "T1498": {
        "name": "Network Denial of Service",
        "tactic_ids": ["TA0040"],
        "keywords": ["ddos", "dos attack", "flood attack", "syn flood",
                     "udp flood", "network flood", "amplification attack"],
        "event_types": ["NETWORK_CONN"],
        "severity": "critical",
        "description": "Flooding network resources to deny access."
    },
    "T1499": {
        "name": "Endpoint Denial of Service",
        "tactic_ids": ["TA0040"],
        "keywords": ["endpoint dos", "system crash", "bsod", "kernel panic",
                     "resource exhaustion", "fork bomb"],
        "event_types": [],
        "severity": "critical",
        "description": "Crashing or exhausting endpoint resources."
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic_ids": ["TA0040"],
        "keywords": ["delete shadow copy", "vssadmin delete", "bcdedit",
                     "disable recovery", "wbadmin delete", "shadowcopy delete"],
        "event_types": ["EXECUTION_SUSPICIOUS"],
        "severity": "critical",
        "description": "Deleting backups or shadow copies to prevent recovery."
    },
}


# ──────────────────────────────────────────────
# Attack chain templates
# ──────────────────────────────────────────────
ATTACK_CHAINS = [
    {
        "name": "Credential Compromise → Lateral Movement",
        "description": "Brute force followed by successful login and remote service usage",
        "sequence": ["T1110", "T1078", "T1021"],
        "severity": "critical"
    },
    {
        "name": "Execution → Persistence → C2",
        "description": "Suspicious execution leading to persistence mechanism and C2",
        "sequence": ["T1059", "T1547", "T1071"],
        "severity": "critical"
    },
    {
        "name": "Initial Access → Collection → Exfiltration",
        "description": "Account compromise followed by data collection and exfiltration",
        "sequence": ["T1078", "T1005", "T1041"],
        "severity": "critical"
    },
    {
        "name": "Privilege Escalation → Defense Evasion",
        "description": "Elevation of privileges followed by log clearing",
        "sequence": ["T1548", "T1070"],
        "severity": "critical"
    },
    {
        "name": "Discovery → Lateral Movement → Collection",
        "description": "Network discovery leading to lateral movement and data staging",
        "sequence": ["T1046", "T1021", "T1005"],
        "severity": "high"
    },
    {
        "name": "Web Exploitation → Persistence → Exfiltration",
        "description": "Web app exploit → webshell installation → data exfiltration",
        "sequence": ["T1190", "T1505", "T1041"],
        "severity": "critical"
    },
    {
        "name": "Ransomware Kill Chain",
        "description": "Phishing → execution → shadow copy deletion → encryption",
        "sequence": ["T1566", "T1059", "T1490", "T1486"],
        "severity": "critical"
    },
    {
        "name": "Pass-the-Hash → Remote Execution → Data Theft",
        "description": "Credential theft enabling lateral movement and collection",
        "sequence": ["T1003", "T1550", "T1021", "T1005"],
        "severity": "critical"
    },
    {
        "name": "Reconnaissance → Exploit → C2 Establish",
        "description": "Pre-attack scanning leading to exploitation and C2 setup",
        "sequence": ["T1595", "T1190", "T1071", "T1105"],
        "severity": "critical"
    },
    {
        "name": "Insider Threat: Privilege Abuse → Data Staging → Exfil",
        "description": "Privilege escalation leading to data collection and exfiltration via web service",
        "sequence": ["T1548", "T1005", "T1560", "T1567"],
        "severity": "critical"
    },
]


def map_mitre(events):
    """
    Map events to MITRE ATT&CK techniques.
    Updates each event in-place with mitre_tactics and mitre_techniques.
    Returns summary of unique techniques found.
    """
    techniques_found = set()

    for event in events:
        raw_lower = event.get("raw", "").lower()
        event_type = event.get("type", "")

        for tech_id, tech in TECHNIQUES.items():
            matched = False

            # Check by event type
            if event_type in tech.get("event_types", []):
                matched = True

            # Check by keywords
            if not matched:
                for kw in tech.get("keywords", []):
                    if kw in raw_lower:
                        matched = True
                        break

            if matched:
                techniques_found.add(tech_id)

                tech_entry = {
                    "id": tech_id,
                    "name": tech["name"],
                    "severity": tech["severity"],
                    "description": tech["description"]
                }
                if tech_entry not in event["mitre_techniques"]:
                    event["mitre_techniques"].append(tech_entry)

                for tactic_id in tech["tactic_ids"]:
                    tactic = TACTICS.get(tactic_id, {})
                    tactic_entry = {
                        "id": tactic_id,
                        "name": tactic.get("name", "Unknown"),
                    }
                    if tactic_entry not in event["mitre_tactics"]:
                        event["mitre_tactics"].append(tactic_entry)

    return [f"{tid} – {TECHNIQUES[tid]['name']}" for tid in techniques_found]


def get_mitre_heatmap_data(events):
    """
    Generate heatmap data: tactic × technique counts.
    Returns dict: {tactic_id: {technique_id: count}}
    """
    heatmap = {}

    for tactic_id in TACTICS:
        heatmap[tactic_id] = {}

    for event in events:
        for tech in event.get("mitre_techniques", []):
            tech_id = tech["id"]
            tech_def = TECHNIQUES.get(tech_id, {})
            for tactic_id in tech_def.get("tactic_ids", []):
                if tactic_id in heatmap:
                    heatmap[tactic_id][tech_id] = heatmap[tactic_id].get(tech_id, 0) + 1

    return heatmap


def detect_attack_chains(events):
    """
    Detect known attack chain patterns in event sequence.
    Returns list of detected chains with evidence.
    """
    detected_chains = []

    # Gather all techniques seen
    all_techniques = set()
    for event in events:
        for tech in event.get("mitre_techniques", []):
            all_techniques.add(tech["id"])
            # Also check parent technique (e.g. T1059.001 → T1059)
            parent = tech["id"].split(".")[0]
            all_techniques.add(parent)

    for chain in ATTACK_CHAINS:
        sequence = chain["sequence"]
        match_count = sum(1 for t in sequence if t in all_techniques)

        if match_count >= 2:  # At least 2 out of chain steps present
            completeness = match_count / len(sequence)
            detected_chains.append({
                "name": chain["name"],
                "description": chain["description"],
                "severity": chain["severity"],
                "matched_techniques": [t for t in sequence if t in all_techniques],
                "total_steps": len(sequence),
                "completeness": round(completeness * 100),
            })

    return detected_chains


def get_coverage_score(events):
    """
    Calculate MITRE ATT&CK coverage score.
    Returns: tactics covered, techniques detected, total counts.
    """
    tactics_seen = set()
    techniques_seen = set()

    for event in events:
        for tac in event.get("mitre_tactics", []):
            tactics_seen.add(tac["id"])
        for tech in event.get("mitre_techniques", []):
            techniques_seen.add(tech["id"])

    return {
        "tactics_covered": len(tactics_seen),
        "tactics_total": len(TACTICS),
        "techniques_detected": len(techniques_seen),
        "techniques_total": len(TECHNIQUES),
        "coverage_pct": round(len(tactics_seen) / len(TACTICS) * 100) if TACTICS else 0,
    }
