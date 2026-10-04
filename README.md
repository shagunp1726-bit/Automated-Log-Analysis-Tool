# 🔐 ForensicLens – Automated Digital Forensics & Incident Reconstruction System

ForensicLens is a web-based digital forensics platform designed to automate post-incident investigations. The system analyzes authentication, system, USB, and network logs to reconstruct incident timelines, detect attacks, assess severity, and generate professional forensic reports.


## 🚀 Features

- 🔍 Multi-log analysis (authentication, system, USB, network logs)
- 🧠 Brute force attack detection
- 🕒 Incident timeline reconstruction
- 📊 Risk scoring and severity classification
- 🧾 Dynamic, evidence-driven attack narrative generation
- 📄 Automated PDF forensic report generation
- 📊 Advanced SIEM Investigation Workspace (Visual Hunt, AI Copilot, Rule Engine)


## 🛠️ Technology Stack

| Component       | Technology            |
|-----------------|-----------------------|
| Backend         | Python                |
| Web Framework   | Flask                 |
| Frontend        | HTML, CSS, JavaScript |
| Visualization   | Chart.js              |
| PDF Reports     | ReportLab             |
| Security        | SHA-256 hashing       |



## 📁 Project Structure
FORENSICLENS/
│
├── app.py                     # Main Flask application entry point
├── requirements.txt           # Python dependencies
├── README.md                  # Project documentation
│
├── modules/                   # Core forensic analysis logic
│   ├── __pycache__/            # Compiled Python cache files
│   │
│   ├── auth_detector.py        # Authentication anomaly detection
│   ├── hash_integrity.py       # File hash validation & integrity checks
│   ├── incident_analyzer.py   # Central incident correlation engine
│   ├── mitre_mapper.py        # MITRE ATT&CK technique mapping
│   ├── narrative_generator.py # Human-readable investigation narrative
│   ├── parser.py              # Log & evidence parsing logic
│   ├── report_generator.py    # PDF/HTML forensic report generation
│   ├── risk_engine.py         # Risk scoring & threat prioritization
│   ├── severity_explainer.py  # Severity justification & explanation
│   ├── timeline.py            # Event timeline reconstruction
│   └── workspace_manager.py   # Case/workspace handling & isolation
│
├── sample_logs/               # Forensic sample logs for testing & demonstrations
│   ├── windows_attack.log     # Windows APT, Sysmon, Mimikatz, USB exfiltration
│   ├── linux_system.log       # Linux SSH brute force, Sudo abuse, Cron, Auditd
│   ├── android_logcat.log     # Android Logcat, Trojan sideload, SELinux denials
│   ├── enterprise_attack.log  # Multi-stage enterprise attack scenario
│   └── attack_scenario.log    # End-to-end cyber incident reconstruction
│
├── static/                    # Static frontend assets
│   └── style.css              # Global UI styling
│
└── templates/                 # HTML templates (Jinja2)
    ├── index.html             # Landing & upload page (with 1-click sample loaders)
    ├── siem.html              # Advanced SIEM workspace
    ├── dashboard.html         # Investigation dashboard
    └── chain_of_custody.html  # Evidence custody tracking


## 📂 Forensic Sample Logs

ForensicLens comes bundled with sample logs across multiple operating systems:

- **🪟 Windows (`sample_logs/windows_attack.log`)**: Emulates an advanced cyber intrusion with web attacks, brute force (Event 4625), logon success (Event 4624), privilege elevation (Event 4672), encoded PowerShell execution, C2 beaconing (Sysmon Event 3), Mimikatz LSASS credential dumping, lateral movement, USB exfiltration, and anti-forensic log clearing.
- **🐧 Linux (`sample_logs/linux_system.log`)**: Captures Linux server attacks including multi-account SSH brute force, credential compromise, PAM session logging, Sudo root privilege escalation, curl dropper download, Cron persistence, iptables firewall blocks, and Linux Audit (`USER_LOGIN`, `EXECVE`) records.
- **🤖 Android (`sample_logs/android_logcat.log`)**: Models a mobile banking trojan / spyware infection using standard Android Logcat formatting (`threadtime` & `brief`), covering sideloaded package installation (`PackageManager`), trojan launch (`ActivityManager`), SELinux mandatory access control violations (`avc: denied`), anti-virus package removal, and fatal runtime security exceptions.

You can analyze these samples with **1-click** directly from the home page or upload them manually.





## ⚙️ Installation & Setup

 Clone or download the project

git clone https://github.com/mishu1507/ForensicLens
cd ForensicLens

pip install -r requirements.txt
Run the application

python app.py
Open the application in your browser

http://127.0.0.1:5000