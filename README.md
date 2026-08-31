# Home SOC Lab — Windows Attack Detection & Response

A practical Security Operations Center (SOC) lab built to simulate, detect, investigate, and document a Windows-based attack using **Kali Linux, Windows 10 Pro, Sysmon, and Wazuh**.

---

## 🏗️ Lab Architecture

```text
Kali Linux
Attacker + Wazuh Manager
192.168.240.3
        │
        │ RDP Brute Force
        ▼
Windows 10 Pro
Target + Wazuh Agent
192.168.240.4
DESKTOP-SS2VKH0
        │
        ├── Windows Security Logs
        └── Sysmon Telemetry
                 │
                 ▼
           Wazuh Manager
                 │
                 ▼
          Wazuh Dashboard
```


---

## 🧰 Technologies Used

- **Kali Linux** — Attack simulation and Hydra
- **Windows 10 Pro** — Target endpoint
- **Sysmon** — Endpoint telemetry and process monitoring
- **Wazuh** — SIEM, detection, and log analysis
- **MITRE ATT&CK** — Attack technique mapping
- **VirtualBox** — Virtual lab environment

---

## 🔴 Simulated Attack Chain

```text
RDP Brute Force
       ↓
Credential Recovery
       ↓
Successful RDP Authentication
       ↓
PowerShell Execution
       ↓
Account/System Discovery
       ↓
Windows Event Log Clearing
```

---

# 🔎 Detection & Investigation

## 1. RDP Brute-Force Attack

Hydra was used from the Kali Linux VM to perform a controlled credential-guessing attack against the Windows RDP service.

### Command

```bash
hydra -L user.txt -P password.txt rdp://192.168.240.4
```

### Observations

- **Source:** `192.168.240.3`
- **Target:** `192.168.240.4`
- **Attempts:** 49
- **Event:** 4625 — Failed Logon
- **MITRE:** T1110 — Brute Force

---

## 2. Successful RDP Login

The recovered credentials were used to establish an RDP session.

- **Event:** 4624 — Successful Logon
- **Logon Type:** 10 — RemoteInteractive
- **Wazuh Rule:** 92653
- **User:** `WORKGROUP\nidhi`
- **MITRE:** T1021.001, T1078.003

---

## 3. PowerShell Execution

PowerShell was executed after the successful RDP login.

powershell
powershell.exe -Command "whoami"
- **Sysmon Event:** 1 — Process Create
- **Wazuh Rule:** 92027
- **MITRE:** T1059.001 — PowerShell

---

## 4. Account & System Discovery

PowerShell was used to perform account and system discovery.

- **Wazuh Rules:** 92033 / 92031
- **MITRE:** T1087 — Account Discovery

---

## 5. Scheduled Task Activity

Scheduled-task-related activity was detected during the post-access phase.

- **Wazuh Rule:** 92154
- **Telemetry:** `taskschd.dll`
- **MITRE:** T1053.005 — Scheduled Task/Job

---

## 6. Event Log Clearing

The Windows Application log was cleared using:

```powershell
wevtutil cl Application
---

# 🧠 MITRE ATT&CK Mapping

| Activity | MITRE Technique | ID | Wazuh Rule / Event |
|---|---|---|---|
| RDP Brute Force | Brute Force | T1110 | Event 4625 |
| Successful RDP | Remote Services: RDP | T1021.001 | 92653 / 4624 |
| Valid Account Usage | Valid Accounts: Local Accounts | T1078.003 | 4624 |
| PowerShell Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | 92027 |
| Account Discovery | Account Discovery | T1087 | 92033 / 92031 |
| Scheduled Task Activity | Scheduled Task/Job | T1053.005 | 92154 |
| Event Log Clearing | Indicator Removal: Clear Windows Event Logs | T1070.004 | 63104 / Event 104 |

---

# 🔗 Attack Investigation & Correlation

The individual events were investigated together using common attributes such as:

- Source IP
- Target IP
- Username
- Logon Type
- Event timestamps
- Sequence of activity

### Attack Timeline

```text
Kali Linux
192.168.240.3
       │
       ▼
RDP Failed Logons
Event 4625
       │
       ▼
Valid Credentials Recovered
nidhi / nidhi
       │
       ▼
Successful RDP Login
Event 4624
Logon Type 10
       │
       ▼
PowerShell
Sysmon Event 1
       │
       ▼
Discovery Activity
       │
       ▼
Scheduled Task Activity
       │
       ▼
Application Log Cleared
Event 104
```

The matching host, account, source address, and chronological sequence allowed the events to be investigated as a connected attack scenario.

---

# 🛡️ Incident Response

Recommended response actions for this type of incident include:

- Reset or disable the compromised account
- Terminate active RDP sessions
- Investigate the endpoint for suspicious processes and files
- Check for newly created scheduled tasks and persistence mechanisms
- Enable account lockout protections
- Enable Network Level Authentication (NLA) for RDP
- Restrict RDP access through VPNs or controlled jump hosts
- Use MFA for remote access where supported
- Preserve Windows Security and Sysmon logs
- Isolate the endpoint if malicious activity is confirmed

### Response Workflow

```text
Detection
   ↓
Validate Alert
   ↓
Investigate Events
   ↓
Identify Compromised Account
   ↓
Contain Access
   ↓
Check for Persistence
   ↓
Preserve Evidence
   ↓
Remediate
```

---

# 📊 SOC Skills Demonstrated

- Wazuh SIEM deployment and monitoring
- Wazuh Agent and Manager configuration
- Sysmon deployment and telemetry collection
- Windows Security Event Log analysis
- RDP attack detection
- Authentication investigation
- PowerShell activity analysis
- Endpoint activity monitoring
- MITRE ATT&CK mapping
- Alert investigation and correlation
- Attack timeline reconstruction
- Incident response planning
- Wazuh dashboard and visualization development

---

# 📋 Key Windows Events

| Event ID | Description | Purpose |
|---|---|---|
| **4624** | Successful Logon | Detect successful authentication |
| **4625** | Failed Logon | Detect failed authentication / brute force |
| **4634** | Logoff | Identify session termination |
| **104** | Event Log Cleared | Detect log-clearing activity |
| **4698** | Scheduled Task Created | Detect scheduled task creation |
| **Sysmon 1** | Process Create | Monitor process execution |

---

# 🧪 Lab Safety

All testing was performed inside an isolated **VirtualBox Host-Only network**.

The simulated attacks were directed only against the Windows 10 Pro laboratory VM and were not performed against production systems, external systems, or the physical host.

---

# 🏁 Final Result

This Home SOC Lab demonstrated a complete Windows attack investigation, starting with an RDP brute-force attempt and progressing through successful authentication, PowerShell execution, discovery, scheduled-task activity, and event-log clearing.

Wazuh and Sysmon provided the telemetry required to detect and investigate the different stages of the attack, while MITRE ATT&CK was used to classify the observed behaviors.

### Final Attack Flow

```text
RDP Brute Force
       ↓
Credential Recovery
       ↓
Successful RDP
       ↓
PowerShell
       ↓
Account/System Discovery
       ↓
Scheduled Task Activity
       ↓
Event Log Clearing
       ↓
Investigation
       ↓
Incident Response
```

**Status: Detection successfully validated and incident investigation completed.**
