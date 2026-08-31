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
Gaining Access
       ↓
Successful RDP Authentication
       ↓
Post-Access Activity
       ↓
Covering Tracks
       ↓
Incident Reporting
```

---

# 🔎 Detection & Investigation

## 1. Brute-Force Attack

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

### 2. Gaining Access

A controlled RDP brute-force attack was performed using Hydra. Valid credentials were recovered and used to establish a successful RDP session.

- **Event:** 4624 — Successful Logon
- **Logon Type:** 10 — RemoteInteractive
- **Wazuh Rule:** 92653
- **User:** `WORKGROUP\nidhi`
- **MITRE:** T1021.001, T1078.003

### 3. Post-Access Activity

PowerShell was executed after gaining RDP access, followed by account and system discovery activities.

- **Sysmon Event:** 1 — Process Create
- **Wazuh Rule:** 92027
- **MITRE:** T1059.001 — PowerShell
- **Discovery Rules:** 92033 / 92031
- **MITRE:** T1087 — Account Discovery

### 4. Covering Tracks

The Windows Application event log was cleared using `wevtutil`, simulating an attempt to remove forensic evidence.

- **Event:** 104 — Application Log Cleared
- **Wazuh Rule:** 63104
- **User:** `nidhi`
- **MITRE:** T1070.004 — Clear Windows Event Logs

### 5. Reporting

Wazuh alerts and Windows/Sysmon telemetry were reviewed, correlated, mapped to MITRE ATT&CK, and documented as an incident.



### 🧠 MITRE ATT&CK Mapping

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




