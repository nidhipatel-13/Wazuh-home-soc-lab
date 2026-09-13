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
        ├── Sysmon Telemetry
        └── FIM (File + Registry Monitoring)
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

### 6. File Integrity Monitoring (FIM)

To extend detection beyond the initial attack chain, File Integrity Monitoring was configured to detect both file-system and Windows Registry tampering.

**Configuration:**
```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>10</frequency>
  <directories>C:\Users\Public</directories>
  <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
</syscheck>
```

#### File-level test

A file (`malware.txt`) was created inside `C:\Users\Public\Pictures` to simulate a dropped payload.

- **Event:** File added to the system
- **Wazuh Rule:** 554
- **Path:** `c:\users\public\pictures\malware.txt`

#### Registry persistence test

A registry Run key was added and removed to simulate a classic malware persistence technique.

```powershell
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "testpersistence" -Value "C:\test.exe"
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "testpersistence"
```

- **Event:** Registry Value Entry Added to the System / Registry Value Entry Deleted
- **Wazuh Rules:** 752 (added), 751 (deleted), 750 (modified), 594 (key checksum changed)
- **MITRE:** T1547.001 — Registry Run Keys / Startup Folder

**Observations:** Both file and registry changes were detected and logged with full context — including path, event type, and rule classification — confirming Wazuh's FIM module correctly captured unauthorized file drops and persistence-style registry modifications on the compromised endpoint.

### 7. Custom Detection Rules

#### Rule 100101 — Windows Firewall Disabled

Detects when the Windows Firewall is disabled across any profile, a common defense-evasion technique used to allow follow-on attack traffic through.

```xml
<group name="windows,firewall,windows_firewall,">

  <rule id="100101" level="12">
    <if_sid>67005</if_sid>
    <description>MYRULE: Windows Firewall has been disabled</description>
    <mitre>
      <id>T1562.004</id>
    </mitre>
    <group>firewall_disable,defense_evasion,</group>
  </rule>

</group>
```

#### Rule 100102 — Security Audit Log Cleared

Detects clearing of the Windows Security event log — the log that records authentication and logon activity, making this a strong indicator of anti-forensics/log-tampering behavior following a compromise.

```xml
<group name="windows,security_log,log_tampering,log_clearing_auditlog,windows_log,">

  <rule id="100102" level="12">
    <if_sid>63103</if_sid>
    <field name="win.system.eventID">^1102$</field>
    <description>MYRULE: Windows Security audit log was cleared</description>
    <mitre>
      <id>T1070.001</id>
    </mitre>
    <group>log_tampering,defense_evasion,</group>
  </rule>

</group>
```

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
| File Drop (Simulated Payload)  | Ingress Tool Transfer                       | T1105     | Rule 554           |
| Registry Persistence           | Registry Run Keys / Startup Folder          | T1547.001 | Rules 750/751/752  |
| Firewall Disabled              | Disable or Modify System Firewall           | T1562.004 | Rule 100101         |
| Security Log Cleared           | Indicator Removal: Clear Windows Event Logs | T1070.001 | Rule 100102         |

---




