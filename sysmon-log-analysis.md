# 📊 Sysmon Log Analysis Lab

> 📝 This project explores Windows event logging using Sysmon to detect and document suspicious activity such as scans, execution of binaries, network connections, DNS queries, file creation, process access, and image loads.

---

## 🎯 Objective

To install and configure Sysmon on a Windows 10 virtual machine and analyze logs generated during controlled simulations of common attacker behavior. The goal is to understand how Sysmon enhances visibility into endpoint behavior.

---

## 🧪 Lab Environment

- **Windows 10 VM** (Target)  
  - Fresh install with NAT + Host-Only adapters  
  - Sysmon installed with SwiftOnSecurity configuration  
- **Kali Linux VM** (Attacker)  
  - Used to simulate recon and basic attacks (e.g., Nmap scans, file transfer)  
- **Tools Used**  
  - Sysmon  
  - Event Viewer  
  - PowerShell  
  - Python3 (HTTP server on Kali)  
  - ProcDump, PsExec (Sysinternals)  
  - Nmap (optional)

---

## 🔍 Simulated Events and Observations

### 🔹 Process Creation – Calculator (Event ID 1)

```powershell  
Start-Process calc.exe  
```

Sysmon logged this as Event ID 1, capturing `CommandLine`, `ParentProcessName`, and `Hashes`.

#### 📸 Screenshots

![PowerShell – Launching Calculator](./screenshots/PS_Command_Line_Calc.PNG)  
![Event Viewer – Event ID 1 Details](./screenshots/EV_ID_1.PNG)

---

### 🔹 Network Connection – Test-NetConnection (Event ID 3)

```powershell  
Test-NetConnection -ComputerName example.com -Port 80  
```

Logged as Event ID 3, showing `SourceIp`, `DestinationIp`, and `Protocol`.

#### 📸 Screenshots

![PowerShell NetConnection Test](./screenshots/PS_CL_Network_Connection.PNG)  
![Event Viewer – Event ID 3 Details](./screenshots/EV_ID_3.PNG)

---

### 🔹 DNS Query – Resolve-DnsName (Event ID 22)

```powershell  
Resolve-DnsName microsoft.com  
```

Captured as Event ID 22, with `QueryName`, `QueryResults`, and `DestinationIp`.

#### 📸 Screenshots

![PowerShell DNS Query](./screenshots/PS_CL_DNS_Query.PNG)  
![Event Viewer – Event ID 22 Details](./screenshots/EV_ID_22.PNG)

---

### 🔹 File Creation – Sysmon Test File (Event ID 11)

#### 1) PowerShell File Creation (No Event Logged)

```powershell  
New-Item -Path C:\Users\Public\sysmon_file_lab.txt -ItemType File  
```

**Observation:** No Event ID 11 appeared—indicating the default config filtered out this action.

##### 📸 Screenshots

![PowerShell File Creation (no Event 11)](./screenshots/PS_CL_File_creation_1.PNG)  
![Event Viewer – No Event ID 11 Logged](./screenshots/1_NO_Result_EV_ID_11.PNG)

---

#### 2) File Download via Microsoft Edge (Event ID 11)

![Download ProcDump](./screenshots/ProcDump_Download.PNG)  
![Edge Download Completion](./screenshots/EV_ID_11_Download_using_MSEDGE.PNG)

Logged as Event ID 11, capturing `TargetFilename` and `Image`.

---

### 🔹 Process Access – ProcDump to Notepad (Event ID 10)

```powershell  
# Spawn SYSTEM shell via PsExec  
.\PsExec.exe -accepteula -s -i powershell.exe  
# In SYSTEM shell:  
cd C:\Users\Labuser\Downloads  
.\ProcDump.exe -accepteula -ma notepad C:\Temp\notepad.dmp  
```

Logged as Event ID 10, capturing `SourceImage`, `TargetImage`, `GrantedAccess`, and `CallTrace`.

#### 📸 Screenshots

![SYSTEM shell ProcDump invocation & success](./screenshots/SYSTEM_PS_CL_Procdump_Invocation_and_success.PNG)  
![Verify dump file exists](./screenshots/PS_CL_Verify_Dump.PNG)  
![Event Viewer – Event ID 10 Details](./screenshots/EV_ID_10.PNG)

---

### 🔹 Image Load – CMD Launch (Event ID 7)

```powershell  
Start-Process cmd.exe  
```

Logged as Event ID 7, capturing `ImageLoaded`, `Hashes`, `ImageSize`, and `Signed`.

#### 📸 Screenshots

![PowerShell – Launching CMD](./screenshots/PS_CL_image_load.PNG)  
![Event Viewer – Event ID 7 Details](./screenshots/EV_ID_7.PNG)

---

## 🧠 Final Observations

### 1. Compare Metadata
- **Common fields:**  
  - `UtcTime`  
  - `ProcessGuid` / `ProcessId`  
  - `Image` / `SourceImage` / `TargetImage`  
- **Unique fields:**  
  - **Event 3 (Network Connection):** `SourceIp`, `DestinationIp`, `Protocol`  
  - **Event 22 (DNS Query):** `QueryName`, `QueryResults`  
  - **Event 11 (File Creation):** `TargetFilename`  
  - **Event 10 (Process Access):** `GrantedAccess`, `CallTrace`  
  - **Event 7 (Image Load):** `ImageLoaded`, `Hashes`, `ImageSize`, `Signed`

### 2. Identify Gaps
- Outbound HTTP requests didn’t always generate Event ID 3 under default rules.  
- Simple PowerShell file creation was filtered out until download actions triggered Event ID 11.  
- No `CallTrace` until enabled in config.  
- `SignatureStatus` missing for some signed images.

### 3. Detection Potential
- **Event 1:** Alert on unknown or unsigned executables.  
- **Event 10:** Alert when `TargetImage=lsass.exe` or high-memory access flags.  
- **Event 22:** Alert on DNS queries to suspicious domains.  
- **Event 7:** Alert on unsigned or uncommon DLL loads in critical processes.

---

### 4. Documentation

#### Event ID 1 – Process Creation
- **Command:** `Start-Process calc.exe`  
- **Timestamp:** 6/17/2025 4:27:43 PM (from EV_ID_1.PNG)  
- **Anomalies:** None

#### Event ID 3 – Network Connection
- **Command:** `Test-NetConnection -ComputerName example.com -Port 80`  
- **Timestamp:** 6/17/2025 4:43:51 PM (from EV_ID_3.PNG)  
- **Anomalies:** None

#### Event ID 22 – DNS Query
- **Command:** `Resolve-DnsName microsoft.com`  
- **Timestamp:** 6/17/2025 4:51:44 PM (from EV_ID_22.PNG)  
- **Anomalies:** None

#### Event ID 11 – File Creation
- **Command:** `New-Item -Path C:\Users\Public\sysmon_file_lab.txt -ItemType File`  
- **Timestamp:** 6/17/2025 4:54:00 PM (approx, from PS_CL_File_creation_1.PNG)  
- **Anomalies:** No Event ID 11 logged for simple PS file creation under default config  
- **Command:** Download ProcDump via Edge  
- **Timestamp:** 6/17/2025 5:02:54 PM (from EV_ID_11.PNG)  
- **Anomalies:** Logged as Event ID 11 by `msedge.exe`

#### Event ID 10 – Process Access
- **Command:**  
  1. `.\PsExec.exe -accepteula -s -i powershell.exe`  
  2. `.\ProcDump.exe -accepteula -ma notepad C:\Temp\notepad.dmp`  
- **Timestamp:** 6/17/2025 5:58:16 PM (from EV_ID_10.PNG)  
- **Anomalies:** None

#### Event ID 7 – Image Load
- **Command:** `Start-Process cmd.exe`  
- **Timestamp:** 6/17/2025 6:43:22 PM (from EV_ID_7.PNG)  
- **Anomalies:** None

---

## ✅ Summary

This lab demonstrates how Sysmon’s detailed event logging across process, network, DNS, file, handle-access, and image-load events provides comprehensive endpoint visibility. Tuning the configuration is critical to ensure you capture high-fidelity data for threat detection and SIEM integration.

---

**Next steps:**  
- Forward Sysmon logs to Wazuh  
- Create Sigma detection rules  
- Draft incident-style summaries based on these events  

