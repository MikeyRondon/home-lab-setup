# 📊 Sysmon Log Analysis Lab

> 📝 This project explores Windows event logging using Sysmon to detect and document suspicious activity such as scans, execution of binaries, and network events.

---

## 🎯 Objective

To install and configure Sysmon on a Windows 10 virtual machine and analyze logs generated during controlled simulations of common attacker behavior (e.g., port scans, script execution). The goal is to understand how Sysmon enhances visibility into endpoint behavior.

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
  - Python3 (for HTTP server on Kali)  
  - Nmap (optional)

---

## 🛠️ Steps

1. ✅ Installed Sysmon on Windows VM
2. ✅ Applied SwiftOnSecurity configuration
3. ✅ Confirmed Sysmon logs to Event Viewer
4. ✅ Simulated activity: process creation, DNS queries, web requests
5. ✅ Captured and reviewed Event IDs 1, 3, and 22
6. ✅ Documented logs and screenshots

---

## 🧠 Key Event IDs

| Event ID | Description          |
|----------|----------------------|
| 1        | Process Creation     |
| 3        | Network Connection   |
| 22       | DNS Query            |

---

## 🔍 Simulated Events and Observations

### 🔹 Process Creation – Notepad (Event ID 1)

```powershell
Start-Process notepad
```
Sysmon successfully logged this as Event ID 1.

Captured the full command line, hash values, and parent process (PowerShell).

### 📸 Screenshots

#### PowerShell – Launching Notepad  
![PowerShell Notepad Command](./screenshots/PS%20NP%20Proj.2.PNG)

#### Event Viewer – Event ID 1 (Process Creation)  
![Sysmon Event ID 1 – Notepad](./screenshots/EV%20ID%201%20NP%20proj.2.PNG)

### 🔹 DNS Query via nslookup – Logged as Event ID 3
```powershell
nslookup google.com
```
Expected Event ID 22 (DNS query), but received Event ID 3 (network connection to DNS server).

Likely due to default Sysmon config suppressing DNS logs for certain tools like `nslookup`

### 📸 Screenshots

#### PowerShell `nslookup` Output  
![PowerShell nslookup](./screenshots/NS%20LOOKUP%20DNS%20Query%20ID%2022%20proj.2.PNG)

#### Event Viewer – Event ID 3 from `nslookup.exe`  
![Event ID 3 – nslookup DNS connection](./screenshots/EV%20DNS%20ID%203%20no%20ID%2022.PNG)

### 🔹 Outbound HTTP Request to Kali – Logged as Event ID 22

```powershell
Invoke-WebRequest http://192.168.56.101
```
Used Kali's Python HTTP server 
```bash
python3 -m http.server 80
```
PowerShell successfully connected to the server and returned a directory listing in HTML.

Sysmon logged this activity as a **DNS query (Event ID 22)** initiated by `powershell.exe`.

However, **Event ID 3 (network connection)** was not recorded — likely filtered out by the default **SwiftOnSecurity** Sysmon configuration.

### 📸 Screenshots

#### Kali terminal showing incoming request  
![Kali HTTP Server](./screenshots/Kali%20Basic%20web%20listener%20proj.2.PNG)

#### PowerShell output  
![PowerShell Web Request](./screenshots/Windows%20WebRequest%20proj.2.PNG)

#### Event Viewer showing Event ID 22 for PowerShell  
![Event ID 22 - PowerShell](./screenshots/EV%20id%2022%20no%20ID3.PNG)

### 🔹 File Creation – Event ID 11

```powershell
New-Item -Path C:\Users\Public\sysmon-lab-test.txt -ItemType File
```

Sysmon successfully logged this action as **Event ID 11**, indicating a file was created by `powershell.exe`.

The event captured the full **TargetFilename**, **Image path**, and **Process ID**, providing insight into endpoint-level file activity.

This demonstrates how Sysmon tracks file creation by specific executables, which can be crucial for detecting suspicious script behavior or lateral movement.

---

### 📸 Screenshots

#### PowerShell – File Creation Command  
![PowerShell File Creation](./screenshots/PS%20FileCreate%20proj.2.PNG)

#### Event Viewer – Event ID 11 Logged  
![Sysmon Event ID 11 – File Creation](./screenshots/EV%20ID%2011%20FileCreate%20proj.2.PNG)


## 🧠 Observations

- Sysmon reliably logs **process creation** (Event ID 1) and provides detailed metadata like parent-child relationships and hashes.
- **DNS activity** can appear as either Event ID 3 or 22 depending on the command used and the active configuration.
- **PowerShell web requests** were logged under Event ID 22, but did not always trigger Event ID 3 — likely due to filtering in the SwiftOnSecurity config.
- **File creation** (Event ID 11) was not logged under the default configuration until a minimal test config was applied, highlighting how **Sysmon's effectiveness depends heavily on how it's configured**.
- For accurate endpoint monitoring, custom or expanded configs are essential — especially for detecting attacker behaviors like script-based file drops or silent connections.

---

## 📸 Screenshots

#### 🧾 Event Viewer – Sysmon Logs
- **Event ID 1 – Notepad**
  ![Event ID 1 – Notepad](./screenshots/EV%20ID%201%20NP%20proj.2.PNG)

- **Event ID 3 – nslookup DNS connection**
  ![Event ID 3 – nslookup](./screenshots/EV%20DNS%20ID%203%20no%20ID%2022.PNG)

- **Event ID 22 – PowerShell DNS Query**
  ![Event ID 22 – PowerShell](./screenshots/EV%20id%2022%20no%20ID3.PNG)

#### 💻 PowerShell Output
- **Notepad Process Launch**
  ![PowerShell Start-Process](./screenshots/PS%20NP%20Proj.2.PNG)

- **Invoke-WebRequest Output**
  ![PowerShell WebRequest](./screenshots/Windows%20WebRequest%20proj.2.PNG)

#### 🖥️ Kali Terminal – HTTP Connection
- **Kali Receiving Request**
  ![Kali Web Server](./screenshots/Kali%20Basic%20web%20listener%20proj.2.PNG)



## ✅ Summary

This lab demonstrates how Sysmon provides deep visibility into endpoint activity, from process creation and network behavior to DNS queries and file creation.

By simulating common system actions — like launching applications, performing DNS lookups, making web requests, and creating files — we tested how Sysmon detects and logs these events.

We also observed that Sysmon’s default or community configurations (like SwiftOnSecurity’s) may filter out important events like file creation unless explicitly configured.

These findings underscore the importance of using custom or minimal configs in lab environments for full visibility, especially when preparing for threat detection and SIEM integration work.

---

**Next steps:**
- Forward Sysmon logs to a SIEM (e.g., Wazuh)
- Trigger and test alerts using detection rules (e.g., Sigma)
- Write incident-style summaries based on real event log data



