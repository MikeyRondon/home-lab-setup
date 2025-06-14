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


## 🧠 Observations

- Sysmon reliably logs **process creation** (Event ID 1).  
- DNS queries may appear as **Event ID 3** (network connection) or **Event ID 22** (DNS query), depending on the tool used and the Sysmon config.  
- PowerShell-initiated connections sometimes bypass **Event ID 3** logging under default configurations.  
- Effective real-world monitoring requires tuning Sysmon rules for full network visibility and endpoint telemetry.

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

This lab demonstrates how Sysmon provides deep insight into Windows endpoint behavior.  
By simulating activity such as process launches, DNS lookups, and outbound HTTP connections,  
I was able to examine how and when different events are captured — and what may be filtered by default.

---

### 🧭 Next Steps

- Integrate Sysmon logs into a SIEM (e.g., Wazuh)  
- Test alert generation using detection rules (e.g., Sigma)  
- Write incident-style summaries for log analysis practice


