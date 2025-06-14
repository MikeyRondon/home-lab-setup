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

📸 Screenshots:

PowerShell command

Event Viewer showing Event ID 1

🔹 DNS Query via nslookup – Logged as Event ID 3
powershell
Copy
Edit
nslookup google.com
Expected Event ID 22 (DNS query), but received Event ID 3 (network connection to DNS server).

Likely due to default Sysmon config suppressing DNS logs.

📸 Screenshots:

PowerShell nslookup output

Event Viewer showing Event ID 3 (nslookup.exe to 10.0.2.3:53)

🔹 Outbound HTTP Request to Kali – Logged as Event ID 22
powershell
Copy
Edit
Invoke-WebRequest http://192.168.56.101
Used Kali's Python HTTP server (python3 -m http.server 80)

PowerShell successfully connected and returned HTML.

Sysmon logged a DNS query from PowerShell (Event ID 22), but did not log Event ID 3.

Likely filtered out by SwiftOnSecurity config.

📸 Screenshots:

Kali terminal showing incoming request

PowerShell output

Event Viewer showing Event ID 22 for PowerShell

## 🧠 Observations

- Sysmon reliably logs **process creation** (Event ID 1).  
- DNS queries may appear as **Event ID 3** (network connection) or **Event ID 22** (DNS query), depending on the tool used and the Sysmon config.  
- PowerShell-initiated connections sometimes bypass **Event ID 3** logging under default configurations.  
- Effective real-world monitoring requires tuning Sysmon rules for full network visibility and endpoint telemetry.

---

## 📸 Screenshots

- Sysmon Event Viewer logs: Event ID 1, 3, and 22  
- PowerShell session outputs  
- Kali terminal showing incoming web connection


## ✅ Summary

This lab demonstrates how Sysmon provides deep insight into Windows endpoint behavior.  
By simulating activity such as process launches, DNS lookups, and outbound HTTP connections,  
I was able to examine how and when different events are captured — and what may be filtered by default.

---

### 🧭 Next Steps

- Integrate Sysmon logs into a SIEM (e.g., Wazuh)  
- Test alert generation using detection rules (e.g., Sigma)  
- Write incident-style summaries for log analysis practice


