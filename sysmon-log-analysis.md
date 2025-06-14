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
  - Event Viewer / Log Parser / Sigma (optional)
  - Wireshark / Nmap (for cross-reference)

---

## 🛠️ Steps

1. ✅ Download and install Sysmon from Microsoft Sysinternals  
2. ✅ Apply SwiftOnSecurity Sysmon configuration  
3. ✅ Validate Sysmon is logging to Event Viewer (Event ID 1, 3, etc.)  
4. ✅ Simulate basic attacker behavior from Kali:
   - Run Nmap scan from Kali to Windows
   - (Optional) Transfer script or binary and execute
5. ✅ Open Event Viewer and filter for relevant Sysmon Event IDs
6. ✅ Document observed events (e.g., process creation, network connections)
7. ✅ Correlate activity with timeline of simulated attack

---

## 🧠 Key Event IDs

| Event ID | Description                    |
|----------|--------------------------------|
| 1        | Process creation               |
| 3        | Network connection             |
| 7        | Image loaded                   |
| 11       | File creation                  |
| 22       | DNS query                      |

---

## 📸 Screenshots

- Sysmon config output  
- Example logs from Event Viewer  
- Nmap scan trigger and resulting logs  
- Timeline of activity observed

---

## ✅ Summary

This lab demonstrated how Sysmon provides granular insight into endpoint behavior by logging system-level activity. By simulating basic attack scenarios from Kali Linux and reviewing the logs in Event Viewer, I was able to identify key events tied to scanning, network access, and process execution. Future steps include forwarding logs to a SIEM (Wazuh) and testing real-time alerting workflows.
