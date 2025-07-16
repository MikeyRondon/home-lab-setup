# 🧪 Lab Progress Tracker

> This file documents the setup steps and progress of my home cybersecurity lab. It includes systems installed, configurations completed, and upcoming improvements.

---

## ✅ Completed

- [x] Installed VirtualBox on Windows 10 host  
- [x] Downloaded and extracted Kali Linux VirtualBox VM files (.vdi + .vbox)  
- [x] Manually imported Kali VM into VirtualBox  
- [x] Configured Kali with NAT + Host-Only network adapters  
- [x] Successfully booted and logged into Kali Linux  
- [x] Updated Kali system via terminal (`sudo apt update && sudo apt upgrade -y`)  
- [x] Took VirtualBox snapshot of clean Kali install  
- [x] Downloaded Windows 10 ISO from Microsoft  
- [x] Created Windows 10 VM in VirtualBox  
- [x] Assigned NAT + Host-Only network adapters to Windows VM  
- [x] Installed Windows 10 using a local (offline) account  
- [x] Installed VirtualBox Guest Additions on Windows VM  
- [x] Took snapshot of clean Windows 10 install  
- [x] Verified Host-Only communication between Kali and Windows VMs (ping successful)  
- [x] Installed Wireshark on Kali Linux  
- [x] Ran a TCP SYN scan from Kali to Windows 10 using Nmap  
- [x] Captured and filtered traffic in Wireshark using `tcp.flags.syn == 1 && tcp.flags.ack == 0`  
- [x] Uploaded screenshots of scan and IP configs  
- [x] Created and committed `wireshark-scan-analysis.md`  
- [x] Linked project in main `README.md`  
- [x] Wrote and added `setup-overview.md` documenting lab architecture  
- [x] Installed and configured Sysmon on Windows 10 endpoint  
- [x] Completed Sysmon log analysis and wrote `sysmon-log-analysis.md`  
- [x] Installed and configured Ubuntu Server for Wazuh manager  
- [x] Deployed Wazuh as a SIEM/log aggregator  
- [x] Configured Wazuh to collect and correlate logs  
- [x] Created Sigma rule for non-system DLL loads (`sigma/sysmon-image-load-detect.yml`)  
- [x] Created Sigma rule for Temp-directory process executions (`sigma/sysmon-temp-execution-detect.yml`)  
- [x] Tested Sigma rules with VaultCli.dll and `test.dll` scenarios  
- [x] Enforced Software Restriction Policy to block Temp-folder executables  
- [x] Simulated Mimikatz credential-dump, captured detection in Wazuh, and wrote incident summary  

---

## 🛠️ In Progress

- [ ] Join TryHackMe and complete first room  

---

## 🎯 Planned Improvements

- Set up basic Active Directory domain  
- Build a Wazuh/OpenSearch dashboard for Sysmon alerts  
- Expand Sigma rules for other Sysmon EventIDs (e.g., NetworkConnect, Registry changes)  
- Document user audit with PowerShell  

