# 🧪 Lab Progress Tracker

This file documents the setup steps and progress of my home cybersecurity lab. It includes systems installed, configurations completed, and upcoming improvements.

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

---

## 🛠️ In Progress

- [ ] Install and configure Ubuntu Server  
- [ ] Set up Sysmon on Windows 10 endpoint  
- [ ] Deploy Wazuh as a SIEM/log aggregator  
- [ ] Configure Wazuh to collect and correlate logs  
- [ ] Join TryHackMe and complete first room  
- [ ] Begin documenting second lab (Sysmon or endpoint logging)

---

## 🎯 Planned Improvements

- Set up basic Active Directory domain  
- Test alerting using Splunk Free (or Wazuh)  
- Write incident response summary from simulated compromise  
- Document user audit with PowerShell  
