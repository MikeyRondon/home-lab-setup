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

---

## 🛠️ In Progress

- [ ] Create and configure Windows 10 VM
- [ ] Install Wireshark on host and Kali
- [ ] Simulate basic reconnaissance scan from Kali
- [ ] Analyze scan traffic in Wireshark
- [ ] Install and configure Ubuntu Server
- [ ] Set up Sysmon on Windows 10 endpoint
- [ ] Deploy Wazuh as a SIEM/log aggregator
- [ ] Configure Wazuh to collect and correlate logs
- [ ] Join TryHackMe and complete first room

---

## 🎯 Planned Improvements

- Set up basic Active Directory domain
- Test alerting using Splunk Free (or Wazuh)
- Write incident response summary from simulated compromise
- Document user audit with PowerShell
