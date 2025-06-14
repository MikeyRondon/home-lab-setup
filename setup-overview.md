# ⚙️ Home Lab Setup Guide

This guide outlines the configuration of my home cybersecurity lab, including host OS, virtualization platform, virtual machines, and network layout. The goal is to build an isolated and flexible environment for exploring threat detection, system hardening, and SOC-style monitoring.

---

## 🖥️ Host System

- **OS**: Windows 10  
- **RAM**: 16 GB  
- **CPU**: 8-core processor  
- **Storage**: 100+ GB free  
- **Virtualization Tool**: VirtualBox

---

## 📦 Virtual Machines

| VM Name       | OS / Role         | Purpose                                 |
|---------------|-------------------|-----------------------------------------|
| Kali Linux    | Debian-based      | Attacker system; Nmap scans, basic testing  
| Windows 10    | Desktop OS        | Endpoint target; testing logging, recon detection  
| Ubuntu Server | Headless server   | For simulating services / hosting future web app  
| Wazuh or SO   | Security monitoring | SIEM/log collection (planned)           |

---

## 🌐 Networking Setup

- **Adapter 1**: NAT – Provides internet access for updates and downloads  
- **Adapter 2**: Host-Only – Isolated lab network for internal traffic  
- **Lab Network**: Fully segmented from host network and external devices

---

## 🧰 Tools to Install

| Tool        | VM(s)         | Purpose                                |
|-------------|---------------|----------------------------------------|
| Wireshark   | Kali / Host   | Packet capture and network traffic analysis  
| Nmap        | Kali          | Scanning and reconnaissance  
| Sysmon      | Windows 10    | Endpoint event logging  
| Wazuh Agent | All VMs       | Forwarding logs to central SIEM

---

## 🔐 Security Considerations

- VMs isolated via Host-Only networking to prevent host exposure  
- Snapshots taken before/after key configurations or experiments  
- No sensitive data used — test environment only  
- Internet access allowed only for lab-related downloads/updates

---

## ✅ Status

This setup is currently **in progress**.  
- ✅ Kali Linux and Windows 10 VMs created and configured  
- ✅ Wireshark installed and used for initial packet capture  
- 🔜 Ubuntu and SIEM components (Wazuh/Security Onion) will follow  
- 📸 Screenshots and documentation will be added to each project folder as lab work continues

