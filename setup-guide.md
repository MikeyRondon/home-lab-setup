# ⚙️ Home Lab Setup Guide

This guide outlines the initial configuration of my home cybersecurity lab, including host OS, virtualization platform, virtual machines, and network layout. The goal is to build an isolated and flexible environment for exploring threat detection, system hardening, and SOC-style monitoring.

---

## 🖥️ Host System

- **OS**: Windows 10  
- **RAM**: [Insert your RAM amount here]  
- **CPU**: [Insert your CPU info if you'd like]  
- **Storage**: [Insert available disk space or total drive size]  
- **Virtualization Tool**: VirtualBox

---

## 📦 Virtual Machines

| VM Name       | OS / Role         | Purpose                                |
|---------------|-------------------|----------------------------------------|
| Kali Linux    | Debian-based      | Attacker, nmap scans, basic testing    |
| Windows 10    | Desktop OS        | Endpoint target, logging activity      |
| Ubuntu Server | Headless server   | Future: simulate services / web app    |
| Wazuh/SO      | Security monitoring| SIEM/log collection (planned)          |

---

## 🌐 Networking Setup

- **Adapter 1**: NAT (internet access for updates/lab downloads)  
- **Adapter 2**: Host-Only (internal traffic between VMs)  
- **Lab Network**: Segregated, no access to host network

---

## 🧰 Tools to Install

| Tool        | VM          | Purpose                                 |
|-------------|-------------|------------------------------------------|
| Wireshark   | Kali / Host | Packet analysis                          |
| Nmap        | Kali        | Scanning & recon                         |
| Sysmon      | Windows     | Endpoint logging                         |
| Wazuh Agent | All VMs     | Log forwarding to SIEM                   |

---

## 🔐 Security Considerations

- VMs isolated from host via Host-Only networking  
- Snapshots created before and after major changes  
- No real personal data used  
- Test-only environment — never connected to production systems

---

## ✅ Status

This setup is currently in progress. VMs will be created and configured one at a time, with notes and screenshots added as I go.

