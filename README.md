# 🧪 Home Lab Setup

My personal cybersecurity lab using virtual machines and open-source tools. This project documents the setup and use of my home cybersecurity lab, designed for hands-on learning in IT support, networking, and SOC analyst skills. It includes system configurations, threat simulations, packet captures, log analysis, and write-ups for real-world tools.

---

## 🎯 Objective

To create a secure and flexible virtual environment where I can explore threat detection, system hardening, incident response, and log analysis using real-world tools and techniques.

---

## 🏗️ Lab Overview

### Host System
- **OS:** Windows 10  
- **RAM:** 16 GB  
- **CPU:** 8-core  
- **Storage:** 100+ GB free  
- **Virtualization:** VirtualBox  

### 📦 Virtual Machines

| VM Name       | OS / Role        | Purpose                                         |
|---------------|------------------|-------------------------------------------------|
| Kali Linux    | Debian-based     | Attacker system; Nmap scans & basic testing     |
| Windows 10    | Desktop OS       | Endpoint target; Sysmon & log forwarding tests  |
| Ubuntu Server | Headless server  | Wazuh manager & other service hosting           |
| Wazuh Agent   | Installed on all | Forwarding logs to central SIEM (Wazuh manager) |

### 🛰️ Networking Setup
- **Adapter 1:** NAT – Internet access for updates/downloads  
- **Adapter 2:** Host-Only – Isolated lab network for internal traffic  
- **Lab Network:** Fully segmented from host and external networks  

---

## 🧰 Tools Used

> 🔍 *Some tools are actively in progress.*

### 🛰️ Networking & Monitoring
- ✅ Wireshark  
- 🟡 Suricata *(planned)*  
- 🟡 TCPDump *(learning)*  

### 💻 Endpoints & Systems
- ✅ Windows 10/11  
- ✅ Kali Linux / Ubuntu  
- ✅ PowerShell & Bash  

### 📊 SIEM & Security
- ✅ Wazuh (forwarded Sysmon logs, custom Sigma rules & incident reporting)  
- 🟡 Splunk Free *(planned)*  
- ✅ Sysmon + Event Viewer  

---

## 🛠️ Skills Practiced

- Virtual machine management & snapshots  
- Secure network design & segmentation  
- Packet capture & Wireshark analysis  
- Sysmon & Wazuh log forwarding  
- Sigma rule writing & incident documentation  
- Windows & Linux hardening  
- Basic red/blue team workflows  

---

## 📂 Projects

- 🧪 **[Wireshark TCP SYN Scan Analysis](./wireshark-scan-analysis.md)**  
  Captured and analyzed a TCP SYN scan with Nmap and Wireshark in an isolated VM lab.  

- 🖥️ **[Sysmon Log Analysis](./sysmon-log-analysis.md)**  
  Installed and configured Sysmon on Windows, forwarded events to Wazuh, authored Sigma rules, and documented incidents (VaultCli load, Temp-directory execution).

---

## 🚧 In Progress

- Automate lab build with Terraform/Ansible  
- Simulate phishing attack & detection  
- Endpoint security tests  

---

## 🚧 Planned Improvements

- Set up Active Directory domain  
- Test alerting with Splunk Free (or Wazuh dashboards)  
- Write incident response summary from simulated compromise  
- Develop PowerShell auditing tools  
