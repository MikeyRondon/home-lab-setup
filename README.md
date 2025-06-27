# 🧪 Home Lab Setup

My personal cybersecurity lab using virtual machines and open-source tools.

This project documents the setup and use of my home cybersecurity lab, designed for hands-on learning in IT support, networking, and SOC analyst skills. It includes system configurations, threat simulations, traffic analysis, and writeups for real-world tools.

---

## 🎯 Objective

To create a secure and flexible virtual environment where I can explore threat detection, system hardening, incident response, and log analysis using real-world tools and techniques.

---

## 🏗️ Lab Overview

- **Host OS**: Windows 10  
- **Virtualization**: VirtualBox  
- **VMs Used**:
  - Kali Linux (attacker/testing)
  - Windows 10 (endpoint target)
  - Ubuntu Server (basic service host)
  - Security Onion or Wazuh (SIEM/log analysis — in progress)

- **Network Configuration**:
  - NAT + Host-Only Adapter
  - Isolated internal lab network for traffic inspection

---

## 🧰 Tools Used

### 🛰️ Networking & Monitoring  
- Wireshark  
- Suricata  
- TCPDump  

### 💻 Endpoint & Systems  
- Windows 10/11  
- Ubuntu / Kali Linux  
- PowerShell & Bash  

### 🔐 SIEM & Security  
- Wazuh *(in progress)*  
- Splunk Free *(planned)*  
- Sysmon + Event Viewer

---

## 🛠️ Skills Practiced

- Virtual machine management  
- Secure network design & segmentation  
- Incident simulation & detection  
- Packet capture & traffic analysis  
- Basic red/blue team workflows  
- Windows and Linux hardening  
- Threat documentation & reporting

---

## 📸 Screenshots

Screenshots are included in individual project folders and lab writeups (see below). They include VM setup, network scans, Wireshark filters, and packet capture views.

---

## 📂 Projects

- [Wireshark TCP SYN Scan Analysis](./wireshark-scan-analysis.md)  
  Performed a TCP SYN scan in an isolated VM lab and analyzed packet flow with Wireshark.

- [Sysmon Log Analysis](./sysmon-log-analysis.md)  
  Configured Sysmon on Windows to log process and network events during recon simulations.

- [Home Lab Architecture Overview](./setup-overview.md)  
  Breakdown of host specs, VM layout, and network segmentation for the lab.

---

## 🚧 In Progress

- Simulate phishing attack + detection  
- Automate lab build with Terraform/Ansible  
- Endpoint security tests

