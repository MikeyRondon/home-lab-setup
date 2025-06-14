# home-lab-setup
My personal cybersecurity lab using virtual machines and open-source tools.

# 🧪 Home Cybersecurity Lab

This project documents the setup and use of my personal home cybersecurity lab, designed for hands-on learning in IT support, networking, and SOC analyst skills.

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
  - Security Onion or Wazuh (SIEM/log analysis, in progress)

- **Network Configuration**:  
  - NAT + Host-Only Adapter  
  - Isolated internal lab network for traffic inspection

---

## 🧰 Tools Used

### Networking & Monitoring  
- Wireshark  
- Suricata  
- TCPDump  

### Endpoint & Systems  
- Windows 10/11  
- Ubuntu / Kali Linux  
- PowerShell & Bash  

### SIEM / Security  
- Wazuh (in progress)  
- Splunk Free (planned)  
- Sysmon + Windows Event Viewer

---

## 🔐 Skills Practiced

- Virtual machine management  
- Secure network design & segmentation  
- Incident simulation & detection  
- Packet capture & log analysis  
- Basic red/blue team workflows  
- Windows and Linux hardening  
- Threat documentation & reporting

---

## 📸 Screenshots (Coming Soon)

I’ll be adding screenshots of my network setup, VM configurations, packet captures, and log dashboards as the lab evolves.

---

## 📂 Projects

- [Wireshark TCP SYN Scan Analysis](./wireshark-scan-analysis.md)  
  Performed a basic TCP SYN scan using Nmap, captured network traffic with Wireshark, and analyzed TCP handshake behavior in a virtualized lab environment.

---

## 🚧 In Progress

- Configure Wazuh SIEM  
- Set up centralized log collection  
- Simulate phishing attack + detection  
- Create a writeup on incident response from a simulated compromise
