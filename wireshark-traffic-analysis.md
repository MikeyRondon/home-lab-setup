# 🔍 Wireshark Traffic Analysis (Planned Lab)

> 📝 *This lab is currently in progress. This writeup serves as a structured plan and will be updated as the lab is completed.*

This document outlines a planned lab to perform a basic packet capture using Wireshark. The goal is to observe and analyze network traffic generated from a simulated reconnaissance scan between two virtual machines.

---

## 🎯 Objective

To use Wireshark to capture and analyze traffic from an `nmap` scan targeting a Windows 10 VM, and to identify key indicators of scanning activity.

---

## 🧪 Planned Lab Setup

- **Host OS**: Windows 10  
- **Virtualization Tool**: VirtualBox  
- **VMs**:
  - **Kali Linux** – Launches the scan  
  - **Windows 10** – Target endpoint  
- **Networking**: NAT + Host-Only Adapter  
- **Tool**: Wireshark installed on Kali Linux

---

## 📡 Planned Scan

Command to run on Kali:

```bash
nmap -sS -T4 -p 1-1000 192.168.56.10
