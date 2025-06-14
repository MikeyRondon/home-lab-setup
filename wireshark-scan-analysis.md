# 🔍 Wireshark TCP SYN Scan Analysis

> 📝 This is my first traffic analysis lab conducted in my home cybersecurity lab. It simulates a basic TCP SYN scan and captures the resulting traffic using Wireshark for hands-on packet inspection.

---

## 🎯 Objective

To observe and analyze the packet-level behavior of a basic TCP SYN scan performed using `nmap` from a Kali Linux VM to a Windows 10 VM.

---

## 🧪 Lab Environment

- **Kali Linux (Attacker)**  
  - OS: Kali 2025.2  
  - Tools: Nmap, Wireshark  
  - IP: `192.168.56.101`

- **Windows 10 (Target)**  
  - Clean installation  
  - No firewall changes made  
  - IP: `192.168.56.102`

- **Network Setup**  
  - Host-Only Adapter (eth1 on Kali)  
  - NAT Adapter for internet access (eth0 on Kali)

---

## 📡 Scan Command Used

```bash
nmap -sS -T4 -p 1-1000 192.168.56.102
```

---

## 📸 Screenshots

### Windows IP Configuration (`ipconfig`)
![ipconfig](./screenshots/ipconfig%20on%20windows.PNG)

### Nmap Scan from Kali
![Nmap Scan](./screenshots/nmap%20scan.PNG)

### Kali Network Interfaces (`ip a`)
![Kali ip a](./screenshots/output%20IP%20A%20on%20Kali.PNG)

### Wireshark TCP SYN Packet Filter View
![Wireshark SYN Scan](./screenshots/Wire%20shark%20display%20filter.PNG)

---

## ✅ Summary

This lab demonstrated the process of performing and analyzing a TCP SYN scan in a virtual lab environment. I gained practical experience using Nmap and Wireshark, and confirmed successful communication between isolated VMs using Host-Only networking. Future labs will build on this by adding endpoint logging with Sysmon, SIEM tools like Wazuh, and incident detection workflows.

