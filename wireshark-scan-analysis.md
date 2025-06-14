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
