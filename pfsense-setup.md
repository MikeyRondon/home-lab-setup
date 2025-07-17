# pfSense Setup & Configuration

## 🎯 Objective
Implement basic firewalling and outbound NAT to allow LAN clients Internet access while blocking unsolicited inbound traffic.

---

## Lab Topology & Resources

Host: VirtualBox on Windows 10 host

pfSense VM: 2 vCPU, 4 GB RAM, 20 GB disk; Adapter 1 = NAT (WAN), Adapter 2 = Host‑only (LAN)

Host‑only network: vboxnet0 (192.168.56.1/24), built‑in DHCP disabled

LAN client VMs: Windows 10, Kali, Wazuh (each with second adapter on vboxnet0)

---

## Environment Preparation

Download latest pfSense CE AMD64 ISO from https://www.pfsense.org/download/

Verify SHA256 checksum:

```powershell
Get-FileHash .\pfsense-CE-*.iso -Algorithm SHA256
```

Store verified ISO in lab-resources/isos/

---

## pfSense VM Creation

New VM → Name: pfSense, Type: BSD, Version: FreeBSD (64-bit)

Memory: 4096 MB; Disk: 20 GB VDI, dynamically allocated

Storage → Attach ISO to Controller: IDE

Network → Adapter 1: NAT; Adapter 2: Host‑only (vboxnet0)

screenshot: pfsense_vm_settings.png

---

## Installation & Initial Config

Boot installer → Select Install, accept default keymap and terminal

Partitioning: Auto (UFS)

Interface Assignment: em0 → WAN; em1 → LAN

LAN IP: Static 192.168.56.1/24, enable DHCP 192.168.56.100–200

Complete install → Remove ISO, reboot

screenshot: pfsense_console_interfaces.png

---
Host‑only Networking Fix

Disable built‑in DHCP on vboxnet0 in VirtualBox Host Network Manager

On pfSense console:
```yaml
2) Set interface(s) IP address
Select interface: 2 (LAN)
Configure IPv4 via DHCP? n
Enter new LAN IPv4 address: 192.168.56.1
Subnet bit count: 24
<ENTER> for no gateway
Configure IPv6 via DHCP6? n
<ENTER> to keep HTTPS
Enable DHCP server on LAN? y
Accept default range 192.168.56.100–200
```

Reboot pfSense, renew Windows lease:

ipconfig /renew "Ethernet 2"

screenshot: windows_lan_ipconfig.png

---

Setup Wizard

Wizard → Next

General Info: Hostname pfsense, Domain home.arpa, DNS 1.1.1.1, Disable override ✓

WAN: DHCP

LAN: 192.168.56.1/24, DHCP 192.168.56.100–200

Skip optional CARP/IP Alias

Time Zone: Configure, Next

Finish → Dashboard

screenshot: pfsense_login.png & pfsense_change_password.png

---

Dashboard Verification

Confirm WAN = 10.0.2.x; LAN = 192.168.56.1

screenshot: pfsense_dashboard.png

---








```
## 5. Basic Firewall & NAT
- LAN→WAN rules
- NAT outbound mode
- Testing Internet access

## 6. VPN Setup (Optional)
- OpenVPN or IPsec tunnel
- Client export & connection testing

## 7. IDS/IPS Integration
- Installing Suricata package
- Rule feeds & alert testing

## 8. Monitoring & Logs
- ntopng/darkstat setup
- Sending logs to Wazuh (syslog forwarder)

## 9. Advanced Topics (Optional)
- Multi‑WAN/load balancing
- Captive portal
- High availability

## 10. Lessons Learned & Next Steps
- What worked, what didn’t
- Ideas for expanding the lab
```
