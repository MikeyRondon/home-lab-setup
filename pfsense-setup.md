# pfSense Setup & Configuration

## 🎯 Objective
Implement basic firewalling and outbound NAT to allow LAN clients Internet access while blocking unsolicited inbound traffic.

## 1. Project Overview
- Goals & features
- Lab topology diagram

## 2. Environment Preparation
- VM host details
- ISO download & checksums

## 3. pfSense Installation
- VM creation (vCPU, RAM, disks, NICs)
- Boot installer & partitioning

## 4. Initial Configuration
- Assign interfaces
- WebGUI access setup
- Admin password change

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
