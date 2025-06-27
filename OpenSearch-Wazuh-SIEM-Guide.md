# Building a Home-Lab SIEM with OpenSearch & Wazuh

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Setup Steps](#setup-steps)

   * [1. Add OpenSearch Repos & Keys](#1-add-opensearch-repos--keys)
   * [2. Install & Configure OpenSearch](#2-install--configure-opensearch)
   * [3. Install & Configure OpenSearch Dashboards](#3-install--configure-opensearch-dashboards)
   * [4. Install the Wazuh Dashboard Plugin](#4-install-the-wazuh-dashboard-plugin)
   * [5. Enroll Windows Sysmon Agent](#5-enroll-windows-sysmon-agent)
   * [6. Verify Events in Wazuh](#6-verify-events-in-wazuh)
5. [Screenshots](#screenshots)
6. [Lessons Learned](#lessons-learned)

---

## Overview

This guide walks through deploying a home-lab SIEM using OpenSearch, OpenSearch Dashboards, and Wazuh. You will:

* Collect Windows Sysmon events centrally
* Ship logs from a Windows 10 VM to a Wazuh manager on Ubuntu
* Visualize alerts and events in OpenSearch Dashboards

---

## Architecture

```text
+----------------------+       +------------------------------------+
| Windows 10 VM        |       | Wazuh-Manager VM (Ubuntu 22.04)    |
| - Sysmon installed   |       | - OpenSearch 2.19.1                |
| - Wazuh agent        | ----> | - OpenSearch Dashboards 2.19.1     |
|                      | host- | - Wazuh Manager 4.12.0             |
+----------------------+ only  +------------------------------------+
```

* **Host-only network**: 192.168.56.0/24 between VMs
* **NAT network**: Internet access for updates

---

## Prerequisites

* VirtualBox with two VMs:

  * Ubuntu 22.04 (≥2 vCPU, 4 GB RAM)
  * Windows 10
* Sysmon installed on the Windows VM
* Admin access on both VMs

---

## Setup Steps

### 1. Add OpenSearch Repos & Keys

```bash
# Import GPG key
wget -qO - https://artifacts.opensearch.org/publickeys/opensearch.pgp \
  | sudo apt-key add -

# Core repo
cat <<EOF | sudo tee /etc/apt/sources.list.d/opensearch.list
deb https://artifacts.opensearch.org/releases/bundle/opensearch/2.x/apt stable main
EOF

# Dashboards repo
cat <<EOF | sudo tee /etc/apt/sources.list.d/opensearch-dashboards.list
deb https://artifacts.opensearch.org/releases/bundle/opensearch-dashboards/2.x/apt stable main
EOF

sudo apt update
```

### 2. Install & Configure OpenSearch

```bash
sudo apt install -y opensearch

# Bind to all interfaces
sudo sed -i 's/#network\.host:.*/network.host: 0.0.0.0/' /etc/opensearch/opensearch\.yml

sudo systemctl enable opensearch.service
sudo systemctl start opensearch.service

curl -I http://localhost:9200   # expect HTTP/1.1 200 OK
```

### 3. Install & Configure OpenSearch Dashboards

```bash
sudo apt install -y opensearch-dashboards

# Bind to all interfaces
sudo sed -i 's/#server\.host:.*/server.host: "0.0.0.0"/'   /etc/opensearch-dashboards/opensearch_dashboards\.yml

# Point to local OpenSearch
sudo sed -i 's|#opensearch\.hosts:.*|opensearch.hosts: ["http://localhost:9200"]|'   /etc/opensearch-dashboards/opensearch_dashboards\.yml

sudo systemctl enable opensearch-dashboards.service
sudo systemctl restart opensearch-dashboards.service

curl -I http://127.0.0.1:5601  # expect HTTP/1.1 200 OK
```

### 4. Install the Wazuh Dashboard Plugin

```bash
sudo apt install -y wazuh-dashboard
sudo systemctl restart opensearch-dashboards.service

ls -l /usr/share/opensearch-dashboards/plugins | grep wazuh
```

### 5. Enroll Windows Sysmon Agent

```bash
# On Ubuntu manager
sudo /var/ossec/bin/manage_agents
# A → name=Win10-Sysmon, IP=192.168.56.xxx
# Q, E → copy authentication key

# On Windows 10 VM
msiexec /i https://packages.wazuh.com/4.x/windows/wazuh-agent-4.12.0-1.msi ^
 /quiet WAZUH_MANAGER='192.168.56.xxx' WAZUH_AGENT_NAME='Win10-Sysmon' ^
 WAZUH_AUTHD_AUTHENTICATION_KEY='<paste key>'

# Configure Sysmon channel
# Edit C:\Program Files\Ossec\ossec.conf:
<localfile>
  <log_format>eventchannel</log_format>
  <location>Microsoft-Windows-Sysmon/Operational</location>
</localfile>

Restart-Service wazuh-agent
```

### 6. Verify Events in Wazuh

* Open your host browser to `http://192.168.56.xxx:5601/app/wazuh`
* Click the **shield icon (Wazuh)** in the sidebar
* Under **Security Events**, confirm you see Sysmon actions (ProcessCreate, NetworkConnect, etc.)

---

## Screenshots

Place screenshots in `/docs/screenshots/` and reference them here:

1. OpenSearch Dashboards home
2. Wazuh Overview page
3. Sample Sysmon event

---

## Lessons Learned

* Pivoted from Elasticsearch/Kibana due to plugin version conflicts with Wazuh 4.12
* OpenSearch Dashboards provides native support and removes compatibility headaches
* Real-world troubleshooting: DNS fixes, network binding, package versions

---

*End of guide*
