# Active Directory Lab Setup

Project Overview
A concise summary of what you’ll accomplish in this lab:

Deploy a Windows Server VM as a Domain Controller

Configure DNS and Active Directory Domain Services

Join a client VM to your new domain

# Objectives
Install and configure Windows Server as an AD DS domain controller

Create and verify a new Active Directory forest and domain

Join a Windows client to the domain

Document verification steps and next‑step recommendations

# Lab Environment
Host OS: e.g. VMware/VirtualBox on Windows 10

Domain Controller VM:

OS: Windows Server 2019 (or 2022)

CPU / RAM / Disk

Client VM:

OS: Windows 10

CPU / RAM / Disk

Network Topology:

[Insert ASCII diagram or link to image]

# Prerequisites
Windows Server ISO downloaded and mounted

Static IP reserved for DC (e.g. 192.168.56.10)

Ensure VMs are on the same host‑only network

Admin credentials for installation

# Step‑by‑Step Guide
Create & Configure the DC VM

Provision VM with recommended specs

Mount the Windows Server ISO

Install Windows Server

Follow installation wizard, set Administrator password

Set Static IP & DNS

Go to Network Settings → IPv4 → Properties

IP: 192.168.56.10, Mask: 255.255.255.0, DNS: 127.0.0.1

Add Active Directory Domain Services Role

Server Manager → Add roles and features → AD DS

Include DNS Server when prompted

Promote Server to Domain Controller

In Server Manager’s AD DS pane, click “Promote this server…”

Create a new forest (e.g. corp.local)

Set DSRM password and complete wizard

Verify DNS & AD Health

Run dcdiag and nslookup corp.local in PowerShell

Create Organizational Units & Users

Open “Active Directory Users and Computers”

Right‑click domain → New → OU (e.g. “Staff”)

Create a user account under the OU

Join Client VM to Domain

On Windows 10 VM: System → Change settings → Domain → corp.local

Authenticate with domain admin credentials

Test Domain Login

Log off and log in as your new domain user

# Verification & Troubleshooting
DNS Test:

powershell
Copy
Edit
Resolve-DnsName dc1.corp.local
Domain Join Test:

Ping DC from client: ping 192.168.56.10

View group policy: gpresult /r

# Cleanup (Optional)
Demote DC via Server Manager

Remove AD DS and DNS roles

Delete VMs

# Next Steps
Configure Group Policy Objects (GPOs) for security baseline

Delegate OU permissions for help‑desk roles

Integrate with Wazuh for DC log monitoring

Document common AD cmdlets (e.g. Get-ADUser, New-ADGroup)

# References
Microsoft Docs: Install Active Directory Domain Services

“Active Directory: Designing, Deploying, and Running Active Directory” by Brian Desmond
