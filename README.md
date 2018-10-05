# Network Security Checklist

## Abstract

This is a checklist that may help you defending your network against cyber attacks.

## All OS

You should match this section against all operating systems.

- [ ] Ensure system is patched and up to date
- [ ] Implement proper least privilege
- [ ] Run a layered endpoint defense strategy
- [ ] Enforce complex passwords
- [ ] If no application protecting IPv6, disable IPv6
- [ ] Enable password rotation
- [ ] Disable user accounts after login failures
- [ ] Use dual factor authentication if possible
- [ ] Centralized authentication service
- [ ] Monitor log messages with Logwatch

## Windows

- [ ] Remove PowerShell v2
- [ ] Limit execution of script content (WSH)
    - [ ] Constrained language
    - [ ] block powershell interpreter
- [ ] Enable system wide transcript files
- [ ] Restrict macro execution
- [ ] Disable local administrator accounts
- [ ] Disable NTLM (use kerberos)
- [ ] Disable SMBv1
- [ ] Enable SMB signing
- [ ] Deploy Microsoft [LAPS](https://technet.microsoft.com/en-us/mt227395.aspx)
- [ ] Disabled [LLMNR](https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution)
- [ ] Disable [NetBIOS-NS](https://en.wikipedia.org/wiki/NetBIOS)
- [ ] Disable WDigest and caching of cleartext credentials
- [ ] Create an entry for [WPAD](https://en.wikipedia.org/wiki/Web_Proxy_Auto-Discovery_Protocol) deweaponize poisoning
- [ ] Limit use of privileged accounts to only manage explicit privileged machines

## Linux

- [ ] Minimize packages
- [ ] Check listening ports
- [ ] Disable unnecessary services
- [ ] Disable root login
- [ ] Login whitelist
- [ ] SSHv2 enabled
- [ ] Deny users from using Cronjobs
- [ ] enable SELinux
- [ ] Enable iptables (ufw)
- [ ] Disable Ctrl+Alt+Delete in `/etc/inittab`
- [ ] Disable interactive hotkey startup at boot
- [ ] Check accounts for empty passwords
- [ ] Keep `/boot` read-only
- [ ] Ignore ICMP / Broadcast request
- [ ] Check file permissions (777, SUID, SGID)
- [ ] Check files with no owners
- [ ] Deploy security pakcages (`tiger`, `tripwire`, `rkhunter`)
- [ ] Deploy `auditd` to check for read / write events
- [ ] Deploy `fail2ban` / `denyhost` as IDS
- [ ] Set GRUB bootloader password
- [ ] Configure sysctl ([Linux Kernel /etc/sysctl.conf Security Hardening](https://www.cyberciti.biz/faq/linux-kernel-etcsysctl-conf-security-hardening/))

## Networking

- [ ] Set up ARP poisoning mitigation ([ARP Poisoning Attack and Mitigation Techniques](https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-6500-series-switches/white_paper_c11_603839.html))
- [ ] Check ACL items
- [ ] No split tunneling
- [ ] Check DMZ
- [ ] Check OOB
- [ ] Routing protocol authentication
- [ ] STP Enabled
- [ ] VLAN configured properly
- [ ] Segregate legacy technology
