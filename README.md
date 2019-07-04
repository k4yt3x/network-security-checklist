# Network Security Checklist<!-- omit in toc -->

- [Abstract](#Abstract)
- [All OS](#All-OS)
- [Windows](#Windows)
- [Linux](#Linux)
- [Networking](#Networking)
- [Explainations](#Explainations)
  - [IPv6](#IPv6)
  - [PowerShell V2](#PowerShell-V2)
  - [NTLM and Kerberos](#NTLM-and-Kerberos)
    - [Weaknesses](#Weaknesses)
    - [NLM Attacks](#NLM-Attacks)
    - [Kerberos Attacks](#Kerberos-Attacks)
  - [WPAD](#WPAD)
  - [RODC](#RODC)
- [Supplemental Information](#Supplemental-Information)
  - [PowerSploit](#PowerSploit)
  - [Active Directory](#Active-Directory)
    - [Groups with AD Admin Rights](#Groups-with-AD-Admin-Rights)
    - [Group Policy](#Group-Policy)
    - [AD Asset Discovery](#AD-Asset-Discovery)
  - [Microsoft Password & Active Directory](#Microsoft-Password--Active-Directory)
  - [Useful Links](#Useful-Links)

## Abstract

This is a checklist that may help you defending your network against cyber attacks.

## All OS

You should match this section against all operating systems.

- [ ] Ensure system is patched and up to date
- [ ] Implement proper least privilege
- [ ] Run a layered endpoint defense strategy
- [ ] Enforce complex passwords
- [ ] If no application protecting IPv6, disable IPv6 [[1]]
- [ ] Enable password rotation
- [ ] Disable user accounts after login failures
- [ ] Use dual factor authentication if possible
- [ ] Centralized authentication service
- [ ] Monitor log messages with Logwatch

## Windows

- [ ] Remove PowerShell v2 [[2]]
- [ ] Limit execution of script content (WSH)
    - [ ] Constrained language
    - [ ] block powershell interpreter
- [ ] Enable system wide transcript files
- [ ] Restrict macro execution
- [ ] Disable local administrator accounts
- [ ] Disable NTLM [[3]]
- [ ] Enable Kerberos with AES encryption
- [ ] Disable SMBv1
- [ ] Enable SMB signing
- [ ] Deploy Microsoft [LAPS](https://technet.microsoft.com/en-us/mt227395.aspx)
- [ ] Use fine grained password policy
- [ ] Disabled [LLMNR](https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution)
- [ ] Disable [NetBIOS-NS](https://en.wikipedia.org/wiki/NetBIOS)
- [ ] Disable WDigest and caching of cleartext credentials
- [ ] Create an entry for [WPAD](https://en.wikipedia.org/wiki/Web_Proxy_Auto-Discovery_Protocol) deweaponize poisoning [[4]]
- [ ] Limit use of privileged accounts to only manage explicit privileged machines
- [ ] Make use of Read-Only Domain Controllers ([RODC](https://docs.microsoft.com/en-us/windows/desktop/ad/rodc-and-active-directory-schema)) [[5]]
- [ ] Change DSRM account password or create DSRM account on DC
- [ ] Set DsrmAdminLogonBehavior = 1 (force stop AD for DSRM logon)
- [ ] Enable UNC hardening (MS15-011)
- [ ] No computer accounts in admin groups
- [ ] Identify who has AD admin rights (domain/forest)
- [ ] Identify who can logon to Domain Controllers (and admin rights to virtual environment hosting virtual DCs)
- [ ] Scan ADs, OUs, AdminSDHolder, and GPOs for inappropriate custom permissions
- [ ] Ensure AD administrators (Domain Admins) protect their credentials by not logging into untrusted systems (workstations).
- [ ] Limit service account rights that are currently DA (or equivalent).
- [ ] Enable compound authentication
- [ ] Enable Dynamic access control
- [ ] Check [LSA protection](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [ ] Add administrator accounts to "Protected Users" security group
- [ ] Configure Just Enough Administration ([JEA](https://docs.microsoft.com/en-us/powershell/jea/overview))
- [ ] Enable Privileged Access Management feature

## Linux

- [ ] Minimize packages
- [ ] Check listening ports
- [ ] Disable unnecessary services
- [ ] Disable root login
- [ ] Login whitelist
- [ ] SSHv2 enabled
- [ ] Deny users from using Cronjobs
- [ ] enable `SELinux`
- [ ] Enable `iptables` (`ufw`)
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

## Explainations

### IPv6

When implementing IPv6 on a network, remember a basic principle: **you need to configure security for IPv4 and IPv6 separately**. For example, if ACL is deployed on the router for IPv6, it does not apply for IPv6.

Configure ACL (deny all pings).

```
(config)#access-list 100 deny icmp any any echo
```

Apply ACL to interface GigabitEthernet 0/0. Note how you have to apply ACL to both IPv4 and IPv6 on both directions.

```
(config)#ip access-group 100 in
(config)#ip access-group 100 out
(config)#ipv6 access-group 100 in
(config)#ipv6 access-group 100 out
```

### PowerShell V2

Even if powershell is disabled

### NTLM and Kerberos

- [Network security: Restrict NTLM: Audit NTLM authentication in this domain](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-audit-ntlm-authentication-in-this-domain)

NTLM is how Windows stores passwords and authenticates. It uses MD4 to store passwords. Network authentication uses the hash, but not the original password. This makes NTLM vulnerable to NTLM relaying. By relaying the authentication request to a rogue server, the target machine will attempt to log in into the server, without verifying the identity of the server. Then, the rogue server can relay the authentication requests to a target server, thus gaining access to the server.

#### Weaknesses

|NTLM|Kerberos|
|-|-|
|Typically mix of NTLM v1 & v2|Supported encryption types|
|Encryption: DES or MD4 or HMAC-MD5|RC4 Encryption = NTLM Hash|
|No mutual authentication|Compromise of TLK = compromise of Kerberos|
|Hash used behind the scenes|Stolen credentials reusable until ticket expires|
|Stolen credentials reusable until password changed|TGS PAC validation not typically performed|
|Credentials can be "leaked" via web browser||

#### NLM Attacks

- SMB Relay - simulate SMB server or relay to attacker system
- Intranet HTTP NTLM auth - relay to rogue server
- NBNS/LLMNR - respond to NetBIOS broadcasts
- HTTP - SMB NTLM relay
- WPAD - network proxy
- ZackAttack - SOCKS proxy, SMB/HTTP, LDAP, etc.
- Pass the Hash (PtH)

Services that NTLM will attempt to login automatically:

- SMB
- HTTP (Exchange Web Services)
- LDAP
- MSSQL

#### Kerberos Attacks

- Replay attacks
- Pass the Ticket (reuse tickets)
- Over-pass the hash (pass the key)
- Offline (user) password cracking (Kerberoast)
- Forged tickets - Golden/Silver
- Diamond PAC
- MS14-068

### WPAD

By default, Windows detects web proxies and tries to log in with the currently-logged-in user's credentials. This might cause leakage of HTTP credentials, and should be disabled.

### RODC

- DC services without storing passwords.
- Only receives inbound replication from writable DCs.
- Requires cached passwords for local site authentication.
- Enables delegation of RODC administration to non AD admin.
- Use cases:
    - Physical security issues.
    - Third party software install on DC.
    - "Untrusted admin" scenario.

## Supplemental Information

### PowerSploit

[PoewrSploit](https://github.com/PowerShellMafia/PowerSploit) is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment.

### Active Directory

- All authenticated users have read access to:
    - Most (all) objects & their attributes in AD (even across trusts).
    - Most (all) contents in the domain share "SYSVOL" which can contain interesting scripts & files.
- A standard user account can:
    - Have elevated rights through the magic of "SID History" without being a member of any groups.
    - Have the ability to modify users/groups without elevated rights through custom OU permissions.
    - Compromise an entire AD domain simply by improperly being granted modify rights to an OU or domain-linked GPO.
- AD objects are not deleted when removed from the list.
- AD forest is the security boundary.
- All AD information stays in the boundary.
- All domains within the forest implicitly trust each other through automatic trust of the parent and the child domain.
- Domain is a partition of the forest.
- Trust can exist between forests.
- **Federation** is more secure than trust. It creates a ticket for every authenticated request, thus preventing unauthorized access.
- No security policy = default (minimum).
- DCs need additional security policies (GPO).
- Windows systems (DC) need to be configured for enhanced auditing.
- You can query DNS through LDAP.

#### Groups with AD Admin Rights

- Domain Admins
- Enterprise Admins
- Domain "Administrators"
- Custom Delegation at domain/OU level
- Groups with DC logon rights

#### Group Policy

- User & computer management
- Create GPO & link to OU
- Comprised of:
    - Group Policy Object (GPO) in AD
    - Group Policy Template (GPT) files in SYSVOL
    - Group Policy Client Side Extensions on clients

#### AD Asset Discovery

- Domain Controllers
- Exchange Servers
- SCCM
- DFS Shares

### Microsoft Password & Active Directory

- TPM generates user public-private key pair (public key added to AD user attribute).
- User credential device-specific secrets stored in VSM.
- Machine data & user credential info combined & sent to DC for user TGT.
- Cred Guard owns system private key used to get TGT.

### Useful Links

- [DEFCON 20: Owned in 60 Seconds: From Network Guest to Windows Domain Admin](https://www.youtube.com/watch?v=nHU3ujyw_sQ)
- [Beyond the Mcse: Active Directory for the Security Professional](https://www.youtube.com/watch?v=2w1cesS7pGY)

[1]: https://github.com/K4YT3X/network-security-checklist#ipv6
[2]: https://github.com/K4YT3X/network-security-checklist#powershell-v2
[3]: https://github.com/K4YT3X/network-security-checklist#ntlm-and-kerberos
[4]: https://github.com/K4YT3X/network-security-checklist#wpad
[5]: https://github.com/K4YT3X/network-security-checklist#rodc