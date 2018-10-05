# Network Security Checklist

## Abstract

This is a checklist that may help you defending your network against cyber attacks.

## All OS

You should match this section against all operating systems.

- [ ] Ensure system is patched and up to date
- [ ] Implement proper least privilege
- [ ] Run a layered endpoint defense strategy
- [ ] Enforce complex passwords

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
- [ ] Enable password rotation
- [ ] Disabled [LLMNR](https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution)
- [ ] Disable [NetBIOS-NS](https://en.wikipedia.org/wiki/NetBIOS)
- [ ] Disable WDigest and caching of cleartext credentials
- [ ] Create an entry for [WPAD](https://en.wikipedia.org/wiki/Web_Proxy_Auto-Discovery_Protocol) deweaponize poisoning
- [ ] Limit use of privileged accounts to only manage explicit privileged machines

## Linux

- [ ] TODO