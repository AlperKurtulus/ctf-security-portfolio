# Privilege Escalation Writeups

Detailed writeups on privilege escalation techniques for both Linux and Windows systems.

## 📝 Available Writeups

### [Linux Privilege Escalation](./linux-privesc.md)
- **Difficulty:** Medium
- **Focus:** SUID/SGID exploitation, sudo misconfigurations, cron jobs
- **Key Skills:** System enumeration, exploit identification, privilege escalation

### [Windows Privilege Escalation](./windows-privesc.md)
- **Difficulty:** Medium
- **Focus:** Token manipulation, service exploitation, registry abuse
- **Key Skills:** Windows internals, privilege escalation vectors

## 🎯 Learning Objectives

### Linux Privilege Escalation
- System enumeration techniques
- SUID/SGID binary exploitation
- Sudo privilege abuse
- Cron job manipulation
- Capabilities exploitation
- Kernel exploits
- NFS misconfiguration

### Windows Privilege Escalation
- Token impersonation
- Unquoted service paths
- Service binary hijacking
- Registry key permissions
- Scheduled task abuse
- DLL hijacking
- Windows kernel exploits

## 🛠️ Essential Tools

### Linux Tools
- **LinPEAS** - Automated enumeration
- **LinEnum** - System enumeration script
- **pspy** - Process monitoring without root
- **GTFOBins** - Unix binary exploitation
- **linux-exploit-suggester** - Kernel exploit finder

### Windows Tools
- **WinPEAS** - Windows enumeration
- **PowerUp** - PowerShell privilege escalation
- **Seatbelt** - Security-focused enumeration
- **Sherlock** - Missing patch finder
- **Mimikatz** - Credential extraction

## 📚 Common Techniques

### Linux Vectors
1. **SUID/SGID Binaries**
   - Find: `find / -perm -4000 2>/dev/null`
   - Exploit with GTFOBins

2. **Sudo Misconfigurations**
   - Check: `sudo -l`
   - Exploit NOPASSWD entries

3. **Cron Jobs**
   - Check: `/etc/crontab`, `crontab -l`
   - Writable scripts in PATH

4. **Kernel Exploits**
   - Check version: `uname -a`
   - Search exploits: `searchsploit kernel`

5. **Capabilities**
   - Find: `getcap -r / 2>/dev/null`
   - Exploit cap_setuid capabilities

### Windows Vectors
1. **Service Exploits**
   - Unquoted service paths
   - Weak service permissions
   - Binary hijacking

2. **Registry Exploits**
   - AlwaysInstallElevated
   - AutoRun keys

3. **Token Manipulation**
   - SeImpersonatePrivilege
   - Potato family exploits

4. **Scheduled Tasks**
   - Weak permissions
   - Missing binaries

## 🔍 Enumeration Methodology

### Phase 1: System Information
- OS version and architecture
- Current user and privileges
- Network configuration
- Running processes and services

### Phase 2: User Enumeration
- Current user privileges
- Other user accounts
- Group memberships
- Home directories and files

### Phase 3: File System
- World-writable directories
- SUID/SGID files (Linux)
- File permissions
- Configuration files with credentials

### Phase 4: Processes and Services
- Running processes
- Scheduled tasks/cron jobs
- Installed software versions
- Service configurations

### Phase 5: Network
- Network connections
- Open ports
- Firewall rules
- Network shares

## 📖 Resources

- [GTFOBins](https://gtfobins.github.io/)
- [LOLBAS (Living Off The Land Binaries)](https://lolbas-project.github.io/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackTricks](https://book.hacktricks.xyz/)
- [Windows Privilege Escalation Guide](https://www.fuzzysecurity.com/tutorials/16.html)

---

*Master the art of privilege escalation through practice and understanding! 🚀*
