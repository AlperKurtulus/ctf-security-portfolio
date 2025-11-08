# 🎯 TryHackMe Portfolio

**Profile:** [TheJker](https://tryhackme.com/p/TheJker)  
**Rooms Completed:** 130+  
**Completed Paths:** 3  
**Badges Earned:** 18  

---

## 📊 Overview

This directory contains my complete TryHackMe journey, including detailed writeups, custom automation scripts, and comprehensive progress tracking. The content demonstrates practical cybersecurity skills across multiple domains including web application security, penetration testing, privilege escalation, and security automation.

### Achievements

- ✅ **Jr Penetration Tester Path** - Complete penetration testing methodology
- ✅ **Web Fundamentals Path** - Deep dive into web security
- ✅ **Pre Security Path** - Cybersecurity foundations
- 🏆 **18 Badges Earned** - Including Webbed, OWASP Top 10, SQL Slayer, and more
- 🎯 **130+ Rooms Completed** - Across 14 different categories

---

## 📁 Directory Structure

```
tryhackme/
├── PROGRESS.md              # Detailed tracking of all 130+ rooms
├── writeups/                # Comprehensive room writeups
│   ├── web-security/        # Web application vulnerabilities
│   ├── privilege-escalation/# Linux & Windows privilege escalation
│   ├── network-security/    # Network reconnaissance and exploitation
│   └── boxes/               # Complete CTF box walkthroughs
├── scripts/                 # Custom security automation tools
│   ├── enumeration/         # Reconnaissance automation
│   ├── exploitation/        # Exploit generation tools
│   ├── post-exploitation/   # Post-compromise utilities
│   └── utilities/           # Helper scripts
└── badges/                  # Badge achievements documentation
```

---

## 📝 Writeups

### Web Application Security

Detailed writeups covering modern web vulnerabilities:

- **SQL Injection** - Database exploitation techniques
- **Cross-Site Scripting (XSS)** - Reflected, stored, and DOM-based XSS
- **Server-Side Request Forgery (SSRF)** - Internal network access
- **XML External Entity (XXE)** - XML parser exploitation
- **Server-Side Template Injection (SSTI)** - Template engine attacks
- **Authentication Bypass** - Login mechanism vulnerabilities
- **File Inclusion** - LFI and RFI exploitation
- **Insecure Deserialization** - Object injection attacks

### Privilege Escalation

Comprehensive escalation techniques:

- **Linux PrivEsc** - SUID binaries, sudo misconfigurations, kernel exploits
- **Windows PrivEsc** - Token impersonation, service exploits, registry manipulation

### Network Security

Network-focused security testing:

- **Nmap Mastery** - Advanced port scanning and service enumeration
- **Protocol Analysis** - Understanding and exploiting network protocols
- **Firewall Evasion** - Bypassing network security controls

### CTF Boxes

Complete walkthroughs of popular boxes:

- **Blue** - Windows exploitation with EternalBlue
- **Pickle Rick** - Web exploitation and privilege escalation
- **RootMe** - Linux privilege escalation

---

## 🛠️ Custom Scripts

### Enumeration Tools

**auto_enum.sh** - Comprehensive automated reconnaissance script

- Automated Nmap scanning (quick, detailed, UDP, vulnerability scans)
- Web enumeration (Gobuster, Nikto, WhatWeb)
- SMB enumeration (enum4linux, smbclient)
- DNS and SNMP enumeration
- Organized output directory structure
- Color-coded status reporting

**Usage:**
```bash
./auto_enum.sh <target_ip> [output_dir]
```

### Exploitation Tools

**revshell_generator.py** - Multi-language reverse shell payload generator

- Supports 25+ reverse shell types
- Languages: Bash, Python, PHP, Netcat, Perl, Ruby, PowerShell, and more
- PowerShell Base64 encoding
- URL encoding for web payloads
- Interactive TTY upgrade instructions
- Color-coded output

**Usage:**
```bash
python3 revshell_generator.py
```

### Post-Exploitation Tools

**linux_privesc_check.sh** - Linux privilege escalation enumeration

- System and kernel information
- User and group enumeration
- Sudo privilege checking
- SUID/SGID binary discovery
- Writable file and directory detection
- Cron job analysis
- Network configuration review
- Running process enumeration
- Capability checking
- Environment variable analysis
- Automated recommendations

**Usage:**
```bash
./linux_privesc_check.sh
```

---

## 🎯 Learning Paths Completed

### 1. Jr Penetration Tester

**Duration:** Comprehensive pathway covering complete pentesting lifecycle

**Modules Completed:**
- Introduction to Pentesting
- Network Security
- Web Application Security
- Privilege Escalation (Linux & Windows)
- Metasploit Framework
- Burp Suite Mastery
- Post-Exploitation Techniques

**Skills Gained:**
- Complete penetration testing methodology
- From reconnaissance to reporting
- Professional-grade testing techniques

### 2. Web Fundamentals

**Duration:** In-depth web security training

**Modules Completed:**
- How the Web Works
- HTTP Protocol Deep Dive
- OWASP Top 10 Vulnerabilities
- Burp Suite Professional Usage
- Authentication & Authorization
- API Security

**Skills Gained:**
- Advanced web application testing
- API security assessment
- Modern web vulnerability exploitation

### 3. Pre Security

**Duration:** Foundation building in cybersecurity

**Modules Completed:**
- Networking Fundamentals
- Linux Basics
- Windows Basics
- Web Technology Fundamentals

**Skills Gained:**
- Strong foundation in IT and security
- Understanding of core technologies
- Preparation for advanced topics

---

## 🏅 Badge Collection

### Web Security Badges (5)
- 🕸️ **Webbed** - Web fundamentals mastery
- 🌐 **World Wide Web** - Advanced web security
- 🎯 **Intro to Web Hacking** - Web application basics
- 🔫 **Burp'ed** - Burp Suite proficiency
- 🔒 **OWASP Top 10** - OWASP vulnerability expertise

### System Security Badges (3)
- 🐧 **cat linux.txt** - Linux fundamentals
- 💣 **Metasploitable** - Metasploit mastery
- 🔍 **System Sniffer** - System enumeration

### Penetration Testing Badges (5)
- ⚔️ **Sword Apprentice** - Offensive security
- 🛡️ **Shield Apprentice** - Defensive security
- 🎯 **Pentesting Principles** - Core methodology
- 🔧 **Pentester Tools** - Tool proficiency
- 🗝️ **Authentication Striker** - Auth vulnerabilities

### Specialized Badges (4)
- 🌐 **Networking Nerd** - Network security
- 🗄️ **SQL Slayer** - SQL injection mastery
- 🏆 **Gold League** - Competitive performance
- 💙 **Blue** - Defensive security

### General Badges (1)
- ✅ **Cyber Ready** - Security readiness

---

## 📈 Progress Statistics

### Completion by Category

| Category | Rooms | Percentage |
|----------|-------|------------|
| Web Application Security | 30+ | 23% |
| Injection Vulnerabilities | 16 | 12% |
| Network Security | 23 | 18% |
| Tools & Exploitation | 11 | 8% |
| Windows Security | 8 | 6% |
| Linux Security | 6 | 5% |
| Other Categories | 36 | 28% |

### Difficulty Distribution

- **Easy:** 65 rooms (50%)
- **Medium:** 50 rooms (38%)
- **Hard:** 15 rooms (12%)

---

## 🎓 Skills Demonstrated

### Technical Proficiency

1. **Web Application Testing**
   - OWASP Top 10 vulnerabilities
   - Advanced injection techniques
   - API security testing
   - Authentication bypass methods

2. **Network Security**
   - Port scanning and enumeration
   - Service exploitation
   - Network protocol analysis
   - Firewall evasion techniques

3. **System Security**
   - Linux and Windows privilege escalation
   - System hardening analysis
   - Configuration review
   - Post-exploitation techniques

4. **Security Automation**
   - Custom script development
   - Workflow automation
   - Tool integration
   - Efficient reconnaissance

### Soft Skills

- **Persistence** - Completing 130+ rooms requires dedication
- **Problem Solving** - Each room presents unique challenges
- **Continuous Learning** - Active engagement with new content
- **Documentation** - Maintaining detailed progress tracking

---

## 🔗 Resources

### TryHackMe Platform
- [My Profile](https://tryhackme.com/p/TheJker)
- [TryHackMe Homepage](https://tryhackme.com/)

### Tools & References
- [GTFOBins](https://gtfobins.github.io/) - Unix binary exploitation
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - Security payloads
- [HackTricks](https://book.hacktricks.xyz/) - Pentesting methodology
- [Exploit-DB](https://www.exploit-db.com/) - Exploit database

---

## 📊 Future Goals

- [ ] Complete 200+ rooms
- [ ] Earn all available badges
- [ ] Complete additional learning paths
- [ ] Master Active Directory security
- [ ] Advance to red team operations

---

## ⚖️ Legal Disclaimer

All activities documented here were performed in authorized TryHackMe environments. The techniques and tools described should only be used:

- In approved learning environments
- With explicit authorization
- For educational purposes
- In compliance with applicable laws

**Unauthorized access to computer systems is illegal.**

---

*Last Updated: January 2025*  
*This portfolio demonstrates practical cybersecurity skills acquired through hands-on learning.*
