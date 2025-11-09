# TryHackMe Portfolio

![TryHackMe](https://img.shields.io/badge/TryHackMe-130%2B_Rooms-C11111?style=for-the-badge&logo=tryhackme)
![Paths](https://img.shields.io/badge/Completed_Paths-4-success?style=for-the-badge)
![Badges](https://img.shields.io/badge/Badges-18-gold?style=for-the-badge)

## 📊 Overview

This directory contains comprehensive documentation of my TryHackMe journey, including writeups, scripts, and achievements.

**Profile:** [TheJker](https://tryhackme.com/p/TheJker)

### Statistics
- **Rooms Completed:** 130+
- **Learning Paths:** 4 (Jr Penetration Tester, Web Fundamentals, Pre Security, Cyber Security 101)
- **Badges Earned:** 18
- **Skill Level:** Actively learning and expanding expertise
- **Last Updated:** November 9, 2025

---

## 📁 Directory Structure

### 📝 Writeups
Detailed writeups organized by category:

```
writeups/
├── boxes/                 # Complete box walkthroughs
│   └── internal.md       # Internal box (Hard) - NEW!
├── web-security/         # Web application security challenges
├── privilege-escalation/ # Linux and Windows privesc
└── network-security/     # Network reconnaissance and exploitation
```

Each writeup includes:
- Challenge overview and objectives
- Reconnaissance and enumeration methodology
- Vulnerability identification and analysis
- Exploitation techniques with code
- Post-exploitation activities
- Lessons learned and key takeaways
- Remediation recommendations

### 🛠️ Scripts
Custom automation scripts developed during challenges:

```
scripts/
├── enumeration/           # Automated reconnaissance tools
├── exploitation/          # Exploit automation and payload generation
├── post-exploitation/     # Post-compromise enumeration
└── utilities/            # Helper scripts and utilities
```

**Featured Scripts:**
- `auto_enum.sh` - Comprehensive automated enumeration
- `revshell_generator.py` - Multi-language reverse shell generator
- `linux_privesc_check.sh` - Linux privilege escalation checker

### 🏅 Badges
Documentation of earned badges and associated skills:

```
badges/
└── README.md              # Complete badge collection and descriptions
```

---

## 🎯 Completed Learning Paths

### 1. Jr Penetration Tester ✅
**Status:** Completed  
**Duration:** 3 months  
**Rooms:** 25

A comprehensive path covering essential penetration testing skills:
- **Network Security:** Port scanning, service enumeration, network exploitation
- **Web Application Security:** OWASP Top 10, authentication bypass, injection attacks
- **Linux & Windows Exploitation:** Privilege escalation, lateral movement
- **Post-Exploitation:** Data exfiltration, persistence, cleanup

**Key Skills Acquired:**
- Methodical reconnaissance and enumeration
- Identifying and exploiting common vulnerabilities
- Understanding security from an attacker's perspective
- Professional reporting and documentation

---

### 2. Web Fundamentals ✅
**Status:** Completed  
**Duration:** 2 months  
**Rooms:** 18

In-depth exploration of web technologies and security:
- **Web Technologies:** HTTP/HTTPS, DNS, cookies, sessions
- **Web Application Architecture:** Client-server model, APIs, databases
- **Common Vulnerabilities:** SQLi, XSS, CSRF, SSRF, XXE
- **Security Tools:** Burp Suite, SQLMap, directory busters

**Key Skills Acquired:**
- Deep understanding of web application architecture
- Identifying logic flaws and security misconfigurations
- Manual and automated vulnerability testing
- Web proxy usage and request manipulation

---

### 3. Pre Security ✅
**Status:** Completed  
**Duration:** 1 month  
**Rooms:** 14

Foundational knowledge for cybersecurity:
- **Networking Fundamentals:** OSI model, TCP/IP, protocols
- **Linux Basics:** Command line, file system, permissions
- **Windows Basics:** File system, user management, security features
- **Career Guidance:** Roles, certifications, learning paths

**Key Skills Acquired:**
- Strong networking fundamentals
- Linux and Windows system administration basics
- Understanding of core security principles
- Career direction and planning

---

### 4. Cyber Security 101 ✅
**Status:** Completed  
**Duration:** 1 month  
**Rooms:** 12

Introduction to cybersecurity concepts and practices:
- **Security Fundamentals:** CIA triad, threat modeling, risk assessment
- **Offensive Security:** Penetration testing methodology, red team operations
- **Defensive Security:** Blue team operations, incident response, SOC
- **Security Tools:** Introduction to common security tools and frameworks

**Key Skills Acquired:**
- Understanding of core security concepts
- Introduction to offensive and defensive security
- Security operations and monitoring basics
- Foundation for advanced cybersecurity topics

---

## 📈 Recent Achievements

### Latest Writeup: Internal Box (Hard)
**Completed:** November 9, 2025  
**Time:** 4.5 hours  
**Difficulty:** Hard

**Key Techniques:**
- WordPress exploitation via theme editor
- Manual credential hunting in `/opt` directory
- SSH local port forwarding to access internal Jenkins
- Jenkins Script Console exploitation (Groovy RCE)
- Docker container enumeration and credential discovery
- Multi-layered privilege escalation

**Lessons Learned:**
- Automated tools (LinPEAS) don't catch everything
- Manual enumeration and creative thinking are critical
- SSH tunneling is essential for accessing internal services
- Pattern-based file searching reveals hidden credentials

**Writeup:** [internal.md](./writeups/boxes/internal.md)

---

## 🎓 Skills Matrix

| Skill Category | Proficiency Level | Notes |
|---------------|------------------|-------|
| **Web Exploitation** | ⭐⭐⭐⭐ | SQLi, XSS, LFI/RFI, authentication bypass |
| **Network Enumeration** | ⭐⭐⭐⭐ | Nmap, service identification, protocol analysis |
| **Linux Privilege Escalation** | ⭐⭐⭐⭐ | SUID, sudo, capabilities, manual enumeration |
| **Windows Privilege Escalation** | ⭐⭐⭐ | Token impersonation, service exploits |
| **Burp Suite** | ⭐⭐⭐⭐ | Proxy, repeater, intruder, extensions |
| **Metasploit** | ⭐⭐⭐ | Module usage, payload generation, Meterpreter |
| **Python Scripting** | ⭐⭐⭐⭐ | Automation, exploit development |
| **Bash Scripting** | ⭐⭐⭐⭐ | Enumeration scripts, automation |
| **Active Directory** | ⭐⭐ | Basic enumeration, Kerberoasting (learning) |
| **Binary Exploitation** | ⭐⭐ | Buffer overflow basics (learning) |

**Legend:** ⭐ Basic | ⭐⭐ Intermediate | ⭐⭐⭐ Advanced | ⭐⭐⭐⭐ Expert | ⭐⭐⭐⭐⭐ Master

---

## 🚀 Next Goals

- [ ] Complete "Internal" box writeup ✅ **DONE!**
- [ ] Complete SOC Level 1 Path
- [ ] Complete Offensive Pentesting Path  
- [ ] Achieve 200 rooms completed
- [ ] Participate in TryHackMe King of the Hill
- [ ] Complete 10 Hard-level boxes
- [ ] Develop advanced automation framework
- [ ] Explore Active Directory exploitation path
- [ ] Practice buffer overflow challenges

---

## 📚 Resources

### Custom Scripts Repository
All custom scripts developed during challenges are available in the `/scripts` directory with full documentation.

### Badge Collection
View all earned badges and their requirements in `/badges/README.md`

### Progress Tracker
Detailed room-by-room progress is tracked in `PROGRESS.md`

---

## 🤝 Connect

- **TryHackMe Profile:** [TheJker](https://tryhackme.com/p/TheJker)
- **GitHub:** [AlperKurtulus](https://github.com/AlperKurtulus)
- **Repository:** [ctf-security-portfolio](https://github.com/AlperKurtulus/ctf-security-portfolio)

---

## ⚠️ Disclaimer

All writeups and techniques documented here are for educational purposes only. Always:
- Obtain proper authorization before testing
- Respect terms of service and legal boundaries
- Practice ethical hacking principles
- Never use these techniques on systems you don't own or have explicit permission to test

---

**Last Updated:** November 9, 2025  
**Maintained by:** AlperKurtulus  
**Status:** Actively updating with new challenges and writeups

---

<div align="center">

**📚 Learn | 🔒 Practice | 🎯 Master**

*Continuous learning in cybersecurity*

</div>
