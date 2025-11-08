# TryHackMe Portfolio

![TryHackMe](https://img.shields.io/badge/TryHackMe-130%2B_Rooms-C11111?style=for-the-badge&logo=tryhackme)
![Paths](https://img.shields.io/badge/Completed_Paths-3-success?style=for-the-badge)
![Badges](https://img.shields.io/badge/Badges-18-gold?style=for-the-badge)

## 📊 Overview

This directory contains comprehensive documentation of my TryHackMe journey, including writeups, scripts, and achievements.

**Profile:** [TheJker](https://tryhackme.com/p/TheJker)

### Statistics
- **Rooms Completed:** 130+
- **Learning Paths:** 3 (Jr Penetration Tester, Web Fundamentals, Pre Security)
- **Badges Earned:** 18
- **Skill Level:** Actively learning and expanding expertise

---

## 📁 Directory Structure

### 📝 Writeups
Detailed writeups organized by category:

```
writeups/
├── web-security/          # Web application security challenges
├── privilege-escalation/  # Linux and Windows privesc
├── network-security/      # Network reconnaissance and exploitation
└── boxes/                # Complete box walkthroughs
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

### 1. Jr Penetration Tester
**Status:** ✅ Completed

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

### 2. Web Fundamentals
**Status:** ✅ Completed

In-depth exploration of web technologies and security:
- **Web Technologies:** HTTP/HTTPS, DNS, cookies, sessions
- **Web Application Architecture:** Client-server model, APIs, databases
- **Common Vulnerabilities:** SQLi, XSS, CSRF, SSRF, XXE
- **Security Tools:** Burp Suite, SQLMap, directory busters

**Key Skills Acquired:**
- Deep understanding of web application architecture
- Identifying logic flaws and security misconfigurations
- Manual and automated vulnerability testing
- Burp Suite mastery

### 3. Pre Security
**Status:** ✅ Completed

Foundation in cybersecurity fundamentals:
- **Networking Basics:** OSI model, TCP/IP, protocols
- **Linux Fundamentals:** Command line, file system, permissions
- **Windows Fundamentals:** File system, Active Directory basics
- **Security Principles:** CIA triad, defense in depth

**Key Skills Acquired:**
- Strong foundation in networking concepts
- Comfortable with Linux and Windows environments
- Understanding of fundamental security principles
- Prepared for advanced security topics

---

## 📈 Progress Tracking

For detailed room-by-room progress, see [PROGRESS.md](./PROGRESS.md)

### Rooms by Category

| Category | Rooms Completed |
|----------|----------------|
| Web Application Security | 30+ |
| Injection Vulnerabilities | 16 |
| Authentication & Authorization | 8 |
| Network Security | 23 |
| Linux Security | 6 |
| Windows Security | 8 |
| Tools & Exploitation | 11 |
| Cryptography | 3 |
| Fundamentals | 12 |
| Defensive Security | 8 |
| Specialized Topics | 7 |
| Scripting & Programming | 4 |
| CTF Boxes | 9 |
| Miscellaneous | 4 |

---

## 🎓 Key Learning Areas

### Web Application Security
- **SQL Injection:** Union-based, blind, error-based, time-based
- **Cross-Site Scripting (XSS):** Stored, reflected, DOM-based
- **Authentication Bypass:** Logic flaws, session hijacking, token manipulation
- **File Upload Vulnerabilities:** Unrestricted upload, type bypass, path traversal
- **Server-Side Attacks:** SSRF, XXE, SSTI, deserialization

### System Exploitation
- **Linux Privilege Escalation:** SUID/SGID, sudo misconfigurations, cron jobs, kernel exploits
- **Windows Privilege Escalation:** Unquoted service paths, token manipulation, registry exploits
- **Remote Code Execution:** Command injection, file inclusion, deserialization
- **Post-Exploitation:** Lateral movement, credential harvesting, persistence

### Network Security
- **Reconnaissance:** Nmap, service enumeration, OS fingerprinting
- **Network Services:** FTP, SSH, SMB, RDP, DNS exploitation
- **Protocol Analysis:** Packet capture, traffic analysis, man-in-the-middle
- **Wireless Security:** WPA/WEP cracking, rogue AP detection

### Tooling
- **Burp Suite:** Proxy, repeater, intruder, scanner
- **Metasploit Framework:** Module selection, payload generation, post-exploitation
- **Nmap:** Port scanning, service detection, script scanning
- **Custom Scripts:** Python and Bash automation

---

## 🔍 Methodology

My approach to challenges follows a structured methodology:

### 1. Reconnaissance
- Passive information gathering
- Service enumeration
- Technology identification

### 2. Scanning & Enumeration
- Port scanning (Nmap)
- Web directory enumeration (Gobuster, ffuf)
- Service-specific enumeration (enum4linux, SMB, FTP, etc.)

### 3. Vulnerability Analysis
- Manual testing
- Automated scanning
- Version research
- Exploit identification

### 4. Exploitation
- Proof of concept development
- Exploit execution
- Initial access

### 5. Post-Exploitation
- System enumeration
- Privilege escalation
- Lateral movement
- Objective completion

### 6. Documentation
- Detailed notes
- Screenshots
- Command history
- Lessons learned

---

## 🏆 Notable Achievements

### Badges Earned (18)
- Webbed, World Wide Web, Intro to Web Hacking
- Burp'ed, OWASP Top 10, SQL Slayer
- Networking Nerd, cat linux.txt, Metasploitable
- System Sniffer, Pentesting Principles, Authentication Striker
- Pentester Tools, Gold League, Cyber Ready
- Blue, Sword Apprentice, Shield Apprentice

### Skills Demonstrated
- **Web Security:** Advanced understanding of OWASP Top 10
- **System Exploitation:** Linux and Windows privilege escalation
- **Networking:** Comprehensive network security knowledge
- **Tool Proficiency:** Burp Suite, Metasploit, Nmap, and more
- **Automation:** Custom script development for efficiency

---

## 📚 Resources

### Useful Links
- [TryHackMe Platform](https://tryhackme.com/)
- [TryHackMe Blog](https://blog.tryhackme.com/)
- [Official Discord](https://discord.gg/tryhackme)

### Recommended Rooms for Beginners
1. **Basic Pentesting** - Great introduction
2. **OWASP Top 10** - Essential web security
3. **Linux PrivEsc** - Fundamental privilege escalation
4. **Burp Suite Basics** - Tool mastery
5. **Metasploit** - Framework fundamentals

---

## 🤝 Contributing

While this is a personal portfolio, I'm happy to:
- Answer questions about specific challenges
- Share additional tips and techniques
- Discuss alternative approaches
- Collaborate on tool development

Feel free to open an issue or reach out!

---

## ⚠️ Ethical Use

All content in this directory is for **educational purposes only**. Always:
- Obtain proper authorization before testing
- Follow TryHackMe's Terms of Service
- Practice responsible disclosure
- Respect the platform and other users

---

## 📞 Contact

- **TryHackMe:** [TheJker](https://tryhackme.com/p/TheJker)
- **GitHub:** [@AlperKurtulus](https://github.com/AlperKurtulus)

---

*Last Updated: November 2025*
