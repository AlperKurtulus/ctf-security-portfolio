# TryHackMe Progress Tracker

**Profile:** [TheJker](https://tryhackme.com/p/TheJker)  
**Total Rooms Completed:** 140+  

---

## 📊 Progress Overview

| Category | Rooms Completed | Status |
|----------|----------------|--------|
| Web Application Security | 30+ | 🟢 Active |
| Injection Vulnerabilities | 16 | 🟢 Active |
| Authentication & Authorization | 8 | ✅ Complete |
| Network Security & Reconnaissance | 23 | 🟢 Active |
| Linux Security | 6 | ✅ Complete |
| Windows Security | 8 | ✅ Complete |
| Tools & Exploitation | 11 | 🟢 Active |
| Cryptography | 3 | ✅ Complete |
| Fundamentals & Methodology | 12 | ✅ Complete |
| Defensive Security & Blue Team | 8 | 🟢 Active |
| Specialized Topics | 7 | 🟢 Active |
| Scripting & Programming | 4 | ✅ Complete |
| CTF Challenges & Boxes | 10 | 🟢 Active |
| Informational & Misc | 4 | ✅ Complete |

**Legend:**  
✅ Complete - Category fully explored  
🟢 Active - Continuing to explore and learn

---

## 🌐 Web Application Security

| Room | Difficulty | Key Topics |
|------|-----------|------------|
| OWASP Top 10 | Easy | Web vulnerabilities, OWASP standards, security testing |
| OWASP Top 10 - 2021 | Easy | Updated vulnerabilities, modern web threats |
| OWASP Juice Shop | Easy | Intentionally vulnerable app, hands-on exploitation |
| Web Fundamentals | Info | HTTP/HTTPS, DNS, web technologies |
| Burp Suite Basics | Easy | Proxy setup, intercept, repeater, intruder |
| Burp Suite Repeater | Easy | Manual request modification, response analysis |
| Burp Suite Intruder | Easy | Automated attacks, payload positions |
| Burp Suite Extensions | Easy | Plugin usage, custom extensions |
| WebAppSec 101 | Easy | Web security fundamentals, common vulnerabilities |
| Upload Vulnerabilities | Easy | File upload bypass, malicious file execution |
| Pickle Rick | Easy | Command injection, privilege escalation |
| Git Happens | Easy | Git repository exposure, source code review |
| IDOR | Easy | Insecure Direct Object Reference, authorization flaws |
| HTTP in Detail | Info | HTTP methods, headers, status codes |
| Cookies | Info | Session management, cookie manipulation |
| Authentication Bypass | Easy | Logic flaws, token manipulation |
| JavaScript Basics | Info | JS fundamentals, DOM manipulation |
| Content Discovery | Easy | Directory enumeration, hidden resources |
| Subdomain Enumeration | Easy | DNS enumeration, virtual host discovery |
| Walking an Application | Info | Manual web app assessment methodology |
| SSRF | Medium | Server-Side Request Forgery, internal service access |
| Cross-Site Scripting | Easy | XSS types, payload crafting, exploitation |
| XXE | Medium | XML External Entity injection, data exfiltration |
| Web Application Firewalls | Medium | WAF bypass techniques, evasion strategies |
| API Hacking | Medium | REST API security, authentication flaws |
| GraphQL | Medium | GraphQL queries, introspection, vulnerabilities |
| WebSockets | Medium | Real-time communication vulnerabilities |
| CORS Misconfiguration | Medium | Cross-Origin Resource Sharing exploits |
| Deserialization | Hard | Insecure deserialization, RCE |
| OAuth | Medium | OAuth flow, token theft, authorization bypass |
| XSS | Medium | Cross-Site Scripting, JavaScript injection, payload crafting
| CSRF | Medium | Cross-Site Request Forgery, token bypass, anti-CSRF
| Dom-Based Attacks | Medium | DOM XSS, client-side exploitation, sink/source analysis
| HTTP Request Smuggling | Hard | Request splitting, HTTP desync, protocol chaining
| HTTP/2 Request Smuggling | Hard | HTTP/2 protocol, smuggling techniques, advanced desync
| Request Smuggling: WebSockets | Hard | WebSocket protocol, hybrid smuggling, advanced chaining
| HTTP Browser Desync | Hard | Browser/server sync issues, desync exploitation, modern web
---

## 💉 Injection Vulnerabilities

| Room | Difficulty | Key Topics |
|------|-----------|------------|
| SQL Injection | Easy | Union-based SQLi, error-based, blind SQLi |
| SQL Injection Lab | Easy | Hands-on SQL injection practice |
| SQLMap | Easy | Automated SQL injection tool usage |
| Advanced SQL Injection | Medium | Complex queries, WAF bypass, out-of-band |
| NoSQL Injection | Medium | MongoDB, NoSQL database exploitation |
| Command Injection | Easy | OS command injection, payload crafting |
| Server-Side Template Injection | Medium | SSTI, template engine exploitation |
| LDAP Injection | Medium | Lightweight Directory Access Protocol exploitation |
| XPath Injection | Medium | XML path language injection |
| CRLF Injection | Medium | HTTP response splitting, header injection |
| Log Poisoning | Medium | Log file injection, LFI to RCE |
| Code Injection | Medium | Dynamic code execution vulnerabilities |
| PHP Code Injection | Medium | eval(), assert(), system() exploitation |
| XML Injection | Medium | XML parser exploitation |
| CSS Injection | Medium | Cascading Style Sheet based attacks |
| Header Injection | Medium | HTTP header manipulation |

---

## 🔐 Authentication & Authorization

| Room | Difficulty | Key Topics |
|------|-----------|------------|
| Authentication Bypass | Easy | Logic flaws, session manipulation |
| JWT Authentication | Medium | JSON Web Token vulnerabilities |
| OAuth Vulnerabilities | Medium | OAuth 2.0 flow exploitation |
| 2FA Bypass | Medium | Two-factor authentication weaknesses |
| Password Attacks | Easy | Brute force, dictionary attacks, credential stuffing |
| Session Management | Medium | Session fixation, hijacking, cookies |
| Access Control Vulnerabilities | Medium | Horizontal/vertical privilege escalation |
| Biometrics Bypass | Hard | Biometric authentication weaknesses |

---

## 🌐 Network Security & Reconnaissance

| Room | Difficulty | Key Topics |
|------|-----------|------------|
| Nmap | Easy | Port scanning, service detection, NSE scripts |
| Nmap Live Host Discovery | Easy | Host discovery techniques |
| Nmap Basic Port Scans | Easy | TCP/UDP scanning methods |
| Nmap Advanced Port Scans | Medium | Stealth scans, firewall evasion |
| Nmap Post Port Scans | Medium | Service enumeration, version detection |
| Network Services | Easy | FTP, SSH, Telnet, SMB exploitation |
| Network Services 2 | Easy | NFS, SMTP, MySQL exploitation |
| Protocols and Servers | Info | Common protocols, server types |
| Protocols and Servers 2 | Info | Advanced protocols, service interaction |
| Wireshark 101 | Easy | Packet analysis, traffic inspection |
| Wireshark Traffic Analysis | Medium | Protocol analysis, attack detection |
| Passive Reconnaissance | Info | OSINT, information gathering |
| Active Reconnaissance | Easy | Direct host interaction, enumeration |
| Red Team Recon | Medium | Advanced reconnaissance techniques |
| DNS in Detail | Info | DNS fundamentals, zone transfers |
| SMB Enumeration | Easy | Server Message Block exploitation |
| FTP Exploitation | Easy | Anonymous FTP, directory traversal |
| SSH | Easy | SSH brute force, key-based auth |
| RDP | Easy | Remote Desktop Protocol exploitation |
| Telnet | Easy | Telnet vulnerabilities, clear-text protocols |
| SNMP | Easy | Simple Network Management Protocol exploitation |
| NFS | Easy | Network File System enumeration |
| Attacking ICS | Hard | Industrial Control Systems security |

---

## 🐧 Linux Security

| Room | Difficulty | Key Topics |
|------|-----------|------------|
| Linux Fundamentals 1 | Info | Basic commands, file system navigation |
| Linux Fundamentals 2 | Info | File permissions, users and groups |
| Linux Fundamentals 3 | Info | Processes, automation, system management |
| Linux PrivEsc | Medium | SUID/SGID, sudo, cron, capabilities |
| Linux Privilege Escalation | Medium | Kernel exploits, misconfigurations |
| Linux File System | Info | Directory structure, important files |

---

## 🪟 Windows Security

| Room | Difficulty | Key Topics |
|------|-----------|------------|
| Windows Fundamentals 1 | Info | File system, user accounts, control panel |
| Windows Fundamentals 2 | Info | System configuration, security features |
| Windows Fundamentals 3 | Info | Active Directory basics, Group Policy |
| Windows PrivEsc | Medium | Token manipulation, unquoted service paths |
| Windows Privilege Escalation | Medium | Registry exploits, scheduled tasks |
| Active Directory Basics | Easy | AD structure, users, groups, computers |
| Attacking Active Directory | Hard | Kerberoasting, Pass-the-Hash, Golden Ticket |
| Blue | Easy | Windows exploitation, EternalBlue |

---

## 🛠️ Tools & Exploitation

| Room | Difficulty | Key Topics |
|------|-----------|------------|
| Metasploit Introduction | Easy | MSF basics, module selection |
| Metasploit Exploitation | Easy | Exploit execution, payload generation |
| Metasploit Meterpreter | Easy | Post-exploitation, advanced features |
| Hydra | Easy | Password brute forcing, credential attacks |
| John the Ripper | Easy | Password cracking, hash identification |
| Hashcat | Medium | GPU-accelerated cracking |
| Gobuster | Easy | Directory/file enumeration |
| ffuf | Easy | Fuzzing, parameter discovery |
| Nikto | Easy | Web server scanning |
| Searchsploit | Easy | Exploit database searching |
| GDB Debugging | Medium | Exploit development, binary analysis |

---

## 🔒 Cryptography

| Room | Difficulty | Key Topics |
|------|-----------|------------|
| Cryptography for Dummies | Info | Encryption basics, common algorithms |
| Encryption 101 | Easy | Symmetric/asymmetric encryption, hashing |
| Hashing Basics | Easy | Hash functions, collision attacks |

---

## 📚 Fundamentals & Methodology 

| Room | Difficulty | Key Topics |
|------|-----------|------------|
| Tutorial | Info | Platform introduction, basic navigation |
| Starting Out in Cyber Sec | Info | Career paths, learning resources |
| Intro to Offensive Security | Info | Red team vs blue team, pentesting basics |
| Intro to Defensive Security | Info | Security operations, threat detection |
| Careers in Cyber | Info | Job roles, certifications, career advice |
| How to Use TryHackMe | Info | Room types, learning paths, streaks |
| OpenVPN | Info | VPN setup and connection |
| Pentesting Fundamentals | Easy | Pentesting methodology, phases |
| Red Team Fundamentals | Easy | Red team operations, adversary emulation |
| Principles of Security | Easy | CIA triad, security models |
| Security Awareness | Easy | Social engineering, phishing, security culture |
| ISO27001 | Info | Information security management |

---

## 🛡️ Defensive Security & Blue Team

| Room | Difficulty | Key Topics |
|------|-----------|------------|
| Intro to Defensive Security | Info | Blue team fundamentals, SOC operations |
| Blue Team 1 | Easy | Incident response, log analysis |
| Security Operations | Medium | SIEM, threat hunting, alert triage |
| Cyber Defense Frameworks | Info | NIST, MITRE ATT&CK, Kill Chain |
| IDS/IPS | Medium | Intrusion detection/prevention systems |
| Snort | Medium | Rule writing, packet analysis |
| Zeek | Medium | Network security monitoring |
| Splunk | Medium | Log aggregation, search queries |

---

## 🎯 Specialized Topics

| Room | Difficulty | Key Topics |
|------|-----------|------------|
| Zero Logon | Hard | CVE-2020-1472, Active Directory exploitation |
| Eternal Blue | Medium | MS17-010, Windows SMB exploitation |
| Log4j | Medium | CVE-2021-44228, Java deserialization |
| PWNKIT | Medium | CVE-2021-4034, Linux privilege escalation |
| PrintNightmare | Medium | CVE-2021-34527, Windows printer spooler |
| DirtyCOW | Hard | CVE-2016-5195, Linux kernel exploit |
| Shellshock | Medium | CVE-2014-6271, Bash vulnerability |

---

## 💻 Scripting & Programming

| Room | Difficulty | Key Topics |
|------|-----------|------------|
| Python Basics | Easy | Python fundamentals, scripting |
| Python for Pentesters | Medium | Automation, exploit development |
| Bash Scripting | Easy | Shell scripting, automation |
| PowerShell for Pentesters | Medium | Windows automation, post-exploitation |

---

## 🚩 CTF Challenges & Boxes

| Room | Difficulty | Key Topics |
|------|-----------|------------|
| Blue | Easy | EternalBlue, Windows exploitation, Metasploit |
| Pickle Rick | Easy | Web exploitation, command injection, Linux PrivEsc |
| RootMe | Easy | Web enumeration, file upload, SUID exploitation |
| Basic Pentesting | Easy | SMB, SSH, web exploitation, privilege escalation |
| Kenobi | Easy | Samba, ProFTPD, path variable manipulation |
| Steel Mountain | Easy | Windows box, RCE, PowerShell PrivEsc |
| Alfred | Easy | Jenkins exploitation, Windows tokens |
| Ice | Easy | Windows exploitation, privilege escalation |
| Ignite | Easy | CMS exploitation, configuration vulnerabilities |
| Internal | Hard | WordPress, SSH tunneling, Jenkins, Docker, multi-stage privesc |

---

## 📋 Informational & Miscellaneous

| Room | Difficulty | Key Topics |
|------|-----------|------------|
| Tutorial Room | Info | Getting started with TryHackMe |
| Intro to Research | Info | Effective vulnerability research |
| Google Dorking | Info | Advanced search operators, OSINT |
| OSINT | Easy | Open-source intelligence gathering |

---

🧠 Cyber Threat Intelligence & Networking (3)

| Intro to Cyber Threat Intel | Info | Threat intelligence basics, OSINT, reporting
| Wifi Hacking 101 | Medium | Wireless security, WPA/2 attacks, WiFi cracking
| Advent of Cyber Prep Track | Easy | Event prep, multi-topic CTF labs, festive security

## 🎓 Learning Path Completion

### ✅ Jr Penetration Tester Path
**Completed:** Yes  
**Rooms:** 25  
**Duration:** 3 months  
**Key Skills:** Network security, web exploitation, privilege escalation

**Included Rooms:**
- Pentesting Fundamentals
- Nmap Series (4 rooms)
- Network Services (2 rooms)
- Burp Suite Series (4 rooms)
- OWASP Top 10
- Web Application Security rooms
- Metasploit Series (3 rooms)
- Linux & Windows PrivEsc

---

### ✅ Web Fundamentals Path
**Completed:** Yes  
**Rooms:** 18  
**Duration:** 2 months  
**Key Skills:** Web technologies, injection attacks, authentication bypass

**Included Rooms:**
- How the Web Works series
- HTTP in Detail
- Burp Suite Basics
- OWASP Top 10
- SQL Injection
- XSS
- Command Injection
- Authentication Bypass
- File Upload Vulnerabilities
- And more web-focused rooms

---

### ✅ Pre Security Path
**Completed:** Yes  
**Rooms:** 14  
**Duration:** 1 month  
**Key Skills:** Networking, Linux, Windows, security principles

**Included Rooms:**
- Linux Fundamentals (3 rooms)
- Windows Fundamentals (3 rooms)
- Network Fundamentals
- Intro to Offensive Security
- Intro to Defensive Security
- Careers in Cyber
- And foundational rooms

---

###✅ Web Application Pentesting Path

***Completed:** Yes
**Rooms:** 27
**Duration:** 2 months
**Key Skills:** Web vulnerabilities, injection attacks, authentication bypass, client/server exploitation

**Included Rooms:**

-Authentication(6)
-Injection Attacks(7)
-Advanced Server-Side Attacks(6)
-Advanced Client-Side Attacks(4)
-HTTP Request Smuggling(4)
