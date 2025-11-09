# Welcome to CTF Security Portfolio

![GitHub last commit](https://img.shields.io/github/last-commit/AlperKurtulus/ctf-security-portfolio)
![GitHub repo size](https://img.shields.io/github/repo-size/AlperKurtulus/ctf-security-portfolio)
![License](https://img.shields.io/github/license/AlperKurtulus/ctf-security-portfolio)

## 🎯 Overview

This repository showcases my cybersecurity journey through Capture The Flag (CTF) challenges, penetration testing writeups, and custom security tools. It contains comprehensive documentation of solved challenges from various platforms including TryHackMe, Root-me, and OverTheWire.

---

## 📊 Current Statistics

| Platform | Completed | Status |
|----------|-----------|--------|
| **TryHackMe** | 130+ Rooms | 🟢 Active |
| **Root-me** | 7+ Writeups | 🟢 Active |
| **OverTheWire** | Level 15+ | 🟢 Active |
| **Learning Paths** | 4 Completed | ✅ Complete |

---

## 🆕 Latest Updates

### Recent TryHackMe Writeup
**[Internal Box (Hard)](./tryhackme/writeups/boxes/internal.md)** - *November 9, 2025*
- Difficulty: Hard ⭐⭐⭐
- Completion Time: 4.5 hours
- Key Techniques: WordPress exploitation, SSH tunneling, Jenkins RCE, Docker enumeration
- Attack Chain: 11 different exploitation stages

**Highlights:**
```
WordPress Theme Editor → www-data shell
  ↓
Manual Credential Hunting → aubreanna user
  ↓
SSH Tunneling → Internal Jenkins
  ↓
Hydra Brute Force → Jenkins admin
  ↓
Script Console RCE → Docker container
  ↓
Container Enumeration → ROOT access
```

### Root-Me Writeups
Published 7 detailed programming and scripting challenge solutions:
- **Back to School** (socket programming)
- **Captcha Me If You Can** (OCR automation)
- **Encoded String** (Base64 decoding)
- **The Roman Wheel** (ROT13 cipher)
- **Uncompress Me** (zlib compression)
- **Mathematic Progression** (algorithm optimization)
- **Pickle Deserialization** (RCE vulnerability)

---

## 📁 Repository Structure

```
ctf-security-portfolio/
├── tryhackme/                    # TryHackMe challenges and writeups
│   ├── writeups/
│   │   ├── boxes/               # Complete box walkthroughs
│   │   │   └── internal.md     # NEW: Internal box (Hard)
│   │   ├── web-security/       # Web exploitation challenges
│   │   ├── privilege-escalation/  # Linux & Windows privesc
│   │   └── network-security/   # Network-focused challenges
│   ├── scripts/                # Custom automation scripts
│   │   ├── enumeration/
│   │   ├── exploitation/
│   │   ├── post-exploitation/
│   │   └── utilities/
│   ├── badges/                 # Earned badges documentation
│   ├── README.md              # TryHackMe overview
│   └── PROGRESS.md            # Detailed progress tracking
│
├── rootme/                      # Root-me challenges
│   ├── programming/            # Programming challenges
│   ├── web-server/            # Web exploitation
│   ├── app-script/            # Scripting challenges
│   └── README.md
│
├── overthewire/                # OverTheWire wargames (coming soon)
│   └── bandit/                # Bandit levels
│
├── tools/                      # Custom security tools
│   └── scripts/               # Utility scripts
│
└── resources/                  # Learning resources
    ├── cheatsheets/           # Quick reference guides
    └── README.md              # Curated resources list
```

---

## 🎓 Completed Learning Paths

### TryHackMe Paths (4 Completed)

1. **Jr Penetration Tester** ✅
   - Network security, web exploitation, privilege escalation
   - 25 rooms completed

2. **Web Fundamentals** ✅
   - HTTP/HTTPS, OWASP Top 10, injection attacks
   - 18 rooms completed

3. **Pre Security** ✅
   - Linux, Windows, networking fundamentals
   - 14 rooms completed

4. **Cyber Security 101** ✅
   - Security fundamentals, offensive & defensive concepts
   - 12 rooms completed

---

## 🏆 Key Achievements

### TryHackMe
- **130+ Rooms Completed**
- **4 Learning Paths Completed**
- **18 Badges Earned**
- **1 Hard Box Writeup Published** (Internal)

### Skills Demonstrated
- ✅ Web Application Exploitation (SQLi, XSS, RCE, File Upload)
- ✅ Linux & Windows Privilege Escalation
- ✅ Network Enumeration & Service Exploitation
- ✅ SSH Tunneling & Network Pivoting
- ✅ Tool Development (Python, Bash scripting)
- ✅ Professional Documentation & Reporting

---

## 🛠️ Featured Tools & Scripts

### Enumeration
- **auto_enum.sh** - Comprehensive automated reconnaissance
- **web_enum.py** - Web application enumeration

### Exploitation
- **revshell_generator.py** - Multi-language reverse shell generator
- **payload_builder.sh** - Custom payload creation

### Post-Exploitation
- **linux_privesc_check.sh** - Linux privilege escalation checker
- **cred_hunter.py** - Credential hunting automation

---

## 📚 Documentation Highlights

### Comprehensive Writeups
Each writeup includes:
- 📋 Challenge overview and objectives
- 🔍 Detailed reconnaissance methodology
- 🕵️ Step-by-step enumeration process
- 💥 Exploitation techniques with code examples
- 🔓 Privilege escalation paths
- 🎓 Lessons learned and key takeaways
- 🛡️ Defensive recommendations

### Example: Internal Box Writeup
- **700+ lines** of detailed documentation
- **Attack chain diagram** with 11 exploitation stages
- **Defensive recommendations** for blue team
- **Alternative approaches** and methodology
- **Time breakdown** by phase (4.5 hours total)
- **Tools used** with complete command reference

---

## 🎯 Skills Matrix

| Category | Proficiency | Details |
|----------|-------------|---------|
| **Web Exploitation** | ⭐⭐⭐⭐ | SQLi, XSS, RCE, File Upload, SSRF |
| **Linux Privilege Escalation** | ⭐⭐⭐⭐ | SUID, sudo, capabilities, manual enum |
| **Windows Privilege Escalation** | ⭐⭐⭐ | Token impersonation, service exploits |
| **Network Enumeration** | ⭐⭐⭐⭐ | Nmap, service identification, protocols |
| **Python Scripting** | ⭐⭐⭐⭐ | Automation, exploit development |
| **Bash Scripting** | ⭐⭐⭐⭐ | Enumeration, post-exploitation |
| **Burp Suite** | ⭐⭐⭐⭐ | Proxy, repeater, intruder |
| **Metasploit** | ⭐⭐⭐ | Module usage, payload generation |

---

## 📈 Progress & Goals

### Current Focus (November 2025)
- 🎯 TryHackMe Medium/Hard boxes
- 🎯 OverTheWire Bandit (Level 15+)
- 🎯 Root-me advanced challenges
- 🎯 Custom tool development

### Short-term Goals
- [ ] Complete 10 Medium boxes on TryHackMe
- [ ] Reach OverTheWire Bandit Level 30
- [ ] Publish 5 more Root-me writeups
- [ ] Complete SOC Level 1 Path

### Long-term Goals
- [ ] eJPT Certification preparation
- [ ] Contribute to open-source security tools
- [ ] Build comprehensive methodology documentation
- [ ] Create video walkthrough series

---

## 🔗 Connect & Follow

- **TryHackMe Profile:** [TheJker](https://tryhackme.com/p/TheJker)
- **GitHub:** [@AlperKurtulus](https://github.com/AlperKurtulus)
- **Repository:** [ctf-security-portfolio](https://github.com/AlperKurtulus/ctf-security-portfolio)

---

## ⚠️ Ethical Use & Disclaimer

All content in this repository is for **educational purposes only**.

**Important Guidelines:**
- ✅ Always obtain proper authorization before testing
- ✅ Follow platform terms of service (TryHackMe, Root-me, etc.)
- ✅ Practice responsible disclosure
- ✅ Respect intellectual property
- ❌ Never use these techniques on systems without permission
- ❌ Unauthorized access to computer systems is illegal

**Legal Notice:** The author is not responsible for any misuse of the information provided. All techniques are demonstrated in controlled, legal environments (CTF platforms).

---

## 📜 License

This repository is licensed under the MIT License. See [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

Special thanks to:
- **TryHackMe** - Excellent learning platform and community
- **Root-me** - Challenging programming and security puzzles
- **OverTheWire** - Classic wargames for skill building
- **InfoSec Community** - Continuous learning and support

---

<div align="center">

**🔒 Security | 📚 Education | 🎯 Continuous Learning**

*Last Updated: November 9, 2025*

---

**If you find this repository helpful, consider giving it a ⭐!**

</div>
