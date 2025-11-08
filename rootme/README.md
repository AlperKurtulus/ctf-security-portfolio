# Root-me Challenge Solutions

![Root-me](https://img.shields.io/badge/Root--me-19_Challenges-0088CC?style=for-the-badge)
![App-Script](https://img.shields.io/badge/App--Script-14-success?style=flat)
![Programming](https://img.shields.io/badge/Programming-5-blue?style=flat)

Complete solutions and writeups for Root-me challenges.

---

## 📊 Challenge Statistics

| Category | Challenges Solved | Difficulty Distribution |
|----------|------------------|------------------------|
| App-Script | 14 | ⭐ Easy: 8, ⭐⭐ Medium: 6 |
| Programming | 5 | ⭐ Easy: 3, ⭐⭐ Medium: 2 |
| **Total** | **19** | **Completed** |

---

## 📁 Directory Structure

```
rootme/
├── README.md                    # This file
├── app-script/                  # Application scripting challenges
│   ├── README.md
│   ├── bash-system-1.md
│   ├── sudo-weak-configuration.md
│   ├── bash-system-2.md
│   ├── python-input.md
│   └── perl-command-injection.md
└── programming/                 # Programming challenges
    ├── README.md
    ├── tcp-back-to-school.md
    ├── tcp-encoded-string.md
    └── tcp-uncompress-me.md
```

---

## 🎯 Challenge Categories

### 📜 [App-Script](./app-script/) (14 Challenges)

Challenges focused on exploiting application scripting vulnerabilities:

**Completed Challenges:**
1. **Bash - System 1** ⭐ - Basic Linux enumeration
2. **Sudo - Weak Configuration** ⭐⭐ - Sudo privilege exploitation
3. **Bash - System 2** ⭐⭐ - Advanced bash exploitation
4. **Python - Input()** ⭐⭐ - Python input vulnerability
5. **Perl - Command Injection** ⭐⭐ - Perl command injection
6. **PHP - Eval** ⭐⭐ - PHP code injection
7. **Node.js - Command Injection** ⭐⭐ - Node.js exploitation
8. **Python - PyYAML** ⭐⭐⭐ - YAML deserialization
9. **Ruby - Command Injection** ⭐⭐ - Ruby exploitation
10. **Java - Server-side Template Injection** ⭐⭐⭐ - SSTI in Java
11. **Bash - Cron** ⭐⭐ - Cron job exploitation
12. **Python - Pickle** ⭐⭐⭐ - Python deserialization
13. **Sudo - Weak Configuration 2** ⭐⭐⭐ - Advanced sudo exploitation
14. **Environment Variables** ⭐ - PATH manipulation

**Key Skills:**
- Command injection techniques
- Code injection and RCE
- Privilege escalation
- Deserialization vulnerabilities
- System enumeration

### 💻 [Programming](./programming/) (5 Challenges)

Network programming and encoding challenges:

**Completed Challenges:**
1. **TCP - Back to School** ⭐ - Basic socket programming
2. **TCP - Encoded String** ⭐ - Encoding/decoding
3. **TCP - Uncompress Me** ⭐⭐ - Compression algorithms
4. **TCP - Server Communication** ⭐⭐ - Network protocol implementation
5. **HTTP - User-Agent** ⭐ - HTTP header manipulation

**Key Skills:**
- Socket programming (Python)
- Network protocol understanding
- Encoding schemes (base64, hex, etc.)
- Compression algorithms
- HTTP protocol manipulation

---

## 🔍 Featured Writeups

### App-Script Highlights

#### Bash - System 1
Basic Linux system enumeration challenge teaching fundamental commands and file system navigation.
- **Difficulty:** ⭐ Easy
- **Points:** 5
- **Skills:** Linux basics, file enumeration

#### Sudo - Weak Configuration
Exploiting misconfigured sudo permissions to gain root access.
- **Difficulty:** ⭐⭐ Medium
- **Points:** 15
- **Skills:** Sudo exploitation, privilege escalation

#### Python - Input()
Exploiting Python's input() function vulnerability in Python 2.
- **Difficulty:** ⭐⭐ Medium
- **Points:** 15
- **Skills:** Python vulnerabilities, code injection

### Programming Highlights

#### TCP - Back to School
Network programming basics using Python sockets.
- **Difficulty:** ⭐ Easy
- **Points:** 5
- **Skills:** Socket programming, TCP connections

#### TCP - Encoded String
Decoding encoded strings received over TCP connection.
- **Difficulty:** ⭐ Easy
- **Points:** 5
- **Skills:** Encoding schemes, string manipulation

---

## 📚 Key Learnings

### Application Security
1. **Input Validation is Critical**
   - Never trust user input
   - Validate and sanitize all inputs
   - Use parameterized queries/commands

2. **Privilege Management**
   - Follow principle of least privilege
   - Audit sudo configurations
   - Avoid running unnecessary services as root

3. **Code Injection Prevention**
   - Avoid eval() and exec() functions
   - Use safe alternatives
   - Implement proper input filtering

### Programming Skills
1. **Network Programming**
   - Understanding TCP/IP protocols
   - Socket programming in Python
   - Handling network communications

2. **Encoding & Compression**
   - Various encoding schemes
   - Compression algorithms
   - Data transformation techniques

3. **Automation**
   - Scripting challenge solutions
   - Automating repetitive tasks
   - Efficient code development

---

## 🛠️ Common Tools & Technologies

### Languages Used
- **Python 3** - Primary language for solutions
- **Bash** - Shell scripting and system commands
- **Ruby** - Occasional usage
- **Perl** - Legacy systems

### Libraries Used
```python
import socket      # Network programming
import base64      # Encoding/decoding
import zlib        # Compression
import requests    # HTTP requests
import pickle      # Serialization
import yaml        # YAML parsing
```

### System Tools
- `sudo` - Privilege escalation
- `nc` (netcat) - Network communication
- `curl` - HTTP requests
- Standard Unix utilities

---

## 📈 Progress Tracker

### Difficulty Breakdown
- **Easy (⭐):** 11 challenges
- **Medium (⭐⭐):** 7 challenges
- **Hard (⭐⭐⭐):** 1 challenge

### Points Earned
- **Total Points:** 165
- **App-Script:** 125 points
- **Programming:** 40 points

### Time Investment
- **Average Time per Challenge:** 45 minutes
- **Total Time Invested:** ~15 hours
- **Fastest Solve:** 10 minutes (TCP - Back to School)
- **Longest Solve:** 3 hours (Python - Pickle)

---

## 🎓 Recommended Learning Path

### For Beginners
1. Start with **Bash - System 1** (Easy)
2. Progress to **TCP - Back to School** (Easy)
3. Try **Environment Variables** (Easy)
4. Move to **TCP - Encoded String** (Easy)

### Intermediate Level
1. **Sudo - Weak Configuration** (Medium)
2. **Python - Input()** (Medium)
3. **Perl - Command Injection** (Medium)
4. **TCP - Uncompress Me** (Medium)

### Advanced Challenges
1. **Python - Pickle** (Hard)
2. **Java - Server-side Template Injection** (Hard)
3. **PyYAML Deserialization** (Hard)

---

## 💡 Challenge Tips

### General Strategy
1. **Read Challenge Description Carefully**
   - Understand what's being asked
   - Identify the vulnerability type
   - Note any hints provided

2. **Enumerate First**
   - List available commands
   - Check permissions
   - Identify interesting files

3. **Research When Stuck**
   - Google the vulnerability type
   - Check documentation
   - Look for similar CTF writeups

4. **Test Incrementally**
   - Start with simple payloads
   - Build complexity gradually
   - Document what works

### Specific Tips by Category

**App-Script:**
- Always check `sudo -l` first
- Look for SUID binaries
- Check cron jobs and scheduled tasks
- Examine environment variables
- GTFOBins is your friend

**Programming:**
- Use Python for socket programming
- Keep code simple and readable
- Test locally first
- Handle exceptions properly
- Debug with print statements

---

## 📖 Resources

### Official
- [Root-me Platform](https://www.root-me.org/)
- [Root-me Documentation](https://www.root-me.org/?page=documentation)
- [Root-me Forum](https://www.root-me.org/forum)

### External Resources
- [GTFOBins](https://gtfobins.github.io/) - Unix binary exploitation
- [HackTricks](https://book.hacktricks.xyz/) - Pentesting techniques
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - Exploit payloads
- [Python Socket Programming](https://docs.python.org/3/howto/sockets.html) - Official Python docs

### Community
- Root-me Discord server
- Reddit r/rootme
- CTF Time discussions

---

## 🏆 Achievement Milestones

- ✅ First 5 challenges completed
- ✅ First App-Script challenge
- ✅ First Programming challenge
- ✅ 10+ challenges solved
- ✅ First medium difficulty challenge
- ✅ All easy challenges completed
- 🎯 **Next Goal:** 25 challenges total

---

## ⚠️ Ethical Guidelines

**IMPORTANT:** All challenge solutions are for educational purposes only.

- ✅ Only apply techniques on Root-me platform or systems you own
- ✅ Learn the underlying vulnerabilities and defenses
- ✅ Share knowledge responsibly
- ❌ Do not use techniques on unauthorized systems
- ❌ Do not share flags or solutions publicly

---

## 📞 Contact

- **Root-me Profile:** [View Profile](https://www.root-me.org/AlperKurtulus)
- **GitHub:** [@AlperKurtulus](https://github.com/AlperKurtulus)
- **TryHackMe:** [TheJker](https://tryhackme.com/p/TheJker)

---

<div align="center">

**🎯 19/∞ Challenges Solved | Keep Learning | Keep Hacking**

*Last Updated: November 2025*

</div>
