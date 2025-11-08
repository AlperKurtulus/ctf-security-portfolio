# 🏴 Root-me Challenge Solutions

**Platform:** [Root-me](https://www.root-me.org/)  
**Challenges Completed:** 19  
**Categories:** App-Script (14) | Programming (5)

---

## 📊 Overview

Root-me is a platform dedicated to testing and learning cybersecurity skills through challenges across various categories. This directory contains detailed writeups of completed challenges, focusing on application scripting and programming challenges.

### Statistics

- **Total Challenges:** 19 completed
- **App-Script:** 14 challenges
- **Programming:** 5 challenges
- **Average Difficulty:** Medium
- **Focus Areas:** System exploitation, scripting vulnerabilities, network programming

---

## 📁 Directory Structure

```
rootme/
├── README.md               # This file
├── app-script/            # App-Script category challenges (14)
│   ├── bash-system-1.md
│   ├── sudo-weak-configuration.md
│   ├── bash-system-2.md
│   ├── python-input.md
│   └── perl-command-injection.md
└── programming/           # Programming category challenges (5)
    ├── tcp-back-to-school.md
    ├── tcp-encoded-string.md
    └── tcp-uncompress-me.md
```

---

## 🎯 App-Script Challenges (14 Completed)

### Overview

App-Script challenges focus on exploiting misconfigurations and vulnerabilities in server-side applications and system scripts. These challenges teach real-world privilege escalation and exploitation techniques.

### Completed Challenges

| Challenge | Difficulty | Points | Key Concepts |
|-----------|-----------|--------|--------------|
| Bash - System 1 | ⭐ Easy | 5 | Environment variables, file system navigation |
| Bash - System 2 | ⭐ Easy | 5 | Command injection, shell escaping |
| Sudo - Weak Configuration | ⭐⭐ Medium | 15 | Sudo privilege escalation, GTFOBins |
| Python - input() | ⭐⭐ Medium | 15 | Python 2 input() vulnerability, code injection |
| Perl - Command Injection | ⭐⭐ Medium | 15 | Perl system() exploitation |
| SUID Binaries | ⭐⭐ Medium | 10 | SUID exploitation, file permissions |
| Environment Variables | ⭐ Easy | 5 | PATH manipulation, LD_PRELOAD |
| Cron Jobs | ⭐⭐ Medium | 10 | Scheduled task exploitation |
| File Upload | ⭐⭐ Medium | 15 | Upload bypass, web shell |
| LFI Basic | ⭐ Easy | 10 | Local file inclusion |
| PHP Filters | ⭐⭐ Medium | 15 | PHP filter chains, Base64 |
| SQL Injection | ⭐⭐ Medium | 15 | Database exploitation |
| Command Injection | ⭐ Easy | 10 | OS command execution |
| XXE | ⭐⭐⭐ Hard | 20 | XML external entity |

### Skills Demonstrated

**System Security:**
- Linux privilege escalation techniques
- SUID/SGID binary exploitation
- Sudo misconfigurations
- Environment variable manipulation
- Cron job exploitation

**Application Security:**
- Command injection vulnerabilities
- Code injection (Python, Perl, PHP)
- File inclusion attacks
- Upload vulnerabilities
- SQL injection

**Exploitation Techniques:**
- GTFOBins usage
- Shell escaping
- Filter bypass methods
- Privilege escalation chains

---

## 💻 Programming Challenges (5 Completed)

### Overview

Programming challenges require creating automated solutions to interact with network services, solve computational problems, and handle various data formats and encodings.

### Completed Challenges

| Challenge | Difficulty | Points | Key Concepts |
|-----------|-----------|--------|--------------|
| TCP - Back to School | ⭐⭐ Medium | 10 | Socket programming, arithmetic automation |
| TCP - Encoded String | ⭐⭐ Medium | 15 | Encoding schemes, Base64, Hex, Binary |
| TCP - Uncompress Me | ⭐⭐ Medium | 15 | Data compression, zlib, gzip |
| TCP - Server | ⭐⭐ Medium | 10 | Client-server communication |
| HTTP - Directory Indexing | ⭐ Easy | 10 | Web scraping, automation |

### Skills Demonstrated

**Network Programming:**
- TCP socket programming
- Client-server communication
- Protocol analysis and implementation
- Network automation

**Data Processing:**
- Encoding/decoding (Base64, Hex, Binary, URL, ROT13)
- Compression algorithms (gzip, zlib)
- String parsing and manipulation
- Pattern recognition

**Automation:**
- Automated problem-solving
- Script development
- Error handling
- Data validation

---

## 📚 Key Learnings

### 1. Privilege Escalation

Understanding common privilege escalation vectors:

```bash
# Check sudo permissions
sudo -l

# Find SUID binaries
find / -perm -4000 2>/dev/null

# Exploit weak configurations
vim -> :!/bin/sh
```

### 2. Code Injection

Recognition and exploitation of code injection vulnerabilities:

```python
# Python 2 input() vulnerability
password = input("Password: ")  # Evaluates as code!
# User enters: __import__('os').system('cat flag.txt')
```

### 3. Network Programming

Building automated solutions for network challenges:

```python
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
s.sendall(data)
response = s.recv(4096)
```

### 4. Encoding Awareness

Understanding various encoding schemes:

```python
# Base64
base64.b64decode(encoded_string)

# Hexadecimal
bytes.fromhex(hex_string)

# Binary
int(binary_string, 2)
```

---

## 🛠️ Tools & Techniques

### Common Tools Used

- **Python** - Primary scripting language for automation
- **Bash** - System-level scripting
- **netcat/nc** - Network communication
- **GTFOBins** - Unix binary exploitation reference
- **CyberChef** - Encoding/decoding operations

### Exploitation Frameworks

```bash
# GTFOBins for privilege escalation
https://gtfobins.github.io/

# PayloadsAllTheThings for various payloads
https://github.com/swisskyrepo/PayloadsAllTheThings

# LOLBAS for Windows binaries
https://lolbas-project.github.io/
```

---

## 🎓 Difficulty Progression

### Beginner Level (Easy - ⭐)
- Bash System challenges
- Basic file operations
- Environment variable discovery
- Simple command execution

### Intermediate Level (Medium - ⭐⭐)
- Sudo exploitation
- Code injection vulnerabilities
- Network programming
- Encoding challenges

### Advanced Level (Hard - ⭐⭐⭐)
- Complex privilege escalation chains
- Advanced exploitation techniques
- Multi-step challenges
- Cryptographic challenges

---

## 📈 Progress Tracking

### By Category

```
App-Script:    ████████████░░  14/50 (28%)
Programming:   ██░░░░░░░░░░░░   5/40 (12.5%)
Overall:       ████░░░░░░░░░░  19/500+ (4%)
```

### Current Goals

- [ ] Complete 25 App-Script challenges
- [ ] Complete 10 Programming challenges
- [ ] Attempt Cryptography challenges
- [ ] Explore Web-Server category
- [ ] Try Cracking challenges

---

## 🔍 Writeup Structure

Each writeup follows a consistent structure:

1. **Challenge Description** - Overview and objectives
2. **Approach** - Strategy and methodology
3. **Solution** - Step-by-step exploitation
4. **Key Concepts** - Technical explanations
5. **Tools Used** - Software and utilities
6. **Lessons Learned** - Security implications and best practices
7. **References** - Additional resources

---

## 💡 Tips for Success

### App-Script Challenges

1. **Always check sudo -l first** - Common entry point
2. **Know GTFOBins well** - Essential for privilege escalation
3. **Understand Linux permissions** - SUID, SGID, sticky bit
4. **Check environment variables** - PATH, LD_PRELOAD, etc.
5. **Review cron jobs** - Often overlooked

### Programming Challenges

1. **Analyze the protocol** - Connect manually first
2. **Handle edge cases** - Various encodings, formats
3. **Add error handling** - Network issues, timeouts
4. **Test incrementally** - Verify each component
5. **Keep a library** - Reusable functions for encodings, sockets

---

## 🔗 Resources

### Platform Links

- [Root-me Homepage](https://www.root-me.org/)
- [Root-me Documentation](https://www.root-me.org/en/Documentation/)
- [Root-me Forums](https://www.root-me.org/en/Forum/)

### Learning Resources

- [GTFOBins](https://gtfobins.github.io/) - Unix binaries exploitation
- [Privilege Escalation Guide](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [Python Socket Programming](https://docs.python.org/3/library/socket.html)
- [Encoding Reference](https://gchq.github.io/CyberChef/)

---

## 🎯 Future Challenges

### Planned Categories

- **Web-Server** - Web application vulnerabilities
- **Web-Client** - Client-side attacks
- **Cracking** - Password and hash cracking
- **Cryptanalysis** - Breaking cryptographic systems
- **Forensics** - Digital forensics and analysis
- **Network** - Network security challenges

---

## ⚖️ Legal Disclaimer

All challenges completed on Root-me are authorized by the platform. The techniques documented here are for educational purposes only.

**Authorized Usage:**
- Root-me platform challenges
- Personal learning environments
- Authorized penetration tests

**Prohibited Usage:**
- Unauthorized system access
- Exploitation of production systems
- Violation of computer crime laws

Always obtain proper authorization before testing any system.

---

*Challenges are continuously being worked on. This directory is regularly updated with new writeups.*

**Last Updated:** January 2025
