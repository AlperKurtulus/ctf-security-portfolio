# TryHackMe Security Scripts

Collection of custom security automation scripts developed during TryHackMe challenges.

## 📁 Script Categories

### 🔍 [Enumeration](./enumeration/)
Automated reconnaissance and enumeration tools:
- **auto_enum.sh** - Comprehensive automated enumeration script

### 💥 [Exploitation](./exploitation/)
Exploit automation and payload generation:
- **revshell_generator.py** - Multi-language reverse shell generator

### 🔓 [Post-Exploitation](./post-exploitation/)
Post-compromise enumeration and privilege escalation:
- **linux_privesc_check.sh** - Linux privilege escalation checker

### 🛠️ [Utilities](./utilities/)
Helper scripts and utilities for penetration testing

---

## 🚀 Featured Scripts

### 1. Automated Enumeration Script

**File:** `enumeration/auto_enum.sh`

**Description:** Comprehensive automated enumeration for penetration testing engagements.

**Features:**
- Nmap scanning (quick, full, UDP, vulnerability)
- Web enumeration (Gobuster, Nikto)
- SMB enumeration (enum4linux)
- Color-coded output
- Organized output directories
- Summary report generation

**Usage:**
```bash
./auto_enum.sh <target_ip>
```

**Example:**
```bash
./auto_enum.sh 10.10.10.10
```

**Requirements:**
- nmap
- gobuster
- nikto
- enum4linux

**Output:**
Creates a directory `enum_<IP>_<timestamp>` with organized scan results.

---

### 2. Reverse Shell Generator

**File:** `exploitation/revshell_generator.py`

**Description:** Multi-language reverse shell payload generator for penetration testing.

**Features:**
- Multiple language support (Bash, Python, PHP, Perl, Ruby, PowerShell, etc.)
- PowerShell with base64 encoding
- Color-coded output
- Copy-ready payloads
- Shell upgrade instructions
- Listener setup guidance

**Usage:**
```bash
python3 revshell_generator.py
```

**Interactive Prompts:**
- Enter LHOST (your IP)
- Enter LPORT (listening port)
- Generates payloads for all supported languages

**Supported Shells:**
- Bash (2 variants)
- Python 2/3
- PHP
- Netcat (2 variants)
- Perl
- Ruby
- PowerShell (with base64 encoding)
- Java

**Example Output:**
```
Enter your LHOST: 10.10.14.5
Enter your LPORT: 4444

Generated Payloads:
- Bash Reverse Shell
- Python Reverse Shell
- PHP Reverse Shell
- [etc...]
```

---

### 3. Linux Privilege Escalation Checker

**File:** `post-exploitation/linux_privesc_check.sh`

**Description:** Automated Linux privilege escalation enumeration script.

**Features:**
- System information gathering
- User and group enumeration
- Sudo privilege checking
- SUID/SGID binary identification
- Writable file/directory discovery
- Cron job analysis
- Network connection enumeration
- Running process analysis
- Capability enumeration
- Environment variable inspection
- Color-coded output with recommendations

**Usage:**
```bash
./linux_privesc_check.sh
```

**No arguments needed** - runs comprehensive enumeration on the current system.

**Checks Performed:**
1. System Information (OS, kernel, hostname)
2. Users & Groups
3. Sudo Privileges
4. SUID/SGID Binaries
5. Writable Files & Directories
6. Cron Jobs & Scheduled Tasks
7. Network Information
8. Running Processes
9. Interesting Files (SSH keys, configs, etc.)
10. Capabilities
11. Environment Variables
12. Installed Software

**Output:**
Organized colored output with sections and actionable recommendations.

---

## 📦 Requirements

### General Dependencies
```bash
# Debian/Ubuntu
sudo apt update
sudo apt install -y nmap gobuster nikto enum4linux python3

# RedHat/CentOS
sudo yum install -y nmap gobuster nikto python3

# Arch Linux
sudo pacman -S nmap gobuster nikto python3
```

### Python Dependencies
```bash
pip3 install requests
```

---

## 🔧 Installation

### Clone Repository
```bash
git clone https://github.com/AlperKurtulus/ctf-security-portfolio.git
cd ctf-security-portfolio/tryhackme/scripts
```

### Make Scripts Executable
```bash
chmod +x enumeration/*.sh
chmod +x exploitation/*.py
chmod +x post-exploitation/*.sh
```

---

## 💡 Usage Tips

### Enumeration
- Always start with enumeration
- Let scripts run completely
- Review all output files
- Pay attention to unusual findings

### Exploitation
- Test payloads in safe environment first
- Always have a listener ready
- Use rlwrap for better shell experience
- Stabilize shells after catching them

### Post-Exploitation
- Run enumeration scripts immediately after gaining access
- Check for quick wins first (sudo -l, SUID binaries)
- Document all findings
- Prioritize high-impact vulnerabilities

---

## ⚠️ Security Warnings

### Important Disclaimers

1. **Authorization Required**
   - Only use on systems you own or have written permission to test
   - Unauthorized access is illegal
   - Always obtain proper authorization

2. **Responsible Use**
   - These tools are for educational purposes
   - Follow ethical hacking principles
   - Respect TryHackMe's Terms of Service
   - Practice responsible disclosure

3. **Legal Considerations**
   - Know your local laws
   - Understand computer crime laws
   - Penetration testing without permission is illegal
   - Be aware of liability issues

4. **Production Systems**
   - Never use on production systems without approval
   - Enumeration tools can be noisy
   - Some scripts may impact performance
   - Always have proper authorization

---

## 🤝 Contributing

While this is a personal portfolio, suggestions for improvements are welcome:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## 📚 Additional Resources

### Learning Resources
- [Offensive Security](https://www.offensive-security.com/)
- [SANS Reading Room](https://www.sans.org/reading-room/)
- [OWASP](https://owasp.org/)
- [HackTricks](https://book.hacktricks.xyz/)

### Tool Documentation
- [Nmap Documentation](https://nmap.org/docs.html)
- [Gobuster Usage](https://github.com/OJ/gobuster)
- [Burp Suite](https://portswigger.net/burp/documentation)

### Communities
- [TryHackMe Discord](https://discord.gg/tryhackme)
- [HackTheBox Forums](https://forum.hackthebox.eu/)
- [Reddit /r/netsec](https://www.reddit.com/r/netsec/)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.

---

## 📞 Contact

- **GitHub:** [@AlperKurtulus](https://github.com/AlperKurtulus)
- **TryHackMe:** [TheJker](https://tryhackme.com/p/TheJker)

---

<div align="center">

**⚠️ Use Responsibly | 🎓 Educational Purpose Only | 🔒 Always Obtain Authorization**

*Last Updated: November 2025*

</div>
