# Network Security Writeups

Writeups focused on network reconnaissance, enumeration, and exploitation techniques.

## 📝 Available Writeups

### [Nmap Mastery](./nmap-mastery.md)
- **Difficulty:** Easy
- **Focus:** Advanced Nmap techniques, NSE scripts, service enumeration
- **Key Skills:** Port scanning, service detection, vulnerability scanning

## 🎯 Learning Objectives

### Network Reconnaissance
- Host discovery techniques
- Port scanning methodologies
- Service version detection
- OS fingerprinting
- Network mapping

### Service Enumeration
- FTP enumeration
- SSH banner grabbing
- SMB/CIFS enumeration
- HTTP/HTTPS analysis
- Database service probing

### Protocol Exploitation
- Protocol-specific attacks
- Man-in-the-middle techniques
- Traffic analysis
- Session hijacking

## 🛠️ Essential Tools

### Scanning Tools
- **Nmap** - Network scanner
- **Masscan** - Fast port scanner
- **Rustscan** - Modern port scanner
- **Angry IP Scanner** - GUI scanner

### Service Enumeration
- **enum4linux** - SMB enumeration
- **smbclient** - SMB client
- **snmpwalk** - SNMP enumeration
- **ldapsearch** - LDAP enumeration

### Traffic Analysis
- **Wireshark** - Packet analyzer
- **tcpdump** - Command-line packet capture
- **tshark** - Terminal-based Wireshark

## 📚 Common Techniques

### Port Scanning
1. **TCP SYN Scan** - Stealthy, half-open scan
2. **TCP Connect Scan** - Full connection scan
3. **UDP Scan** - Slower, but important
4. **Service Version Detection** - Banner grabbing
5. **OS Detection** - Fingerprinting

### Network Enumeration
1. **ARP Scanning** - Local network discovery
2. **DNS Enumeration** - Zone transfers, subdomain discovery
3. **SNMP Enumeration** - Community string brute force
4. **SMB Enumeration** - Shares, users, groups

### Vulnerability Scanning
1. **NSE Scripts** - Nmap scripting engine
2. **Vulnerability Databases** - CVE search
3. **Exploit Verification** - Testing for specific vulnerabilities

## 🔍 Nmap Cheat Sheet

### Basic Scans
```bash
# Quick scan
nmap -F target

# All ports
nmap -p- target

# Specific ports
nmap -p 80,443,8080 target

# Service version
nmap -sV target

# OS detection
nmap -O target
```

### Advanced Scans
```bash
# Aggressive scan
nmap -A target

# Stealth SYN scan
sudo nmap -sS target

# UDP scan
sudo nmap -sU target

# Script scan
nmap --script vuln target
```

### Timing Templates
```bash
# Paranoid (very slow)
nmap -T0 target

# Sneaky
nmap -T1 target

# Polite
nmap -T2 target

# Normal (default)
nmap -T3 target

# Aggressive
nmap -T4 target

# Insane (very fast)
nmap -T5 target
```

## 📖 Resources

- [Nmap Official Documentation](https://nmap.org/docs.html)
- [Nmap NSE Scripts](https://nmap.org/nsedoc/)
- [Network Pentest Cheat Sheet](https://github.com/coreb1t/awesome-pentest-cheat-sheets)
- [HackTricks Network Services](https://book.hacktricks.xyz/network-services-pentesting/)

---

*Network enumeration is the foundation of successful penetration testing! 🌐*
