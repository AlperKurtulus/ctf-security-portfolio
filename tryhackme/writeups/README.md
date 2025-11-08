# TryHackMe Writeups

This directory contains detailed writeups of TryHackMe rooms organized by category.

## 📁 Categories

### 🌐 [Web Security](./web-security/)
Writeups focused on web application vulnerabilities:
- SQL Injection techniques
- Authentication bypass methods
- File inclusion vulnerabilities
- Command injection
- SSRF, XXE, SSTI attacks

### 🔓 [Privilege Escalation](./privilege-escalation/)
System-level exploitation writeups:
- Linux privilege escalation techniques
- Windows privilege escalation methods
- SUID/SGID exploitation
- Sudo misconfigurations
- Kernel exploits

### 🌐 [Network Security](./network-security/)
Network reconnaissance and exploitation:
- Nmap scanning techniques
- Service enumeration
- Protocol exploitation
- Network pivoting

### 🎯 [Boxes](./boxes/)
Complete box walkthroughs:
- Initial reconnaissance
- Exploitation techniques
- Privilege escalation
- Flag capture

## 📝 Writeup Structure

Each writeup follows a consistent format:

```markdown
# Room Name

**Difficulty:** Easy/Medium/Hard
**Category:** Category Name
**Points:** XX

## Challenge Description
Brief overview of the challenge

## Reconnaissance
Initial information gathering steps

## Enumeration
Detailed enumeration process

## Exploitation
Step-by-step exploitation with commands

## Privilege Escalation
Methods used to escalate privileges

## Flags
User and root flags

## Lessons Learned
Key takeaways from the challenge

## Remediation
How to prevent these vulnerabilities

## References
Useful resources and links
```

## 🎯 Key Learning Areas

### Web Application Security
- Understanding HTTP/HTTPS protocols
- Burp Suite mastery
- OWASP Top 10 vulnerabilities
- Manual testing techniques
- Automated scanning tools

### System Exploitation
- Linux and Windows internals
- Privilege escalation methodologies
- Post-exploitation techniques
- Lateral movement strategies

### Network Security
- Port scanning best practices
- Service enumeration techniques
- Protocol analysis
- Firewall evasion

## 🛠️ Tools Used

Common tools referenced in writeups:
- **Reconnaissance:** Nmap, Rustscan, Masscan
- **Web Testing:** Burp Suite, Gobuster, ffuf, Nikto
- **Exploitation:** Metasploit, SQLMap, searchsploit
- **Post-Exploitation:** LinPEAS, WinPEAS, privilege escalation scripts
- **Utilities:** Netcat, Socat, rlwrap

## 📚 Learning Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [GTFOBins](https://gtfobins.github.io/)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

## ⚠️ Disclaimer

These writeups are created for educational purposes only. Always:
- Obtain proper authorization before testing
- Follow TryHackMe's Terms of Service
- Practice ethical hacking principles
- Use knowledge responsibly

---

*Happy Learning! 🎓*
