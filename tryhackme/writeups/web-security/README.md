# Web Security Writeups

This directory contains writeups focused on web application vulnerabilities and exploitation techniques.

## 📝 Available Writeups

### [SQL Injection](./sql-injection.md)
- **Difficulty:** Easy
- **Focus:** SQL injection fundamentals, union-based attacks, blind SQLi
- **Tools:** SQLMap, Burp Suite
- **Key Skills:** Database enumeration, data exfiltration

### [Authentication Bypass](./authentication-bypass.md)
- **Difficulty:** Easy
- **Focus:** Login bypass techniques, session manipulation, JWT vulnerabilities
- **Tools:** Burp Suite, custom scripts
- **Key Skills:** Logic flaw exploitation, token manipulation

### [File Inclusion](./file-inclusion.md)
- **Difficulty:** Medium
- **Focus:** LFI, RFI, path traversal, log poisoning
- **Tools:** Burp Suite, manual testing
- **Key Skills:** File system exploitation, RCE through LFI

## 🎯 Learning Objectives

### SQL Injection
- Understand database structures
- Identify injection points
- Exploit union-based SQLi
- Perform blind SQL injection
- Extract sensitive data
- Bypass authentication with SQLi

### Authentication & Session Management
- Analyze authentication mechanisms
- Identify logic flaws
- Manipulate session tokens
- Bypass multi-factor authentication
- Exploit JWT vulnerabilities

### File Inclusion Vulnerabilities
- Identify file inclusion points
- Exploit local file inclusion (LFI)
- Execute remote file inclusion (RFI)
- Achieve RCE through log poisoning
- Bypass input filters

## 🛠️ Common Tools

- **Burp Suite** - Web application testing platform
- **SQLMap** - Automated SQL injection tool
- **ffuf** - Fast web fuzzer
- **Gobuster** - Directory/file brute-forcer
- **Nikto** - Web server scanner

## 📚 Key Concepts

### OWASP Top 10 Vulnerabilities
1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity Failures
9. Security Logging and Monitoring Failures
10. Server-Side Request Forgery (SSRF)

### Testing Methodology
1. **Information Gathering** - Understand the application
2. **Input Analysis** - Identify injection points
3. **Vulnerability Testing** - Test for specific vulnerabilities
4. **Exploitation** - Exploit confirmed vulnerabilities
5. **Documentation** - Document findings and impact

## 🔍 Common Attack Vectors

### Injection Attacks
- SQL Injection
- Command Injection
- LDAP Injection
- XPath Injection
- XML Injection

### Authentication Attacks
- Credential brute forcing
- Session fixation
- Session hijacking
- Token manipulation
- Logic flaws

### File-based Attacks
- Path traversal
- Local file inclusion
- Remote file inclusion
- Arbitrary file upload
- File type bypass

## 📖 Recommended Reading

- OWASP Web Security Testing Guide
- PortSwigger Web Security Academy
- Bug Bounty Bootcamp
- The Web Application Hacker's Handbook

## ⚠️ Responsible Disclosure

Always practice responsible disclosure:
- Only test on authorized targets
- Document all findings professionally
- Report vulnerabilities responsibly
- Follow the platform's disclosure policy

---

*Practice safe, legal, and ethical hacking! 🔒*
