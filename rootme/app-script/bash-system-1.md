# Bash - System 1

**Category:** App-Script  
**Difficulty:** ⭐ (Easy)  
**Points:** 5  
**Platform:** [Root-me](https://www.root-me.org/)

---

## 📋 Challenge Description

This challenge introduces basic Linux system enumeration and file system navigation. The goal is to find and read a password file located somewhere in the system using standard Linux commands.

The challenge teaches fundamental skills needed for system enumeration:
- Linux command-line navigation
- File system structure understanding
- Basic enumeration techniques
- Environment variable usage

---

## 🎯 Objective

Find and retrieve the password flag hidden in the system using basic bash commands and Linux fundamentals.

---

## 🔍 Approach

### 1. Initial Reconnaissance

First, we need to understand our current position in the system:

```bash
# Check current directory
pwd

# List files in current directory
ls -la

# Check our current user
whoami

# Check environment variables
env
```

### 2. System Enumeration

Explore the file system structure to understand what's available:

```bash
# List root directory
ls -la /

# Check common directories
ls -la /home
ls -la /tmp
ls -la /var

# Look for interesting files
find / -name "*.txt" 2>/dev/null
find / -name "*password*" 2>/dev/null
```

### 3. Finding the Flag

The challenge typically hides the password in a predictable location. Common places to check:

```bash
# Check home directory
ls -la ~
cat ~/.bashrc

# Check current directory for hidden files
ls -la

# Look for environment variables containing passwords
env | grep -i pass
env | grep -i flag
```

---

## 💡 Solution

### Step-by-Step Solution

1. **Connect to the challenge environment** via SSH or web shell

2. **Check environment variables** - Often, flags in basic challenges are stored in environment variables:

```bash
env
```

3. **Look for the password variable**:

```bash
env | grep -i password
# or
echo $PASSWORD
```

4. **Alternative: Search the file system**:

```bash
# Search for files with 'password' in the name
find / -name "*password*" 2>/dev/null

# Check common locations
cat /etc/passwd
cat ~/password.txt
cat /.password
```

5. **Read the password file**:

```bash
cat [path_to_password_file]
```

### Expected Output

The password will be a string that you need to submit to validate the challenge. It typically looks something like:

```
the_password_is_example123
```

---

## 🧠 Key Concepts

### Environment Variables

Environment variables in Linux are dynamic values that affect processes and programs:

```bash
# View all environment variables
env
printenv

# View specific variable
echo $HOME
echo $PATH
echo $USER

# Set a variable
export MY_VAR="value"
```

### File System Navigation

Understanding Linux file system structure:

```
/           - Root directory
/home       - User home directories
/etc        - Configuration files
/tmp        - Temporary files
/var        - Variable data (logs, etc.)
/usr        - User programs
/opt        - Optional software
```

### Basic Linux Commands

Essential commands used in this challenge:

```bash
pwd         # Print working directory
ls          # List files
ls -la      # List all files with details
cd          # Change directory
cat         # Display file contents
find        # Search for files
grep        # Search within files
env         # Show environment variables
whoami      # Current username
```

---

## 🔧 Tools Used

- **bash** - Linux shell
- **ls** - List directory contents
- **cat** - Concatenate and display files
- **env** - Display environment variables
- **find** - Search for files
- **grep** - Pattern matching

---

## 📚 Lessons Learned

### Security Implications

1. **Environment Variables Can Leak Sensitive Data**
   - Passwords and API keys should never be stored in plain environment variables
   - Use secure secret management systems instead

2. **File System Permissions**
   - Understanding file permissions is crucial for security
   - Files containing sensitive data should have restricted permissions

3. **System Enumeration Basics**
   - This is the first step in any penetration test
   - Knowing how to enumerate a system is fundamental

### Best Practices

- **Never store passwords in plain text** in environment variables or files
- **Use proper file permissions** (chmod) to protect sensitive files
- **Implement proper secret management** using tools like HashiCorp Vault, AWS Secrets Manager, etc.
- **Audit environment variables** in production systems

---

## 🔗 References

- [Linux File System Hierarchy](https://www.pathname.com/fhs/)
- [Bash Environment Variables](https://www.gnu.org/software/bash/manual/html_node/Environment.html)
- [Linux Command Cheatsheet](https://www.linuxtrainingacademy.com/linux-commands-cheat-sheet/)
- [GTFOBins](https://gtfobins.github.io/) - Unix binaries that can be exploited

---

## 🎓 Difficulty Assessment

**Skill Level Required:** Beginner  
**Time to Complete:** 5-10 minutes  
**Prerequisites:**
- Basic Linux command-line knowledge
- Understanding of file system navigation
- Familiarity with environment variables

---

## 📝 Notes

This challenge serves as an excellent introduction to Linux system enumeration. The skills learned here are foundational for more advanced challenges and real-world penetration testing scenarios.

**Key Takeaway:** Always start with basic enumeration - check environment variables, file permissions, and common file locations before moving to more complex techniques.

---

## ✅ Validation

Once you find the password, submit it through the Root-me platform to validate the challenge completion and earn your points.

**Challenge Status:** ✅ Completed  
**Date Completed:** [Your completion date]  
**Points Earned:** 5

---

*This writeup is for educational purposes only. Always obtain proper authorization before testing systems.*
