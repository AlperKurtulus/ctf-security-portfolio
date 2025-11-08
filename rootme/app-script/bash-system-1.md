# Bash - System 1

**Category:** App-Script  
**Difficulty:** ⭐ (Easy)  
**Points:** 5  
**Platform:** Root-me

---

## 📋 Challenge Description

This challenge introduces basic Linux system enumeration and file navigation. The goal is to find a password hidden in the system using fundamental Linux commands and understanding of the file system structure.

**Objective:** Find the password stored in a specific location on the system.

---

## 🎯 Learning Objectives

- Master basic Linux commands
- Understand Linux file system structure
- Learn file search techniques
- Practice environment variable usage
- Develop systematic enumeration approach

---

## 🔍 Initial Reconnaissance

### Challenge Access

Upon SSH connection to the challenge server:
```bash
ssh -p 2222 app-script-ch1@challenge.root-me.org
```

We're presented with a limited shell environment where we need to find the password.

---

## 🕵️ Enumeration

### Step 1: Identify Current Context

```bash
# Check current user
whoami
# Output: app-script-ch1

# Check current directory
pwd
# Output: /challenge/app-script/ch1

# List files in current directory
ls -la
```

### Step 2: System Exploration

```bash
# Check home directory
cd ~
ls -la

# Explore common directories
ls -la /tmp
ls -la /var
ls -la /opt
```

### Step 3: Search for Interesting Files

```bash
# Search for files with specific names
find / -name "*password*" 2>/dev/null
find / -name "*.txt" 2>/dev/null
find / -name ".passwd" 2>/dev/null

# Search in home directory
find ~ -type f 2>/dev/null
```

### Step 4: Environment Variables

```bash
# Check all environment variables
env

# Look for interesting variables
echo $HOME
echo $USER
echo $PATH
echo $OLDPWD
```

### Step 5: Hidden Files

```bash
# Check for hidden files (starting with .)
ls -la ~/
ls -la ~/.??*

# Common hidden file locations
cat ~/.bashrc
cat ~/.bash_profile
cat ~/.bash_history
```

---

## 💥 Exploitation

### Finding the Password

**Method 1: Environment Variable**

The password is often stored in an environment variable:

```bash
# List all environment variables
env

# Search for password-related variables
env | grep -i pass
env | grep -i pwd
env | grep -i secret
```

**Expected output:**
```
PASSWORD=yourpasswordhere
```

**Method 2: Hidden File**

Sometimes the password is in a hidden file:

```bash
# Check for hidden files in home directory
ls -la ~/

# Check a specific hidden file
cat ~/.passwd
```

**Method 3: Specific Directory**

The password might be in a file in the challenge directory:

```bash
# Check challenge directory
cd /challenge/app-script/ch1
ls -la

# Read potential password files
cat .passwd
cat password.txt
cat README
```

### Retrieving the Password

Once located, simply read the file or environment variable:

```bash
# If in environment variable
echo $PASSWORD

# If in file
cat ~/.passwd
```

---

## 🔑 Solution

**Password Location:** Environment variable `$PASSWORD` or file `~/.passwd`

**Steps to solve:**
1. Connect via SSH
2. Run `env` or `env | grep -i pass`
3. Find the PASSWORD variable
4. Echo the value: `echo $PASSWORD`
5. Submit the password

**Flag/Password:** `[hidden for learning purposes]`

---

## 📚 Lessons Learned

### 1. Linux Basics

**Essential Commands:**
```bash
pwd         # Print working directory
ls -la      # List all files including hidden
cd          # Change directory
cat         # Display file contents
env         # Show environment variables
find        # Search for files
grep        # Search within files
echo        # Display text/variables
```

### 2. Environment Variables

Environment variables store system-wide or user-specific settings:

```bash
# Display all
env

# Display specific
echo $VARIABLE_NAME

# Set variable (temporary)
export MY_VAR="value"

# Common variables
$HOME       # User home directory
$USER       # Current username
$PATH       # Command search paths
$PWD        # Current directory
$SHELL      # Current shell
```

### 3. Hidden Files in Linux

Files starting with `.` are hidden:

```bash
# Show hidden files
ls -la

# Hidden files examples
.bashrc         # Bash configuration
.bash_history   # Command history
.ssh/           # SSH keys and config
.passwd         # Custom password files
```

### 4. File System Navigation

**Linux File System Hierarchy:**
```
/           # Root directory
/home       # User home directories
/etc        # Configuration files
/var        # Variable data
/tmp        # Temporary files
/opt        # Optional software
/usr        # User programs
/bin        # Essential binaries
```

### 5. Search Techniques

**Finding Files:**
```bash
# By name
find / -name "filename" 2>/dev/null

# By type
find / -type f 2>/dev/null    # Files
find / -type d 2>/dev/null    # Directories

# By permission
find / -perm -4000 2>/dev/null    # SUID files

# By content
grep -r "password" /home 2>/dev/null
```

---

## 🛡️ Security Implications

### Why This Matters

1. **Sensitive Data Exposure**
   - Passwords in environment variables are visible to all processes
   - Hidden files aren't truly hidden
   - File permissions are crucial

2. **Enumeration is Key**
   - Attackers systematically enumerate systems
   - Weak hiding places are quickly discovered
   - Proper secrets management is essential

### Proper Secret Management

**DON'T:**
```bash
# Bad: Password in environment variable
export PASSWORD="mypassword"

# Bad: Password in plain text file
echo "mypassword" > ~/.passwd

# Bad: Password in script
password="mypassword"
```

**DO:**
```bash
# Good: Use secure credential storage
# - Operating system credential managers
# - Encrypted configuration files
# - Password managers
# - Environment-specific secret management (e.g., AWS Secrets Manager)

# Good: Proper file permissions
chmod 600 sensitive_file  # Only owner can read/write

# Good: Encrypted storage
gpg -c sensitive_file     # Encrypt file
```

---

## 💡 Additional Tips

### For CTF Challenges

1. **Start Simple**
   - Check current directory first
   - Look at environment variables
   - Search for obvious files

2. **Be Systematic**
   - Make a checklist
   - Document what you've tried
   - Don't skip basic enumeration

3. **Read Everything**
   - READMEs, hints, error messages
   - File names can be clues
   - Pay attention to permissions

### Commands Cheat Sheet

```bash
# Navigation
pwd                    # Where am I?
ls -la                 # What's here?
cd /path              # Go somewhere
cd ~                  # Go home
cd ..                 # Go up one level

# File Operations
cat file              # Read file
less file             # Read file (paginated)
head file             # First lines
tail file             # Last lines
file filename         # Identify file type

# Search
find / -name "*.txt" 2>/dev/null
grep -r "text" /path 2>/dev/null
locate filename

# Environment
env                   # All variables
echo $VAR            # Specific variable
export VAR="value"   # Set variable

# Information
whoami               # Current user
id                   # User ID and groups
uname -a             # System info
cat /etc/passwd      # User accounts
```

---

## 📖 References

- [Linux Command Line Basics](https://ubuntu.com/tutorials/command-line-for-beginners)
- [Linux File System Hierarchy](https://www.pathname.com/fhs/)
- [Bash Environment Variables](https://www.gnu.org/software/bash/manual/html_node/Environment.html)
- [Linux Hidden Files](https://linuxhandbook.com/show-hidden-files-linux/)

---

## 🎓 Next Steps

After completing this challenge:
1. Try **Bash - System 2** for more advanced techniques
2. Explore **Environment Variables** challenge
3. Learn about **Sudo** misconfigurations
4. Practice with more App-Script challenges

---

**Date Completed:** November 2025  
**Time Taken:** 10 minutes  
**Difficulty Rating:** 2/10

---

*This is the perfect starting point for learning Linux system enumeration!*
