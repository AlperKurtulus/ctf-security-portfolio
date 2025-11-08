# TCP - Back to School

**Category:** Programming  
**Difficulty:** ⭐⭐ (Medium)  
**Points:** 10  
**Platform:** [Root-me](https://www.root-me.org/)

---

## 📋 Challenge Description

This programming challenge tests your ability to create a TCP client that connects to a remote server, receives data, performs calculations, and sends back the results. It's called "Back to School" because it involves solving basic arithmetic problems programmatically.

The challenge teaches:
- TCP socket programming
- Network communication protocols
- String parsing and data extraction
- Arithmetic operations
- Automated problem-solving

---

## 🎯 Objective

Connect to the challenge server via TCP, receive arithmetic problems, solve them automatically, and send back the correct answers to retrieve the flag.

---

## 🔍 Approach

### 1. Understanding the Challenge

The server typically:
1. Sends a series of arithmetic expressions (e.g., "5 + 3", "10 * 2")
2. Expects the client to calculate the result
3. Requires the answer to be sent back in a specific format
4. Sends the flag after all problems are solved correctly

### 2. Protocol Analysis

First, manually connect to understand the protocol:

```bash
# Connect using netcat
nc challenge03.root-me.org [port]

# Observe:
# - What format are questions in?
# - How should answers be formatted?
# - How many questions are there?
# - Is there a time limit?
```

### 3. Solution Strategy

Create a script that:
1. Establishes a TCP connection
2. Receives and parses arithmetic expressions
3. Evaluates the expressions
4. Sends back the results
5. Retrieves and displays the flag

---

## 💡 Solution

### Python Solution

```python
#!/usr/bin/env python3
"""
TCP - Back to School Solver
Connects to server, solves arithmetic problems, retrieves flag
"""

import socket
import re

# Challenge server details
HOST = 'challenge03.root-me.org'
PORT = 52002  # Update with actual port

def solve_arithmetic(expression):
    """
    Safely evaluate arithmetic expression
    Only allows basic operations: +, -, *, /
    """
    try:
        # Remove any non-arithmetic characters except operators and numbers
        clean_expr = re.sub(r'[^0-9+\-*/(). ]', '', expression)
        
        # Evaluate the expression
        result = eval(clean_expr)
        
        # Return as integer if possible, otherwise float
        return int(result) if result == int(result) else result
    except Exception as e:
        print(f"Error evaluating expression: {expression}")
        print(f"Error: {e}")
        return None

def main():
    """Main function to solve the challenge"""
    
    # Create TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"[+] Connecting to {HOST}:{PORT}")
        
        try:
            # Connect to the server
            s.connect((HOST, PORT))
            print("[+] Connected!")
            
            # Receive initial message/instructions
            data = s.recv(4096).decode('utf-8')
            print(f"[*] Received:\n{data}\n")
            
            # Main loop to solve problems
            while True:
                # Receive question
                data = s.recv(4096).decode('utf-8').strip()
                
                if not data:
                    print("[-] Connection closed by server")
                    break
                
                print(f"[*] Received: {data}")
                
                # Check if we got the flag
                if 'flag' in data.lower() or 'congratulations' in data.lower():
                    print(f"[+] Flag found: {data}")
                    break
                
                # Extract the arithmetic expression
                # Look for patterns like "Calculate: 5 + 3" or just "5 + 3"
                match = re.search(r'[\d\s+\-*/().]+', data)
                
                if match:
                    expression = match.group(0).strip()
                    print(f"[*] Expression: {expression}")
                    
                    # Solve the expression
                    result = solve_arithmetic(expression)
                    
                    if result is not None:
                        print(f"[*] Result: {result}")
                        
                        # Send the answer
                        answer = str(result) + '\n'
                        s.sendall(answer.encode('utf-8'))
                        print(f"[+] Sent: {result}")
                    else:
                        print("[-] Failed to solve expression")
                        break
                else:
                    print("[-] Could not extract expression from data")
                    # Try sending the data back or continue
                    continue
            
            # Receive final response (might contain flag)
            try:
                final_data = s.recv(4096).decode('utf-8')
                if final_data:
                    print(f"\n[+] Final message:\n{final_data}")
            except:
                pass
                
        except socket.error as e:
            print(f"[-] Socket error: {e}")
        except Exception as e:
            print(f"[-] Error: {e}")

if __name__ == "__main__":
    main()
```

### Alternative Python Solution (More Robust)

```python
#!/usr/bin/env python3

import socket
import re
import time

HOST = 'challenge03.root-me.org'
PORT = 52002

def safe_eval(expression):
    """Safely evaluate mathematical expression"""
    # Only allow specific characters
    allowed_chars = set('0123456789+-*/(). ')
    if not all(c in allowed_chars for c in expression):
        return None
    
    try:
        return eval(expression)
    except:
        return None

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    
    buffer = ""
    
    while True:
        # Receive data
        chunk = s.recv(1024).decode('utf-8')
        if not chunk:
            break
            
        buffer += chunk
        print(f"Received: {chunk}")
        
        # Look for arithmetic expressions
        lines = buffer.split('\n')
        
        for line in lines:
            # Find expressions like: "12 + 34" or "Calculate: 12 + 34"
            match = re.search(r'([\d\s+\-*/().]+)(?:\s*=\s*\?)?', line)
            
            if match:
                expression = match.group(1).strip()
                
                # Skip if it looks like a result line
                if '=' in line and '?' not in line:
                    continue
                
                result = safe_eval(expression)
                
                if result is not None:
                    print(f"Expression: {expression} = {result}")
                    s.sendall(f"{result}\n".encode('utf-8'))
                    time.sleep(0.1)  # Small delay
        
        # Check for flag
        if 'flag' in buffer.lower() or 'congratulations' in buffer.lower():
            print(f"\n[+] Success! {buffer}")
            break
        
        buffer = lines[-1]  # Keep incomplete line
    
    s.close()

if __name__ == "__main__":
    main()
```

### Bash/Netcat Solution

```bash
#!/bin/bash

# Simple bash solution using netcat and bc

HOST="challenge03.root-me.org"
PORT="52002"

{
    # Wait for initial message
    sleep 1
    
    # Read and solve problems
    while true; do
        read -r line
        echo "Received: $line"
        
        # Extract expression using regex
        expression=$(echo "$line" | grep -oE '[0-9 +\-*/().]+')
        
        if [ -n "$expression" ]; then
            # Calculate using bc
            result=$(echo "$expression" | bc)
            echo "Sending: $result"
            echo "$result"
            
            sleep 0.5
        fi
        
        # Check for flag
        if echo "$line" | grep -qi "flag"; then
            echo "Flag found: $line"
            break
        fi
    done
} | nc "$HOST" "$PORT"
```

---

## 🧠 Key Concepts

### TCP Socket Programming

**TCP (Transmission Control Protocol)** provides reliable, ordered data transmission:

```python
# Create socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to server
s.connect((HOST, PORT))

# Send data
s.sendall(data.encode('utf-8'))

# Receive data
data = s.recv(4096).decode('utf-8')

# Close connection
s.close()
```

### String Parsing

Extract data from server responses:

```python
# Using regex to find numbers and operators
pattern = r'[\d\s+\-*/()]+'
match = re.search(pattern, text)

# Extract specific patterns
numbers = re.findall(r'\d+', text)
```

### Safe Expression Evaluation

**Important:** Never use `eval()` on untrusted input in production. For CTF:

```python
# Controlled environment - CTF challenge
result = eval(expression)

# Production - Use safer alternatives:
import ast
result = ast.literal_eval(simple_expression)

# Or parse and calculate manually
```

---

## 🔧 Tools Used

- **Python3** - Primary programming language
- **socket** - TCP network communication
- **re** (regex) - Pattern matching and extraction
- **netcat** - Manual protocol analysis
- **bc** - Bash calculator for shell scripts

---

## 📚 Lessons Learned

### Technical Skills

1. **Network Programming**
   - TCP socket creation and management
   - Client-server communication
   - Data encoding/decoding

2. **Protocol Analysis**
   - Understanding server-client protocols
   - Identifying message patterns
   - Response format expectations

3. **Automation**
   - Automated problem-solving
   - Script-based challenges
   - Timing and synchronization

4. **String Processing**
   - Regular expressions
   - Data extraction
   - Pattern matching

### Best Practices

1. **Always analyze protocol first** - Manual connection helps understand the format
2. **Handle edge cases** - Different expression formats, multiple problems
3. **Add error handling** - Network issues, parsing errors
4. **Use timeouts** - Prevent hanging connections
5. **Log everything** - Helps debugging when things go wrong

---

## 🔗 References

- [Python Socket Documentation](https://docs.python.org/3/library/socket.html)
- [Python re Module](https://docs.python.org/3/library/re.html)
- [TCP/IP Protocol](https://en.wikipedia.org/wiki/Transmission_Control_Protocol)
- [Network Programming Guide](https://beej.us/guide/bgnet/)

---

## 🎓 Difficulty Assessment

**Skill Level Required:** Intermediate  
**Time to Complete:** 20-30 minutes  
**Prerequisites:**
- Basic Python programming
- Understanding of TCP/IP
- Regular expressions knowledge
- Socket programming basics

---

## 📝 Troubleshooting Tips

### Common Issues

1. **Connection Timeout**
   ```python
   s.settimeout(10)  # Set 10 second timeout
   ```

2. **Incomplete Data Reception**
   ```python
   # Receive until specific delimiter
   data = b''
   while b'\n' not in data:
       data += s.recv(1024)
   ```

3. **Encoding Issues**
   ```python
   # Try different encodings
   data = s.recv(4096).decode('utf-8', errors='ignore')
   ```

4. **Timing Issues**
   ```python
   import time
   time.sleep(0.1)  # Small delay between operations
   ```

---

## ✅ Validation

Run your script and verify:
- [ ] Successfully connects to server
- [ ] Receives and parses questions correctly
- [ ] Calculates answers accurately
- [ ] Sends responses in correct format
- [ ] Retrieves the flag

**Challenge Status:** ✅ Completed  
**Date Completed:** [Your completion date]  
**Points Earned:** 10

---

*This writeup is for educational purposes only. Always obtain proper authorization before testing systems.*
