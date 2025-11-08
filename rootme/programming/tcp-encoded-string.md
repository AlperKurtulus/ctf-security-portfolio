# TCP - Encoded String

**Category:** Programming  
**Difficulty:** ⭐⭐ (Medium)  
**Points:** 15  
**Platform:** [Root-me](https://www.root-me.org/)

---

## 📋 Challenge Description

This programming challenge requires connecting to a TCP server that sends encoded strings. Your task is to decode the strings using various encoding schemes and send back the decoded results. The challenge tests your knowledge of common encoding methods used in cybersecurity.

Common encodings you might encounter:
- Base64
- Hexadecimal
- URL encoding
- ROT13
- Binary
- ASCII codes

---

## 🎯 Objective

Connect to the challenge server, receive encoded strings, decode them using appropriate methods, and send back the decoded text to retrieve the flag.

---

## 🔍 Approach

### 1. Protocol Analysis

First, connect manually to understand the server's behavior:

```bash
# Connect to the server
nc challenge03.root-me.org [port]

# Observe:
# - What encoding format is used?
# - Are multiple encoding methods used?
# - Is the encoding type specified?
# - What format should the answer be in?
```

### 2. Identify Encoding Types

Common patterns to recognize:

```
Base64:       Ends with = or ==, uses A-Z, a-z, 0-9, +, /
Hex:          Only 0-9, A-F characters, often in pairs
Binary:       Only 0 and 1
URL Encoded:  Contains %XX patterns
ROT13:        Looks like scrambled English text
ASCII codes:  Space-separated numbers (typically 32-126)
```

### 3. Solution Strategy

1. Connect to the server
2. Receive the encoded string
3. Identify the encoding method
4. Decode the string
5. Send the decoded result
6. Repeat until flag is received

---

## 💡 Solution

### Python Solution

```python
#!/usr/bin/env python3
"""
TCP - Encoded String Solver
Handles multiple encoding schemes
"""

import socket
import base64
import binascii
from urllib.parse import unquote
import codecs
import re

# Challenge server details
HOST = 'challenge03.root-me.org'
PORT = 52003  # Update with actual port

def decode_base64(encoded_str):
    """Decode Base64 string"""
    try:
        decoded = base64.b64decode(encoded_str).decode('utf-8')
        return decoded
    except Exception as e:
        return None

def decode_hex(encoded_str):
    """Decode hexadecimal string"""
    try:
        # Remove spaces and convert
        hex_str = encoded_str.replace(' ', '').replace('0x', '')
        decoded = bytes.fromhex(hex_str).decode('utf-8')
        return decoded
    except Exception as e:
        return None

def decode_binary(encoded_str):
    """Decode binary string"""
    try:
        # Remove spaces and split into 8-bit chunks
        binary_str = encoded_str.replace(' ', '')
        decoded = ''.join(chr(int(binary_str[i:i+8], 2)) 
                         for i in range(0, len(binary_str), 8))
        return decoded
    except Exception as e:
        return None

def decode_rot13(encoded_str):
    """Decode ROT13 string"""
    try:
        decoded = codecs.decode(encoded_str, 'rot_13')
        return decoded
    except Exception as e:
        return None

def decode_url(encoded_str):
    """Decode URL encoded string"""
    try:
        decoded = unquote(encoded_str)
        return decoded
    except Exception as e:
        return None

def decode_ascii_codes(encoded_str):
    """Decode space-separated ASCII codes"""
    try:
        codes = encoded_str.strip().split()
        decoded = ''.join(chr(int(code)) for code in codes)
        return decoded
    except Exception as e:
        return None

def identify_and_decode(encoded_str):
    """
    Identify encoding type and decode
    Returns: (decoded_string, encoding_type)
    """
    encoded_str = encoded_str.strip()
    
    # Try to identify encoding type
    
    # Check for Base64 (contains =, uses Base64 charset)
    if re.match(r'^[A-Za-z0-9+/]+={0,2}$', encoded_str):
        decoded = decode_base64(encoded_str)
        if decoded:
            return decoded, "Base64"
    
    # Check for Hex (only hex characters)
    if re.match(r'^[0-9A-Fa-f\s]+$', encoded_str) and len(encoded_str.replace(' ', '')) % 2 == 0:
        decoded = decode_hex(encoded_str)
        if decoded:
            return decoded, "Hexadecimal"
    
    # Check for Binary (only 0 and 1)
    if re.match(r'^[01\s]+$', encoded_str) and len(encoded_str.replace(' ', '')) % 8 == 0:
        decoded = decode_binary(encoded_str)
        if decoded:
            return decoded, "Binary"
    
    # Check for ASCII codes (space-separated numbers)
    if re.match(r'^[\d\s]+$', encoded_str):
        decoded = decode_ascii_codes(encoded_str)
        if decoded and decoded.isprintable():
            return decoded, "ASCII Codes"
    
    # Check for URL encoding (contains %)
    if '%' in encoded_str:
        decoded = decode_url(encoded_str)
        if decoded != encoded_str:
            return decoded, "URL Encoded"
    
    # Try ROT13 if text looks scrambled
    if re.match(r'^[A-Za-z\s]+$', encoded_str):
        decoded = decode_rot13(encoded_str)
        if decoded:
            return decoded, "ROT13"
    
    return None, "Unknown"

def main():
    """Main function to solve the challenge"""
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"[+] Connecting to {HOST}:{PORT}")
        
        try:
            s.connect((HOST, PORT))
            print("[+] Connected!")
            
            # Receive and display initial message
            initial = s.recv(4096).decode('utf-8')
            print(f"[*] Initial message:\n{initial}\n")
            
            # Main loop
            buffer = ""
            
            while True:
                # Receive data
                chunk = s.recv(4096).decode('utf-8')
                
                if not chunk:
                    print("[-] Connection closed")
                    break
                
                buffer += chunk
                print(f"[*] Received: {chunk.strip()}")
                
                # Check for flag
                if 'flag' in buffer.lower() or 'congratulations' in buffer.lower():
                    print(f"\n[+] Success!\n{buffer}")
                    break
                
                # Extract encoded string
                # Look for the encoded data (might be after "Decode: " or similar)
                lines = buffer.split('\n')
                
                for line in lines:
                    if not line.strip() or 'decode' in line.lower() and ':' in line:
                        # Extract the part after the colon if present
                        if ':' in line:
                            encoded_str = line.split(':', 1)[1].strip()
                        else:
                            continue
                    else:
                        encoded_str = line.strip()
                    
                    if encoded_str and len(encoded_str) > 5:  # Reasonable length
                        # Try to decode
                        decoded, encoding_type = identify_and_decode(encoded_str)
                        
                        if decoded:
                            print(f"[*] Detected encoding: {encoding_type}")
                            print(f"[*] Decoded: {decoded}")
                            
                            # Send the decoded string
                            response = decoded + '\n'
                            s.sendall(response.encode('utf-8'))
                            print(f"[+] Sent: {decoded}\n")
                            
                            buffer = ""  # Clear buffer
                            break
                        else:
                            print(f"[!] Could not decode: {encoded_str}")
                
        except socket.error as e:
            print(f"[-] Socket error: {e}")
        except Exception as e:
            print(f"[-] Error: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()
```

### Compact Solution

```python
#!/usr/bin/env python3

import socket
import base64
import binascii
from urllib.parse import unquote
import codecs

HOST = 'challenge03.root-me.org'
PORT = 52003

def decode(s):
    """Try multiple decoding methods"""
    
    # Base64
    try:
        return base64.b64decode(s).decode('utf-8')
    except: pass
    
    # Hex
    try:
        return bytes.fromhex(s.replace(' ', '')).decode('utf-8')
    except: pass
    
    # Binary
    try:
        return ''.join(chr(int(s[i:i+8], 2)) for i in range(0, len(s), 8))
    except: pass
    
    # ASCII codes
    try:
        return ''.join(chr(int(x)) for x in s.split())
    except: pass
    
    # URL encoding
    try:
        decoded = unquote(s)
        if decoded != s:
            return decoded
    except: pass
    
    # ROT13
    try:
        return codecs.decode(s, 'rot_13')
    except: pass
    
    return None

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    
    print(s.recv(4096).decode())  # Initial message
    
    while True:
        data = s.recv(4096).decode().strip()
        print(f"Received: {data}")
        
        if 'flag' in data.lower():
            print(f"Flag: {data}")
            break
        
        decoded = decode(data)
        
        if decoded:
            print(f"Decoded: {decoded}")
            s.sendall(f"{decoded}\n".encode())
        else:
            print("Failed to decode")
            break
    
    s.close()

if __name__ == "__main__":
    main()
```

---

## 🧠 Key Concepts

### Common Encodings

#### 1. Base64
```python
import base64

# Encode
encoded = base64.b64encode(b"Hello World").decode()
# Output: SGVsbG8gV29ybGQ=

# Decode
decoded = base64.b64decode(encoded).decode()
# Output: Hello World
```

#### 2. Hexadecimal
```python
# Encode
text = "Hello"
hex_encoded = text.encode().hex()
# Output: 48656c6c6f

# Decode
decoded = bytes.fromhex(hex_encoded).decode()
# Output: Hello
```

#### 3. Binary
```python
# Encode
text = "A"
binary = bin(ord(text))[2:].zfill(8)
# Output: 01000001

# Decode
decoded = chr(int(binary, 2))
# Output: A
```

#### 4. ROT13
```python
import codecs

# Encode/Decode (ROT13 is symmetric)
encoded = codecs.encode("Hello", 'rot_13')
# Output: Uryyb

decoded = codecs.decode(encoded, 'rot_13')
# Output: Hello
```

#### 5. URL Encoding
```python
from urllib.parse import quote, unquote

# Encode
encoded = quote("Hello World!")
# Output: Hello%20World%21

# Decode
decoded = unquote(encoded)
# Output: Hello World!
```

#### 6. ASCII Codes
```python
# Encode
text = "Hi"
codes = ' '.join(str(ord(c)) for c in text)
# Output: 72 105

# Decode
decoded = ''.join(chr(int(x)) for x in codes.split())
# Output: Hi
```

---

## 🔧 Tools Used

- **Python3** - Primary language
- **base64** - Base64 encoding/decoding
- **binascii** - Binary to ASCII conversions
- **urllib.parse** - URL encoding/decoding
- **codecs** - ROT13 and other codecs
- **re** - Regular expressions for pattern matching

---

## 📚 Lessons Learned

### Encoding vs Encryption

**Important distinction:**

- **Encoding** - Transform data for compatibility (reversible, not secure)
  - Base64, Hex, URL encoding
  - Anyone can decode without a key
  
- **Encryption** - Transform data for confidentiality (reversible with key)
  - AES, RSA, etc.
  - Requires secret key to decrypt

### Pattern Recognition

Learn to recognize encoding patterns:

```
Base64:        SGVsbG8gV29ybGQ=
Hex:           48656c6c6f20576f726c64
Binary:        01001000 01100101
URL:           Hello%20World
ASCII:         72 101 108 108 111
ROT13:         Uryyb Jbeyq
```

### Automation Importance

In cybersecurity:
- Manual decoding is slow
- Automation allows rapid analysis
- Scripts handle bulk data processing
- Essential for CTFs and real-world scenarios

---

## 🔗 References

- [Python base64 module](https://docs.python.org/3/library/base64.html)
- [Python codecs module](https://docs.python.org/3/library/codecs.html)
- [CyberChef](https://gchq.github.io/CyberChef/) - Encoding/decoding web tool
- [Base64 Decoder](https://www.base64decode.org/)
- [ASCII Table](https://www.asciitable.com/)

---

## 🎓 Difficulty Assessment

**Skill Level Required:** Intermediate  
**Time to Complete:** 20-30 minutes  
**Prerequisites:**
- Python programming
- Understanding of encoding schemes
- Socket programming basics
- Pattern recognition skills

---

## 📝 Debugging Tips

### 1. Test Encodings Separately

```python
# Test your decoding functions
test_cases = {
    'Base64': 'SGVsbG8=',
    'Hex': '48656c6c6f',
    'Binary': '01001000 01100101',
    'ASCII': '72 101 108 108 111'
}

for encoding, test in test_cases.items():
    result = decode(test)
    print(f"{encoding}: {result}")
```

### 2. Add Verbose Logging

```python
def decode_with_logging(encoded_str):
    print(f"Trying to decode: {encoded_str}")
    print(f"Length: {len(encoded_str)}")
    print(f"Characters: {set(encoded_str)}")
    
    # Try each method with logging
    # ...
```

### 3. Handle Partial Receives

```python
def receive_until(sock, delimiter='\n'):
    """Receive data until delimiter"""
    data = b''
    while delimiter.encode() not in data:
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode()
```

---

## ✅ Validation

Verify your solution:
- [ ] Correctly identifies encoding types
- [ ] Successfully decodes all formats
- [ ] Handles multiple rounds of encoding
- [ ] Retrieves the flag
- [ ] Works reliably with different inputs

**Challenge Status:** ✅ Completed  
**Date Completed:** [Your completion date]  
**Points Earned:** 15

---

## 💡 Pro Tips

1. **CyberChef is your friend** - Use it to test encodings manually first
2. **Chain decoding** - Some challenges use multiple encoding layers
3. **Character set analysis** - Look at what characters are present
4. **Test incrementally** - Test each decoding function separately
5. **Keep a library** - Build a reusable encoding/decoding library

---

*This writeup is for educational purposes only. Always obtain proper authorization before testing systems.*
