# Ethernet Frame Analysis

**Platform:** Root-me  
**Category:** Network  
**Difficulty:** ⭐ Easy  
**Date Solved:** November 2025

---

## 📋 Challenge Description

This challenge involves analyzing raw Ethernet frame data to extract hidden credentials. The objective is to decode a hexadecimal dump of network traffic and identify HTTP Basic Authentication headers.

**Objective:** Extract the credentials from the raw Ethernet frame data.

---

## 🎯 Learning Objectives

- Understand Ethernet frame structure
- Parse raw hexadecimal network data
- Identify HTTP protocol headers
- Decode Base64 encoded credentials
- Develop network analysis skills

---

## 🔍 Initial Analysis

### Understanding the Challenge

The challenge provides a file containing raw hexadecimal data representing an Ethernet frame. This data needs to be:
1. Cleaned and parsed from hex format
2. Decoded to readable text
3. Analyzed for authentication headers
4. Credentials extracted and decoded from Base64

### Ethernet Frame Structure

```
+------------------+------------------+------+------------------+-----+
| Dest MAC (6B)    | Src MAC (6B)     | Type | Payload          | FCS |
+------------------+------------------+------+------------------+-----+
```

The payload contains the IP header, TCP header, and HTTP data with authentication information.

---

## 🕵️ Reconnaissance

### Step 1: Examine the File

The file contains raw hexadecimal data with potential formatting characters (spaces, newlines):
```
00 05 73 a0 00 00 e0 69 95 d8 5a 13 08 00 45 00
...
```

### Step 2: Identify the Protocol

Within the decoded data, we look for:
- HTTP protocol indicators (`GET`, `POST`, `Authorization`)
- Base64 encoded strings (characters A-Z, a-z, 0-9, +, /)

---

## 💥 Exploitation

### Solution Approach

1. **Clean the Hex Data** - Remove non-hexadecimal characters
2. **Convert to Bytes** - Parse hex string to binary data
3. **Decode to Text** - Convert bytes to UTF-8 text
4. **Find Authorization Header** - Search for "Authorization: Basic"
5. **Decode Base64** - Extract and decode the credentials

### Python Script

The solution script (`Ethernet-frame.py`) automates this process:

```python
import re
import base64

def analyze_eth(file_name):
    with open(file_name, "r") as f:
        raw_data = f.read() 
        clean_hex = re.sub(r'[^0-9a-fA-F]', '', raw_data)

    byte_data = bytes.fromhex(clean_hex)
    decoded_text = byte_data.decode('utf-8', errors='ignore')

    target_header = "Authorization: Basic"
    
    if target_header in decoded_text:
        encoded_part = decoded_text.split(f"{target_header}")[1].split("\r\n")[0]
        decoded_cred = base64.b64decode(encoded_part).decode("utf-8")
        print(f"[+] SECRET FOUND: {decoded_cred}")
```

### Key Code Sections

#### Hex Cleaning with Regex
```python
clean_hex = re.sub(r'[^0-9a-fA-F]', '', raw_data)
```
This removes all characters that aren't valid hexadecimal digits.

#### Base64 Decoding
```python
decoded_cred = base64.b64decode(encoded_part).decode("utf-8")
```
The credentials are encoded in Base64 format (`username:password`).

---

## 🔑 Solution

**Steps to solve:**
1. Download the challenge file
2. Run the Python script against the file
3. The script extracts the Base64 encoded credentials
4. Decode reveals `username:password` format
5. Submit the password as the flag

**Flag:** `[hidden for learning purposes]`

---

## 📚 Lessons Learned

### 1. Network Protocol Analysis

Understanding how data flows through network layers:
- **Layer 2 (Ethernet):** MAC addresses, frame structure
- **Layer 3 (IP):** Source/destination IP addresses
- **Layer 4 (TCP):** Port numbers, sequence numbers
- **Layer 7 (HTTP):** Application data, headers

### 2. HTTP Basic Authentication

```
Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^
                     Base64 encoded credentials
```

**Format:** `username:password` → Base64 encode → Header value

**Security Implications:**
- Base64 is encoding, NOT encryption
- Credentials are easily reversible
- Always use HTTPS with Basic Auth
- Consider more secure alternatives (OAuth, JWT)

### 3. Regex for Data Cleaning

```python
import re
# Remove all non-hex characters
clean = re.sub(r'[^0-9a-fA-F]', '', dirty_data)
```

---

## 🛡️ Security Implications

### Why This Matters

1. **Credential Exposure** - Unencrypted HTTP traffic exposes credentials
2. **Network Sniffing** - Attackers can capture and analyze traffic
3. **Base64 is NOT Encryption** - Provides no security, only encoding

### Defense Recommendations

- ✅ Always use HTTPS/TLS for authentication
- ✅ Implement modern authentication (OAuth 2.0, JWT)
- ✅ Use certificate pinning in applications
- ✅ Enable HTTP Strict Transport Security (HSTS)
- ✅ Encrypt sensitive network traffic

---

## 🛠️ Tools Used

- **Python 3** - Scripting language
- **re module** - Regular expression processing
- **base64 module** - Base64 encoding/decoding
- **Wireshark** - Network protocol analyzer (optional)

---

## 📖 References

- [Ethernet Frame Format](https://en.wikipedia.org/wiki/Ethernet_frame)
- [HTTP Basic Authentication](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication)
- [Base64 Encoding](https://en.wikipedia.org/wiki/Base64)
- [Python re Module](https://docs.python.org/3/library/re.html)

---

## 📷 Screenshots

- ![Decoded HTTP headers](./images/Ethernet-frame.png)

---

## 🔗 Navigation

- [← Back to Network Overview](../README.md)
- [Next: FTP Authentication →](../ftp-auth/README.md)
- [Telnet Authentication](../telnet-auth/README.md)

---


**Date Completed:** November 2025  
**Time Taken:** 20 minutes  
**Difficulty Rating:** 3/10

---

*This challenge demonstrates the importance of encrypting network traffic!*
