# Programming Challenges

Network programming and encoding challenges focusing on socket programming, protocol implementation, and data manipulation.

**Challenges Completed:** 5  
**Total Points:** 40

---

## 📝 Available Writeups

### [TCP - Back to School](./tcp-back-to-school.md)
- **Points:** 5
- **Difficulty:** ⭐ Easy
- **Skills:** Socket programming, TCP connections, basic arithmetic

### [TCP - Encoded String](./tcp-encoded-string.md)
- **Points:** 5
- **Difficulty:** ⭐ Easy
- **Skills:** Base64 decoding, encoding schemes, string manipulation

### [TCP - Uncompress Me](./tcp-uncompress-me.md)
- **Points:** 10
- **Difficulty:** ⭐⭐ Medium
- **Skills:** Compression algorithms, zlib, data decompression

### TCP - Server Communication
- **Points:** 10
- **Difficulty:** ⭐⭐ Medium
- **Skills:** Protocol implementation, multi-step communication

### HTTP - User-Agent
- **Points:** 10
- **Difficulty:** ⭐ Easy
- **Skills:** HTTP headers, user-agent manipulation, HTTP requests

---

## 🎯 Learning Objectives

### Network Programming
- Understanding TCP/IP protocols
- Socket programming in Python
- Client-server communication
- Handling network data

### Data Manipulation
- Encoding/decoding techniques
- Compression algorithms
- String processing
- Binary data handling

### Protocol Implementation
- HTTP protocol basics
- Custom protocol implementation
- Request/response handling
- Multi-step communication

---

## 🛠️ Essential Tools & Libraries

### Python Socket Programming
```python
import socket

# Create TCP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to server
sock.connect(('host', port))

# Send data
sock.send(b'data')

# Receive data
data = sock.recv(1024)

# Close connection
sock.close()
```

### Common Python Libraries
```python
import socket      # Network programming
import base64      # Base64 encoding/decoding
import zlib        # Compression/decompression
import requests    # HTTP requests
import struct      # Binary data packing
import hashlib     # Hashing algorithms
import json        # JSON parsing
```

---

## 📚 Key Concepts

### 1. TCP Socket Programming

**Basic Client Example:**
```python
import socket

def connect_to_server(host, port):
    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Connect
    sock.connect((host, port))
    
    # Receive data
    data = sock.recv(4096).decode()
    print(f"Received: {data}")
    
    # Send response
    sock.send(b"Hello Server\n")
    
    # Close
    sock.close()

connect_to_server('challenge.root-me.org', 12345)
```

### 2. Encoding/Decoding

**Common Encoding Schemes:**

```python
import base64

# Base64
encoded = base64.b64encode(b'text')
decoded = base64.b64decode(encoded)

# Hex
hex_str = 'text'.encode().hex()
decoded = bytes.fromhex(hex_str).decode()

# URL encoding
import urllib.parse
encoded = urllib.parse.quote('text with spaces')
decoded = urllib.parse.unquote(encoded)
```

### 3. Compression

**Zlib Compression:**
```python
import zlib

# Compress
compressed = zlib.compress(b'data')

# Decompress
decompressed = zlib.decompress(compressed)
```

### 4. HTTP Requests

**Basic HTTP with Requests:**
```python
import requests

# GET request
response = requests.get('http://challenge.root-me.org')

# Custom headers
headers = {'User-Agent': 'Custom Agent'}
response = requests.get(url, headers=headers)

# POST request
data = {'key': 'value'}
response = requests.post(url, data=data)
```

---

## 💡 Challenge Strategies

### For TCP Challenges
1. **Read Challenge Description**
   - Understand what server expects
   - Note the communication protocol
   - Identify data format

2. **Test Connection**
   ```python
   nc challenge.root-me.org PORT
   ```

3. **Write Python Script**
   - Connect to server
   - Receive and parse data
   - Process data as required
   - Send response
   - Handle multiple rounds if needed

4. **Debug Effectively**
   - Print all received data
   - Check data types
   - Handle exceptions
   - Test locally if possible

### For Encoding Challenges
1. Identify the encoding scheme
2. Decode the data
3. Process as required
4. Encode response if needed
5. Send back to server

### For Compression Challenges
1. Identify compression algorithm
2. Decompress received data
3. Process decompressed data
4. Compress response if needed

---

## 🔧 Template Scripts

### Basic TCP Client Template
```python
#!/usr/bin/env python3
import socket

HOST = 'challenge.root-me.org'
PORT = 12345

def main():
    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        # Connect to server
        sock.connect((HOST, PORT))
        print(f"Connected to {HOST}:{PORT}")
        
        # Receive challenge
        data = sock.recv(4096).decode()
        print(f"Received: {data}")
        
        # Process data here
        # ...
        
        # Send response
        response = "your response\n"
        sock.send(response.encode())
        
        # Receive flag
        flag = sock.recv(4096).decode()
        print(f"Flag: {flag}")
        
    finally:
        sock.close()

if __name__ == '__main__':
    main()
```

### HTTP Request Template
```python
#!/usr/bin/env python3
import requests

URL = 'http://challenge.root-me.org/endpoint'

def main():
    # Custom headers
    headers = {
        'User-Agent': 'Custom Agent'
    }
    
    # Make request
    response = requests.get(URL, headers=headers)
    
    # Print response
    print(f"Status: {response.status_code}")
    print(f"Body: {response.text}")

if __name__ == '__main__':
    main()
```

---

## 📖 Resources

### Official Documentation
- [Python Socket Programming](https://docs.python.org/3/howto/sockets.html)
- [Python Requests Library](https://requests.readthedocs.io/)
- [Python zlib Module](https://docs.python.org/3/library/zlib.html)

### Tutorials
- [Real Python - Socket Programming](https://realpython.com/python-sockets/)
- [Socket Programming in Python](https://www.geeksforgeeks.org/socket-programming-python/)

### Tools
- **netcat** - Network utility for testing
- **Wireshark** - Network protocol analyzer
- **Burp Suite** - HTTP proxy and analyzer

---

## 🎓 Practice Tips

1. **Understand Protocols**
   - Learn TCP/IP basics
   - Understand HTTP protocol
   - Study data formats (JSON, XML)

2. **Master Python**
   - Socket programming
   - String manipulation
   - Binary data handling
   - Exception handling

3. **Debug Effectively**
   - Print everything during development
   - Use `hexdump` for binary data
   - Test with netcat first
   - Handle edge cases

4. **Read Documentation**
   - Python standard library docs
   - RFC specifications
   - Challenge hints

---

*Programming challenges build fundamental skills for security automation!*
