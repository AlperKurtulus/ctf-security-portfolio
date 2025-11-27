# Network Challenges

Network analysis and packet capture challenges focusing on protocol analysis, credential extraction, and traffic inspection.

**Challenges Completed:** 3  
**Total Points:** 25

---

## 📝 Available Writeups

### [Ethernet Frame](./ethernet-frame/README.md)
- **Points:** 10
- **Difficulty:** ⭐ Easy
- **Skills:** Hex parsing, HTTP analysis, Base64 decoding
- **Script:** [Ethernet-frame.py](./ethernet-frame/Ethernet-frame.py)

### [FTP Authentication](./ftp-auth/README.md)
- **Points:** 5
- **Difficulty:** ⭐ Easy
- **Skills:** Log analysis, UTF-16 encoding, FTP protocol
- **Script:** [FTP-Auth.py](./ftp-auth/FTP-Auth.py)

### [Telnet Authentication](./telnet-auth/README.md)
- **Points:** 10
- **Difficulty:** ⭐ Easy
- **Skills:** PCAP analysis, TCP reassembly, Scapy
- **Script:** [Telnet-Auth.py](./telnet-auth/Telnet-Auth.py)

---

## 🎯 Learning Objectives

### Network Protocol Analysis
- Understanding TCP/IP stack layers
- Analyzing network captures (PCAP)
- Identifying authentication protocols
- Extracting credentials from traffic

### Data Encoding & Decoding
- Hexadecimal data parsing
- Base64 encoding/decoding
- Character encoding handling (UTF-8, UTF-16)
- Binary to text conversion

### Security Awareness
- Recognizing insecure protocols
- Understanding credential exposure risks
- Learning secure alternatives

---

## 🛠️ Essential Tools & Libraries

### Scapy - Packet Manipulation
```python
from scapy.all import *

# Load PCAP file
packets = rdpcap("capture.pcap")

# Filter and analyze
for pkt in packets:
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        print(pkt[Raw].load)
```

### Common Python Libraries
```python
import base64      # Base64 encoding/decoding
import re          # Regular expressions
import struct      # Binary data handling
from scapy.all import *  # Packet analysis
```

---

## 📊 Protocol Security Comparison

| Protocol | Encryption | Security Level | Recommended Alternative |
|----------|------------|----------------|------------------------|
| HTTP     | ❌ None    | 🔴 Insecure   | HTTPS                  |
| FTP      | ❌ None    | 🔴 Insecure   | SFTP / FTPS            |
| Telnet   | ❌ None    | 🔴 Insecure   | SSH                    |
| SMTP     | ⚠️ Optional| 🟡 Variable   | SMTP + TLS             |

---

## 📁 Directory Structure

```
network/
├── README.md                    # This file
├── ethernet-frame/
│   ├── README.md               # Challenge writeup
│   ├── Ethernet-frame.py       # Solution script
│   └── images/                 # Screenshots
├── ftp-auth/
│   ├── README.md               # Challenge writeup
│   ├── FTP-Auth.py             # Solution script
│   └── images/                 # Screenshots
└── telnet-auth/
    ├── README.md               # Challenge writeup
    ├── Telnet-Auth.py          # Solution script
    └── images/                 # Screenshots
```

---

## 💡 Challenge Strategies

### For Network Challenges
1. **Identify the Protocol** - Check port numbers, headers
2. **Choose the Right Tool** - Wireshark, Scapy, or custom scripts
3. **Look for Credentials** - USER, PASS, Authorization headers
4. **Decode Encoded Data** - Base64, hex, URL encoding
5. **Reassemble Streams** - TCP data may be fragmented

### Common Credential Locations
- HTTP Authorization headers
- FTP USER/PASS commands
- Telnet login prompts
- Cookie values
- POST body data

---

## 🔧 Template Scripts

### PCAP Analysis Template
```python
#!/usr/bin/env python3
from scapy.all import *

def analyze_pcap(filename):
    packets = rdpcap(filename)
    
    for pkt in packets:
        # Check for TCP with data
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            data = pkt[Raw].load
            print(data.decode('utf-8', errors='ignore'))

if __name__ == '__main__':
    analyze_pcap('capture.pcap')
```

### Hex Decoder Template
```python
#!/usr/bin/env python3
import re
import base64

def decode_hex_file(filename):
    with open(filename, 'r') as f:
        raw = f.read()
    
    # Clean hex data
    clean_hex = re.sub(r'[^0-9a-fA-F]', '', raw)
    
    # Convert to bytes
    byte_data = bytes.fromhex(clean_hex)
    
    # Decode to text
    text = byte_data.decode('utf-8', errors='ignore')
    print(text)

if __name__ == '__main__':
    decode_hex_file('data.txt')
```

---

## 📖 Resources

### Official Documentation
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Wireshark User Guide](https://www.wireshark.org/docs/)
- [Python Socket Programming](https://docs.python.org/3/library/socket.html)

### Protocol References
- [RFC 854 - Telnet Protocol](https://tools.ietf.org/html/rfc854)
- [RFC 959 - FTP Protocol](https://tools.ietf.org/html/rfc959)
- [RFC 7617 - HTTP Basic Auth](https://tools.ietf.org/html/rfc7617)

### Tools
- **Wireshark** - GUI packet analyzer
- **tcpdump** - CLI packet capture
- **Scapy** - Python packet manipulation
- **NetworkMiner** - Network forensics

---

## 🎓 Recommended Learning Path

1. **Start with:** Ethernet Frame (basic hex parsing)
2. **Progress to:** FTP Authentication (log analysis)
3. **Then try:** Telnet Authentication (PCAP with Scapy)

---

## 🔗 Navigation

- [← Back to Root-me Overview](../README.md)
- [App-Script Challenges](../app-script/README.md)
- [Programming Challenges](../programming/README.md)

---

*Network analysis skills are fundamental for security professionals!*
