# Back to School - Root-Me Write-Up

## Challenge Information
- **Platform:** Root-Me
- **Category:** Programming
- **Difficulty:** Easy
- **Points:** 5
- **Date Solved:** 2025-11-09

## Overview
This challenge tests your ability to solve mathematical problems programmatically within a strict time limit (2 seconds). The server sends a mathematical question that requires calculating the square root of a number and multiplying it by another number.

## Challenge Description
The challenge connects to a socket server that:
1. Sends a mathematical question
2. Expects the answer within 2 seconds
3. Returns the flag if the answer is correct

## Reconnaissance

### Initial Analysis
```bash
# Challenge endpoint
Host: challenge01.root-me.org
Port: 52002
Protocol: TCP Socket
```

The server sends questions in the format:
```
"What is the square root of [number1] multiplied by [number2]?"
```

### Time Constraint
The critical aspect of this challenge is the **2-second time limit**. Any unnecessary operations (like printing during calculation) can cause timeout failures.

## Solution Approach

### Strategy
1. Establish socket connection
2. Receive the question
3. Parse numbers using regex
4. Calculate result: `sqrt(number1) * number2`
5. Format answer to 2 decimal places
6. Send answer immediately
7. Receive flag

### Key Optimization
**Avoid printing or any I/O operations during the calculation phase** to stay within the 2-second window.

## Exploitation

### Python Script
See `back_to_school.py` in this directory.

### Key Code Sections

#### Connection and Data Retrieval
```python
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
question = s.recv(1024).decode('utf-8')
```

#### Number Extraction and Calculation
```python
numbers = re.findall(r'\d+', question)
number1 = int(numbers[1])
number2 = int(numbers[2])
result = math.sqrt(number1) * number2
```

#### Answer Formatting
```python
answer_string = f"{result:.2f}"
payload = f"{answer_string}\n".encode('utf-8')
s.sendall(payload)
```

### Execution
```bash
python3 back_to_school.py
```

### Output Example
```
------------------------------
[<] Received Question:
What is the square root of 144 multiplied by 5?
------------------------------
[!] Found Numbers: 144 and 5
[!] Calculated Result: 60.0
[>] Sent Answer: 60.00
------------------------------
[+] SUCCESS! Received Flag:
[FLAG_CONTENT]
------------------------------
```

## Technical Details

### Regex Pattern
```python
numbers = re.findall(r'\d+', question)
```
Extracts all numeric values from the question string.

### Mathematical Operation
```python
result = math.sqrt(number1) * number2
```
Uses Python's `math.sqrt()` for accurate square root calculation.

### Answer Formatting
```python
answer_string = f"{result:.2f}"
```
Formats the result to exactly 2 decimal places as required by the server.

## Lessons Learned
1. **Time Optimization:** In time-constrained challenges, defer all non-critical operations (logging, printing) until after solving
2. **Socket Programming:** Understanding TCP socket communication in Python
3. **Regex Parsing:** Efficiently extracting numeric data from formatted text
4. **Format Precision:** Meeting exact output format requirements (2 decimal places)
5. **Error Handling:** Implementing proper exception handling and resource cleanup

## Common Pitfalls
- ❌ Printing during calculation phase (causes timeout)
- ❌ Incorrect number formatting (wrong decimal places)
- ❌ Not sending newline character with the answer
- ❌ Not closing socket connection properly

## Tools Used
- Python 3
- `socket` module for network communication
- `re` module for regex parsing
- `math` module for mathematical operations

## References
- [Python Socket Programming](https://docs.python.org/3/library/socket.html)
- [Python Math Module](https://docs.python.org/3/library/math.html)
- [Regular Expressions in Python](https://docs.python.org/3/library/re.html)

## Tags
`#programming` `#python` `#socket` `#math` `#timing` `#rootme`