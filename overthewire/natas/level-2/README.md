# Natas Level 2 → Level 3

**Difficulty:** ⭐ Easy  
**Date Completed:** 2025-11-12  
**Author:** AlperKurtulus

---

## Level Goal

There is nothing on this page... or is there? Find the password for the next level.

**Access Information:**
- URL: http://natas2.natas.labs.overthewire.org
- Username: `natas2`
- Password: `TguMNxKo1DSa1tujBLuZJnDUlCcUAPlI`

---

## Solution

### Step 1: Access the Challenge Page

Navigate to http://natas2.natas.labs.overthewire.org and log in with the credentials above.

### Step 2: Analyze the Page Source

The page displays: *"There is nothing on this page"*

View the source code (`Ctrl+U`) and notice:

```html
<img src="files/pixel.png">
```

There's a reference to a `/files/` directory!

### Step 3: Explore the Directory

Navigate to http://natas2.natas.labs.overthewire.org/files/

The directory listing is enabled, revealing:
- `pixel.png` — a tiny 1x1 pixel image
- `users.txt` — an interesting file!

### Step 4: Access users.txt

Navigate to http://natas2.natas.labs.overthewire.org/files/users.txt

The file contains credentials:

```
# username:password
alice:BYNdCesZqW
bob:jw2ueICLvT
charlie:G5vCxkVV3m
natas3:3gqisGdR0pjm6tpkDKdIWO2hSvchLeYH
eve:zo4mJWyNj2
mallory:9urtcpzBmH
```

The password for natas3 is: `3gqisGdR0pjm6tpkDKdIWO2hSvchLeYH`

---

## Automated Solution

A Python script is provided to automate this challenge:

📄 **Script:** [`natas2_v1.py`](./natas2_v1.py)

```bash
# Run from this directory
python3 natas2_v1.py
```

The script accesses the `/files/` directory, detects `users.txt`, parses it, and extracts the natas3 password.

---

## What I Learned

### Key Takeaways
- **Directory listing exposure** is a common misconfiguration that reveals file structure.
- **Path analysis in source code** — image sources, script paths, and links can reveal hidden directories.
- Sensitive files like `users.txt` should never be in publicly accessible directories.

### Security Implications
- **Disable directory listings** in production web servers (Apache: `Options -Indexes`).
- **Never store credentials in plain text** files, especially in web-accessible directories.
- Always check for exposed paths by analyzing HTML source for references to directories.
- This vulnerability is classified as **Sensitive Data Exposure** (OWASP Top 10).

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Web Browser | Navigate directories and view source |
| Directory Enumeration | Manual exploration of exposed paths |
| Python + Requests | Automated file fetching and parsing |

---

## Screenshots

> **Note:** Screenshots will be added by the user.

| Screenshot | Description |
|------------|-------------|
| `images/natas2-files-directory.png` | Directory listing showing files |
| `images/natas2-users-txt.png` | Contents of users.txt with credentials |

---

## Navigation

[← Previous: Level 1](../level-1/README.md) | [Overview](../README.md) | [Next: Level 3 →](../level-3/README.md)
