# Natas Level 0 → Level 1

**Difficulty:** ⭐ Very Easy  
**Date Completed:** 2025-11-12  
**Author:** AlperKurtulus

---

## Level Goal

Find the password for the next level hidden somewhere on the page.

**Access Information:**
- URL: http://natas0.natas.labs.overthewire.org
- Username: `natas0`
- Password: `natas0`

---

## Solution

### Step 1: Access the Challenge Page

Navigate to http://natas0.natas.labs.overthewire.org and log in with the credentials provided above.

### Step 2: View the Page Source

The page displays: *"You can find the password for the next level on this page."*

Right-click on the page and select **"View Page Source"** (or use `Ctrl+U` / `Cmd+U`).

### Step 3: Find the Password

In the HTML source code, you'll find an HTML comment containing the password:

```html
<!--The password for natas1 is 0nzCigAq7t2iALyvU9xcHlYN4MlkIwlq -->
```

---

## Automated Solution

A Python script is provided to automate this challenge:

📄 **Script:** [`natas0_v2.py`](./natas0_v2.py)

```bash
# Run from this directory
python3 natas0_v2.py
```

The script sends an HTTP request with Basic Auth, parses the HTML for the password pattern, and saves it to `natas1_password.txt`.

---

## What I Learned

### Key Takeaways
- **HTML comments are not hidden from users** — they are visible to anyone who views the page source.
- **View Page Source** is a fundamental technique in web security assessments.
- Sensitive information should never be stored in HTML comments or client-side code.

### Security Implications
- Developers sometimes leave debugging information, credentials, or internal notes in HTML comments.
- Always review page source during security assessments — it's often the first place to check.
- This vulnerability falls under **Information Disclosure** in security terminology.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Web Browser | Access challenge and view page source |
| Python + Requests | Automated HTTP requests with Basic Auth |
| Regular Expressions | Parse HTML to extract password |

---

## Screenshots

> **Note:** Screenshots will be added by the user.

| Screenshot | Description |
|------------|-------------|
| `images/natas0-homepage.png` | Natas0 homepage showing the hint |
| `images/natas0-source.png` | Page source showing the password in HTML comment |

---

## Navigation

[← Previous: Overview](../README.md) | [Overview](../README.md) | [Next: Level 1 →](../level-1/README.md)
