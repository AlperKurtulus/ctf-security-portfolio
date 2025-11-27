#!/usr/bin/env python3
"""
Natas Level 1 Solver
Author: AlperKurtulus
Date: 2025-11-12
"""

import requests
import re


def solve_natas1():
    url = "http://natas1.natas.labs.overthewire.org"
    username = "natas1"

    # Read the password for natas1 from a file
    with open("natas1_password.txt", "r") as f:
        password = f.read().strip()

    print("[*] Solving Natas1...")

    response = requests.get(url, auth=(username, password), timeout=10)

    match = re.search(r"password for natas2 is\s+(\w+)", response.text)

    if match:
        next_password = match.group(1)
        print(f"[+] Next password: {next_password}")

        with open("natas2_password.txt", "w") as f:
            f.write(next_password)

        return next_password

    return None


if __name__ == "__main__":
    solve_natas1()
