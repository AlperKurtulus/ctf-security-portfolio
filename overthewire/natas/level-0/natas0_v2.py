#!/usr/bin/env python3
"""
Natas Level 0 Solver
Author: AlperKurtulus
Date: 2025-11-12
"""

import requests
import re


def solve_natas_level(level, password):
    """
    Solves a Natas level.

    Args:
        level (int): The level number.
        password (str): The password for the current level.

    Returns:
        str: The password for the next level, or None if not found.
    """

    url = f"http://natas{level}.natas.labs.overthewire.org"
    username = f"natas{level}"

    print(f"[*] Solving Level {level}...")
    print(f"[*] URL: {url}")

    try:
        # Send the HTTP request
        response = requests.get(url, auth=(username, password), timeout=10)

        # Check the status code
        if response.status_code != 200:
            print(f"[-] Error: Status code {response.status_code}")
            return None

        # Find the password
        # The password for natas0 is in an HTML comment:
        # <!--The password for natas1 is ... -->
        match = re.search(r"password for natas(\d+) is\s+(\w+)", response.text)

        if match:
            next_password = match.group(2)
            print(f"[+] Next password: {next_password}")
            return next_password
        else:
            print("[-] Password not found in response")
            # Optional: print response text for debugging
            # print(response.text)
            return None

    except requests.RequestException as e:
        print(f"[-] Network error: {e}")
        return None


# Main program
if __name__ == "__main__":
    current_level = 0
    current_password = "natas0"

    next_password = solve_natas_level(current_level, current_password)

    if next_password:
        # Save to file
        with open(f"natas{current_level + 1}_password.txt", "w") as f:
            f.write(next_password)
        print("[+] Password saved to file!")
