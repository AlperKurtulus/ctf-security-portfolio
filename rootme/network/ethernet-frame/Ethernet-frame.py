#!/usr/bin/env python3

import re
import base64


def analyze_eth(file_name):
    print(f"    Reading file : {file_name}")

    try:
        with open(file_name, "r") as f:
            raw_data = f.read() 
            clean_hex = re.sub(r'[^0-9a-fA-F]', '', raw_data)

        byte_data = bytes.fromhex(clean_hex)
        decoded_text = byte_data.decode('utf-8', errors ='ignore')

        print("\n--- START OF DECODED TEXT ---")
        print(decoded_text) 
        print("--- END OF DECODED TEXT ---\n")

        target_header = "Authorization: Basic"
        
        if target_header in decoded_text:
            encoded_part = decoded_text.split(f"{target_header}")[1].split("\r\n")[0]
            decoded_cred = base64.b64decode(encoded_part).decode("utf-8")
            print("-" * 40)
            print(f"[+] SECRET FOUND: {decoded_cred}")
            print("-" * 40)
        else:
            print(" No authentication headers found in the file.")
    
    except FileNotFoundError:
        print(f"[!] Error: The file '{filename}' was not found.")
    except Exception as e:
        print(f"[!] An error occurred: {e}")

if __name__ == "__main__":
    target_file = "/home/joker/Desktop/RM-Folders/ch12.txt"
    analyze_eth(target_file)
