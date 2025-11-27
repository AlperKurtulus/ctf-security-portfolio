#!/usr/bin/python3

import sys


def analyze_trace_log(log_file):
    """
    Reads an IBM iSeries communication trace log (UTF-16) 
    and searches for potential credentials.
    """
    print(f"    Reading file: {log_file}")

    try:
        # The file was identified as UTF-16 LE, so we must specify the encoding.
        with open(log_file, "r", encoding='UTF-16') as f:
            lines = f.readlines()
        print(f"    Successfully read {len(lines)} lines. Analyzing for keywords...\n")
        
        found_something = False

        for i,line in enumerate(lines):
            # Check for common credential keywords (case-insensitive)
            lower_line = line.lower()
            if "pass" in lower_line :
                print(f"[+] Interesting Data found on Line {i+1}:")
                print("-" * 50)
                print(line.strip())
                
                for offset in range(1,50):
                    next_index = i + offset
                    if next_index < len(lines):
                        print (f" -->  {lines[next_index].strip()}")

                print("-" * 50)
                found_something = True
        if not found_something:
            print("[-] No obvious credentials found with current keywords.")
            print("    Recommendation: Try manually reading the file or adding more keywords.")
    except FileNotFoundError:
        print(f"[!] Error: The file '{log_file}' was not found.")
    except UnicodeError:
        print("[!] Encoding Error: Could not decode as UTF-16. Try 'utf-8' or 'latin-1'.")
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")

if __name__ == "__main__":
    target_file = "/home/joker/Desktop/RM-Folders/ch1.pcap"
    analyze_trace_log(target_file)
