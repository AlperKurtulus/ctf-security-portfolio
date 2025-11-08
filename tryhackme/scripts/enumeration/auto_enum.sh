#!/bin/bash

#############################################
# Automated Enumeration Script
# Author: Alper Kurtulus (TheJker)
# Description: Comprehensive reconnaissance and enumeration automation
# Usage: ./auto_enum.sh <target_ip> [output_dir]
#############################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════╗"
    echo "║        Automated Enumeration Script v1.0         ║"
    echo "║              Author: TheJker                      ║"
    echo "╚═══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Usage information
usage() {
    echo -e "${YELLOW}Usage: $0 <target_ip> [output_dir]${NC}"
    echo ""
    echo "Example: $0 10.10.10.10 scan_results"
    echo ""
    exit 1
}

# Check if target IP is provided
if [ -z "$1" ]; then
    print_banner
    usage
fi

TARGET_IP=$1
OUTPUT_DIR=${2:-"enum_${TARGET_IP}_$(date +%Y%m%d_%H%M%S)"}

# Create output directory
mkdir -p "$OUTPUT_DIR"/{nmap,web,smb,misc}

print_banner

echo -e "${GREEN}[+] Target: ${TARGET_IP}${NC}"
echo -e "${GREEN}[+] Output Directory: ${OUTPUT_DIR}${NC}"
echo -e "${GREEN}[+] Start Time: $(date)${NC}"
echo ""

#############################################
# NMAP SCANNING
#############################################

echo -e "${BLUE}[*] Starting Nmap Scans...${NC}"

# Quick scan for open ports
echo -e "${CYAN}[>] Running quick port scan...${NC}"
nmap -T4 -p- --min-rate=1000 "$TARGET_IP" -oN "$OUTPUT_DIR/nmap/quick_scan.txt" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓] Quick scan completed${NC}"
    # Extract open ports
    OPEN_PORTS=$(grep -oP '\d+/open' "$OUTPUT_DIR/nmap/quick_scan.txt" | cut -d'/' -f1 | paste -sd,)
    echo -e "${GREEN}    Open ports: ${OPEN_PORTS}${NC}"
else
    echo -e "${RED}[✗] Quick scan failed${NC}"
    OPEN_PORTS=""
fi

# Detailed scan on open ports
if [ ! -z "$OPEN_PORTS" ]; then
    echo -e "${CYAN}[>] Running detailed scan on open ports...${NC}"
    nmap -sC -sV -p "$OPEN_PORTS" "$TARGET_IP" -oN "$OUTPUT_DIR/nmap/detailed_scan.txt" -oX "$OUTPUT_DIR/nmap/detailed_scan.xml" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] Detailed scan completed${NC}"
    else
        echo -e "${RED}[✗] Detailed scan failed${NC}"
    fi
fi

# UDP scan (top 100 ports)
echo -e "${CYAN}[>] Running UDP scan (top 100 ports)...${NC}"
sudo nmap -sU --top-ports 100 "$TARGET_IP" -oN "$OUTPUT_DIR/nmap/udp_scan.txt" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓] UDP scan completed${NC}"
else
    echo -e "${YELLOW}[!] UDP scan failed or requires sudo${NC}"
fi

# Vulnerability scan
echo -e "${CYAN}[>] Running vulnerability scan...${NC}"
nmap --script vuln -p "$OPEN_PORTS" "$TARGET_IP" -oN "$OUTPUT_DIR/nmap/vuln_scan.txt" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓] Vulnerability scan completed${NC}"
else
    echo -e "${RED}[✗] Vulnerability scan failed${NC}"
fi

echo ""

#############################################
# WEB ENUMERATION
#############################################

# Check for web services
WEB_PORTS=$(echo "$OPEN_PORTS" | grep -oE '(80|443|8000|8080|8443)' | head -1)

if [ ! -z "$WEB_PORTS" ]; then
    echo -e "${BLUE}[*] Web service detected on port ${WEB_PORTS}${NC}"
    
    # Determine protocol
    if [[ "$WEB_PORTS" == "443" || "$WEB_PORTS" == "8443" ]]; then
        PROTOCOL="https"
    else
        PROTOCOL="http"
    fi
    
    WEB_URL="${PROTOCOL}://${TARGET_IP}:${WEB_PORTS}"
    
    # Gobuster directory enumeration
    if command -v gobuster &> /dev/null; then
        echo -e "${CYAN}[>] Running Gobuster directory enumeration...${NC}"
        gobuster dir -u "$WEB_URL" -w /usr/share/wordlists/dirb/common.txt -o "$OUTPUT_DIR/web/gobuster.txt" -q 2>/dev/null
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[✓] Gobuster scan completed${NC}"
        else
            echo -e "${YELLOW}[!] Gobuster scan failed (check wordlist path)${NC}"
        fi
    else
        echo -e "${YELLOW}[!] Gobuster not installed, skipping${NC}"
    fi
    
    # Nikto web vulnerability scan
    if command -v nikto &> /dev/null; then
        echo -e "${CYAN}[>] Running Nikto web vulnerability scan...${NC}"
        nikto -h "$WEB_URL" -output "$OUTPUT_DIR/web/nikto.txt" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[✓] Nikto scan completed${NC}"
        else
            echo -e "${RED}[✗] Nikto scan failed${NC}"
        fi
    else
        echo -e "${YELLOW}[!] Nikto not installed, skipping${NC}"
    fi
    
    # WhatWeb
    if command -v whatweb &> /dev/null; then
        echo -e "${CYAN}[>] Running WhatWeb...${NC}"
        whatweb "$WEB_URL" > "$OUTPUT_DIR/web/whatweb.txt" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[✓] WhatWeb completed${NC}"
        else
            echo -e "${RED}[✗] WhatWeb failed${NC}"
        fi
    else
        echo -e "${YELLOW}[!] WhatWeb not installed, skipping${NC}"
    fi
    
    echo ""
fi

#############################################
# SMB ENUMERATION
#############################################

# Check for SMB service
SMB_PORTS=$(echo "$OPEN_PORTS" | grep -oE '(139|445)' | head -1)

if [ ! -z "$SMB_PORTS" ]; then
    echo -e "${BLUE}[*] SMB service detected on port ${SMB_PORTS}${NC}"
    
    # enum4linux
    if command -v enum4linux &> /dev/null; then
        echo -e "${CYAN}[>] Running enum4linux...${NC}"
        enum4linux -a "$TARGET_IP" > "$OUTPUT_DIR/smb/enum4linux.txt" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[✓] enum4linux completed${NC}"
        else
            echo -e "${RED}[✗] enum4linux failed${NC}"
        fi
    else
        echo -e "${YELLOW}[!] enum4linux not installed, skipping${NC}"
    fi
    
    # smbclient listing
    if command -v smbclient &> /dev/null; then
        echo -e "${CYAN}[>] Running smbclient share enumeration...${NC}"
        smbclient -L "//$TARGET_IP" -N > "$OUTPUT_DIR/smb/shares.txt" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[✓] SMB share enumeration completed${NC}"
        else
            echo -e "${YELLOW}[!] SMB share enumeration failed${NC}"
        fi
    else
        echo -e "${YELLOW}[!] smbclient not installed, skipping${NC}"
    fi
    
    echo ""
fi

#############################################
# ADDITIONAL ENUMERATION
#############################################

echo -e "${BLUE}[*] Running Additional Enumeration...${NC}"

# DNS enumeration (if port 53 is open)
if [[ "$OPEN_PORTS" == *"53"* ]]; then
    echo -e "${CYAN}[>] DNS service detected, running dig...${NC}"
    dig @"$TARGET_IP" ANY example.com > "$OUTPUT_DIR/misc/dns_query.txt" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] DNS query completed${NC}"
    fi
fi

# SNMP enumeration (if port 161 is open)
if [[ "$OPEN_PORTS" == *"161"* ]]; then
    if command -v snmpwalk &> /dev/null; then
        echo -e "${CYAN}[>] SNMP service detected, running snmpwalk...${NC}"
        snmpwalk -v2c -c public "$TARGET_IP" > "$OUTPUT_DIR/misc/snmpwalk.txt" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[✓] SNMP enumeration completed${NC}"
        fi
    fi
fi

echo ""

#############################################
# SUMMARY
#############################################

echo -e "${GREEN}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              Enumeration Complete!               ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}[+] Results saved to: ${OUTPUT_DIR}${NC}"
echo -e "${CYAN}[+] End Time: $(date)${NC}"
echo ""
echo -e "${YELLOW}[!] Next Steps:${NC}"
echo -e "    1. Review nmap scan results in ${OUTPUT_DIR}/nmap/"
echo -e "    2. Check web enumeration in ${OUTPUT_DIR}/web/"
echo -e "    3. Analyze SMB findings in ${OUTPUT_DIR}/smb/"
echo -e "    4. Identify potential vulnerabilities and attack vectors"
echo ""
echo -e "${RED}[!] Remember: Only test systems you have permission to test!${NC}"
echo ""
