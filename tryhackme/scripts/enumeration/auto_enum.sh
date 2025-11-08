#!/bin/bash

################################################################################
# Automated Enumeration Script
# 
# Description: Comprehensive automated enumeration for penetration testing
# Author: AlperKurtulus (TheJker)
# Usage: ./auto_enum.sh <target_ip>
#
# Features:
#   - Nmap scanning (quick, full, UDP, vulnerability)
#   - Web enumeration (Gobuster, Nikto)
#   - SMB enumeration (enum4linux)
#   - Color-coded output
#   - Organized output directories
#
# Requirements: nmap, gobuster, nikto, enum4linux
################################################################################

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
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║          Automated Enumeration Script v1.0               ║"
    echo "║              By: AlperKurtulus (TheJker)                 ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Print section header
print_section() {
    echo -e "\n${PURPLE}[*]═══════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}[*] $1${NC}"
    echo -e "${PURPLE}[*]═══════════════════════════════════════════════════════${NC}\n"
}

# Print info message
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Print success message
print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

# Print warning message
print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Print error message
print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Check if required tools are installed
check_tools() {
    print_section "Checking Required Tools"
    
    local tools=("nmap" "gobuster" "nikto" "enum4linux")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            print_success "$tool is installed"
        else
            print_warning "$tool is NOT installed"
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        print_warning "Some tools are missing. Proceeding with available tools..."
    fi
}

# Nmap Quick Scan
nmap_quick_scan() {
    print_section "Nmap Quick Scan - Top 1000 Ports"
    print_info "Scanning top 1000 ports on $TARGET..."
    
    nmap -T4 -F -oN "$OUTPUT_DIR/nmap/quick_scan.txt" "$TARGET"
    
    if [ $? -eq 0 ]; then
        print_success "Quick scan completed"
        print_info "Results saved to: $OUTPUT_DIR/nmap/quick_scan.txt"
    else
        print_error "Quick scan failed"
    fi
}

# Nmap Full Port Scan
nmap_full_scan() {
    print_section "Nmap Full Port Scan - All 65535 Ports"
    print_info "Scanning all ports on $TARGET... (This may take a while)"
    
    nmap -p- -T4 -oN "$OUTPUT_DIR/nmap/full_scan.txt" "$TARGET"
    
    if [ $? -eq 0 ]; then
        print_success "Full port scan completed"
        print_info "Results saved to: $OUTPUT_DIR/nmap/full_scan.txt"
        
        # Extract open ports
        OPEN_PORTS=$(grep "^[0-9]" "$OUTPUT_DIR/nmap/full_scan.txt" | grep "open" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
        
        if [ -n "$OPEN_PORTS" ]; then
            print_success "Open ports found: $OPEN_PORTS"
        fi
    else
        print_error "Full port scan failed"
    fi
}

# Nmap Detailed Service Scan
nmap_service_scan() {
    print_section "Nmap Service and Version Detection"
    
    if [ -z "$OPEN_PORTS" ]; then
        print_warning "No open ports from previous scan, using top 1000 ports"
        nmap -sV -sC -T4 -oN "$OUTPUT_DIR/nmap/service_scan.txt" "$TARGET"
    else
        print_info "Running detailed scan on open ports: $OPEN_PORTS"
        nmap -p "$OPEN_PORTS" -sV -sC -T4 -oN "$OUTPUT_DIR/nmap/service_scan.txt" "$TARGET"
    fi
    
    if [ $? -eq 0 ]; then
        print_success "Service scan completed"
        print_info "Results saved to: $OUTPUT_DIR/nmap/service_scan.txt"
    else
        print_error "Service scan failed"
    fi
}

# Nmap UDP Scan (Top 100 Ports)
nmap_udp_scan() {
    print_section "Nmap UDP Scan - Top 100 Ports"
    print_info "Scanning UDP ports on $TARGET..."
    print_warning "UDP scans are slower and require root privileges"
    
    sudo nmap -sU --top-ports 100 -T4 -oN "$OUTPUT_DIR/nmap/udp_scan.txt" "$TARGET" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        print_success "UDP scan completed"
        print_info "Results saved to: $OUTPUT_DIR/nmap/udp_scan.txt"
    else
        print_warning "UDP scan failed (may require sudo privileges)"
    fi
}

# Nmap Vulnerability Scan
nmap_vuln_scan() {
    print_section "Nmap Vulnerability Scan"
    print_info "Running vulnerability scripts on $TARGET..."
    
    nmap --script vuln -oN "$OUTPUT_DIR/nmap/vuln_scan.txt" "$TARGET"
    
    if [ $? -eq 0 ]; then
        print_success "Vulnerability scan completed"
        print_info "Results saved to: $OUTPUT_DIR/nmap/vuln_scan.txt"
    else
        print_error "Vulnerability scan failed"
    fi
}

# Web Enumeration with Gobuster
gobuster_enum() {
    print_section "Web Directory Enumeration with Gobuster"
    
    # Check if wordlist exists
    WORDLIST="/usr/share/wordlists/dirb/common.txt"
    
    if [ ! -f "$WORDLIST" ]; then
        WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    fi
    
    if [ ! -f "$WORDLIST" ]; then
        print_warning "No wordlist found, skipping Gobuster"
        return
    fi
    
    print_info "Enumerating web directories on http://$TARGET..."
    
    if command -v gobuster &> /dev/null; then
        gobuster dir -u "http://$TARGET" -w "$WORDLIST" -o "$OUTPUT_DIR/web/gobuster.txt" -q
        
        if [ $? -eq 0 ]; then
            print_success "Gobuster scan completed"
            print_info "Results saved to: $OUTPUT_DIR/web/gobuster.txt"
        else
            print_warning "Gobuster scan encountered issues"
        fi
    else
        print_warning "Gobuster not installed, skipping"
    fi
}

# Nikto Web Vulnerability Scan
nikto_scan() {
    print_section "Nikto Web Vulnerability Scan"
    print_info "Running Nikto against http://$TARGET..."
    
    if command -v nikto &> /dev/null; then
        nikto -h "http://$TARGET" -o "$OUTPUT_DIR/web/nikto.txt"
        
        if [ $? -eq 0 ]; then
            print_success "Nikto scan completed"
            print_info "Results saved to: $OUTPUT_DIR/web/nikto.txt"
        else
            print_warning "Nikto scan encountered issues"
        fi
    else
        print_warning "Nikto not installed, skipping"
    fi
}

# SMB Enumeration with enum4linux
smb_enum() {
    print_section "SMB Enumeration with enum4linux"
    print_info "Enumerating SMB services on $TARGET..."
    
    if command -v enum4linux &> /dev/null; then
        enum4linux -a "$TARGET" > "$OUTPUT_DIR/smb/enum4linux.txt" 2>&1
        
        if [ $? -eq 0 ]; then
            print_success "SMB enumeration completed"
            print_info "Results saved to: $OUTPUT_DIR/smb/enum4linux.txt"
        else
            print_warning "SMB enumeration encountered issues"
        fi
    else
        print_warning "enum4linux not installed, skipping"
    fi
}

# Generate summary report
generate_summary() {
    print_section "Generating Summary Report"
    
    SUMMARY_FILE="$OUTPUT_DIR/summary.txt"
    
    cat > "$SUMMARY_FILE" << EOF
═══════════════════════════════════════════════════════════
            ENUMERATION SUMMARY REPORT
═══════════════════════════════════════════════════════════

Target: $TARGET
Date: $(date)
Output Directory: $OUTPUT_DIR

═══════════════════════════════════════════════════════════
                    SCAN RESULTS
═══════════════════════════════════════════════════════════

EOF

    # Add open ports info
    if [ -f "$OUTPUT_DIR/nmap/full_scan.txt" ]; then
        echo "Open Ports:" >> "$SUMMARY_FILE"
        grep "^[0-9]" "$OUTPUT_DIR/nmap/full_scan.txt" | grep "open" >> "$SUMMARY_FILE"
        echo "" >> "$SUMMARY_FILE"
    fi
    
    # Add service info
    if [ -f "$OUTPUT_DIR/nmap/service_scan.txt" ]; then
        echo "Services Detected:" >> "$SUMMARY_FILE"
        grep "^[0-9]" "$OUTPUT_DIR/nmap/service_scan.txt" | grep "open" >> "$SUMMARY_FILE"
        echo "" >> "$SUMMARY_FILE"
    fi
    
    echo "═══════════════════════════════════════════════════════════" >> "$SUMMARY_FILE"
    echo "            END OF SUMMARY REPORT" >> "$SUMMARY_FILE"
    echo "═══════════════════════════════════════════════════════════" >> "$SUMMARY_FILE"
    
    print_success "Summary report generated"
    print_info "Summary saved to: $SUMMARY_FILE"
}

# Main function
main() {
    print_banner
    
    # Check if target IP is provided
    if [ $# -eq 0 ]; then
        print_error "No target IP provided"
        echo -e "\n${YELLOW}Usage:${NC} $0 <target_ip>"
        echo -e "${YELLOW}Example:${NC} $0 10.10.10.10"
        exit 1
    fi
    
    TARGET=$1
    
    # Validate IP address format (basic check)
    if [[ ! $TARGET =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        print_error "Invalid IP address format"
        exit 1
    fi
    
    # Create output directory structure
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    OUTPUT_DIR="enum_${TARGET}_${TIMESTAMP}"
    
    mkdir -p "$OUTPUT_DIR"/{nmap,web,smb}
    
    print_success "Created output directory: $OUTPUT_DIR"
    print_info "Starting enumeration of target: $TARGET"
    
    # Check tools
    check_tools
    
    # Run enumeration
    nmap_quick_scan
    nmap_full_scan
    nmap_service_scan
    nmap_udp_scan
    nmap_vuln_scan
    gobuster_enum
    nikto_scan
    smb_enum
    
    # Generate summary
    generate_summary
    
    print_section "Enumeration Complete"
    print_success "All scans completed successfully!"
    print_info "Results saved in: $OUTPUT_DIR"
    print_info "Summary report: $OUTPUT_DIR/summary.txt"
    
    echo -e "\n${GREEN}Happy Hacking! 🎯${NC}\n"
}

# Run main function
main "$@"
