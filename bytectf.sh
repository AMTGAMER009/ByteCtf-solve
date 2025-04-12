#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Version
VERSION="1.0"

# Banner
banner() {
    clear
    echo -e "${RED}██╗  ██╗ █████╗  ██████╗██╗  ██╗ ██████╗████████╗███████╗"
    echo -e "██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔════╝"
    echo -e "███████║███████║██║     █████╔╝ ██║        ██║   █████╗  "
    echo -e "██╔══██║██╔══██║██║     ██╔═██╗ ██║        ██║   ██╔══╝  "
    echo -e "██║  ██║██║  ██║╚██████╗██║  ██╗╚██████╗   ██║   ███████╗"
    echo -e "╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚══════╝${NC}"
    echo -e "${YELLOW}=======================================================${NC}"
    echo -e "${GREEN}         C T F   H A C K I N G   T O O L K I T         ${NC}"
    echo -e "${BLUE}                  Version: $VERSION                     ${NC}"
    echo -e "${YELLOW}=======================================================${NC}"
    echo -e "${PURPLE}           The Ultimate Bug Hunting Toolkit           ${NC}"
    echo -e "${YELLOW}=======================================================${NC}"
    echo -e "${BLUE}                 Author: Bytehackedits                 ${NC}"
    echo -e "${YELLOW}=======================================================${NC}"
    echo ""
}

# Check dependencies
check_dependencies() {
    local tools=("nmap" "nikto" "dirb" "hydra" "sqlmap" "whois" "dig" "netcat" "curl" "wget" "john" "theharvester" "jq")
    local missing=()
    
    echo -e "${CYAN}[*] Checking required tools...${NC}"
    echo -e "${YELLOW}-------------------------------------------------------${NC}"
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
            echo -e "${RED}[-] $tool is not installed${NC}"
        else
            echo -e "${GREEN}[+] $tool is installed (${PURPLE}$($tool --version 2>&1 | head -n 1)${NC})"
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}[!] The following tools are missing:${NC}"
        for item in "${missing[@]}"; do
            echo -e "${RED}$item${NC}"
        done
        echo -e "\n${YELLOW}Would you like to install missing tools? (y/n)${NC}"
        read -p "> " install_choice
        if [[ "$install_choice" =~ ^[Yy]$ ]]; then
            install_missing_tools "${missing[@]}"
        else
            echo -e "\n${YELLOW}Some features may not work without these tools.${NC}"
        fi
    else
        echo -e "\n${GREEN}[+] All dependencies are installed!${NC}"
    fi
    
    read -p "Press enter to continue..."
}

install_missing_tools() {
    local missing_tools=("$@")
    echo -e "\n${GREEN}[+] Installing missing tools...${NC}"
    
    if [[ -f /etc/debian_version ]]; then
        sudo apt update
        for tool in "${missing_tools[@]}"; do
            sudo apt install -y "$tool"
        done
    elif [[ -f /etc/redhat-release ]]; then
        sudo yum update
        for tool in "${missing_tools[@]}"; do
            sudo yum install -y "$tool"
        done
    else
        echo -e "${RED}[-] Unsupported OS for automatic installation${NC}"
        echo -e "${YELLOW}Please install the following packages manually:${NC}"
        for tool in "${missing_tools[@]}"; do
            echo -e "$tool"
        done
    fi
}

# Network Scanner
network_scan() {
    while true; do
        banner
        echo -e "${CYAN}[*] Network Scanning${NC}"
        echo -e "${YELLOW}-------------------------------------------------------${NC}"
        echo -e "1. Quick Scan (Top 100 ports)"
        echo -e "2. Full Scan (All ports)"
        echo -e "3. Service Version Detection"
        echo -e "4. OS Detection"
        echo -e "5. Custom Scan"
        echo -e "6. Vulnerability Scan"
        echo -e "7. Network Discovery (Ping sweep)"
        echo -e "8. Firewall/IDS Evasion Scan"
        echo -e "9. Back to Main Menu${NC}"
        echo -e "${YELLOW}-------------------------------------------------------${NC}"
        
        read -p "Select an option: " choice
        
        case $choice in
            1)
                read -p "Enter target IP or hostname: " target
                echo -e "\n${GREEN}[+] Starting quick scan...${NC}"
                nmap -T4 -F --open "$target"
                ;;
            2)
                read -p "Enter target IP or hostname: " target
                echo -e "\n${GREEN}[+] Starting full scan...${NC}"
                nmap -T4 -p- -v --open "$target"
                ;;
            3)
                read -p "Enter target IP or hostname: " target
                echo -e "\n${GREEN}[+] Starting service version detection...${NC}"
                nmap -T4 -sV --version-intensity 5 "$target"
                ;;
            4)
                read -p "Enter target IP or hostname: " target
                echo -e "\n${GREEN}[+] Starting OS detection...${NC}"
                nmap -T4 -O --osscan-guess "$target"
                ;;
            5)
                read -p "Enter target IP or hostname: " target
                read -p "Enter custom nmap flags: " flags
                echo -e "\n${GREEN}[+] Starting custom scan with flags: $flags${NC}"
                nmap $flags "$target"
                ;;
            6)
                read -p "Enter target IP or hostname: " target
                echo -e "\n${GREEN}[+] Starting vulnerability scan...${NC}"
                nmap -T4 --script vuln --script-args=unsafe=1 "$target"
                ;;
            7)
                read -p "Enter network range (e.g., 192.168.1.0/24): " network
                echo -e "\n${GREEN}[+] Starting network discovery...${NC}"
                nmap -sn "$network"
                ;;
            8)
                read -p "Enter target IP or hostname: " target
                echo -e "\n${GREEN}[+] Starting evasion scan...${NC}"
                nmap -T2 -f --data-length 24 --mtu 8 --badsum "$target"
                ;;
            9)
                return
                ;;
            *)
                echo -e "${RED}[-] Invalid option${NC}"
                sleep 1
                ;;
        esac
        
        echo -e "\n${YELLOW}[*] Scan completed for $target${NC}"
        read -p "Press enter to continue..."
    done
}

# Web Scanner
web_scan() {
    while true; do
        banner
        echo -e "${CYAN}[*] Web Scanning${NC}"
        echo -e "${YELLOW}-------------------------------------------------------${NC}"
        echo -e "1. Nikto Vulnerability Scan"
        echo -e "2. DIRB Directory Brute-force"
        echo -e "3. SQL Injection Test"
        echo -e "4. Check HTTP Headers"
        echo -e "5. XSS Scan"
        echo -e "6. LFI/RFI Test"
        echo -e "7. CMS Detection"
        echo -e "8. Web Server Fingerprinting"
        echo -e "9. Back to Main Menu${NC}"
        echo -e "${YELLOW}-------------------------------------------------------${NC}"
        
        read -p "Select an option: " choice
        
        case $choice in
            1)
                read -p "Enter target URL (e.g., http://example.com): " target
                echo -e "\n${GREEN}[+] Starting Nikto scan...${NC}"
                nikto -h "$target" -Display 1234EPV
                ;;
            2)
                read -p "Enter target URL (e.g., http://example.com): " target
                echo -e "\n${GREEN}[+] Starting DIRB scan...${NC}"
                dirb "$target" /usr/share/dirb/wordlists/common.txt -r -z 100
                ;;
            3)
                read -p "Enter target URL with parameter (e.g., http://example.com/page?id=1): " target
                echo -e "\n${GREEN}[+] Starting SQLMap scan...${NC}"
                sqlmap -u "$target" --batch --crawl=2 --level=3 --risk=3
                ;;
            4)
                read -p "Enter target URL (e.g., http://example.com): " target
                echo -e "\n${GREEN}[+] Checking HTTP headers...${NC}"
                curl -I -L --connect-timeout 5 "$target"
                echo -e "\n${CYAN}[*] Security Headers Check:${NC}"
                curl -sI "$target" | grep -E 'X-XSS-Protection|X-Content-Type-Options|X-Frame-Options|Content-Security-Policy|Strict-Transport-Security'
                ;;
            5)
                read -p "Enter target URL (e.g., http://example.com): " target
                echo -e "\n${GREEN}[+] Starting XSS scan...${NC}"
                sqlmap -u "$target" --batch --crawl=2 --level=3 --risk=3 --technique=X
                echo -e "\n${CYAN}[*] Running XSStrike...${NC}"
                if command -v xsstrike &> /dev/null; then
                    xsstrike -u "$target"
                else
                    echo -e "${YELLOW}[!] XSStrike not installed. Consider installing for better XSS detection.${NC}"
                fi
                ;;
            6)
                read -p "Enter target URL with parameter (e.g., http://example.com/page?file=index): " target
                echo -e "\n${GREEN}[+] Testing for LFI/RFI vulnerabilities...${NC}"
                sqlmap -u "$target" --batch --crawl=2 --level=3 --risk=3 --technique=LFI
                ;;
            7)
                read -p "Enter target URL (e.g., http://example.com): " target
                echo -e "\n${GREEN}[+] Detecting CMS...${NC}"
                whatweb -a 3 "$target"
                ;;
            8)
                read -p "Enter target URL or IP: " target
                echo -e "\n${GREEN}[+] Fingerprinting web server...${NC}"
                httprint -h "$target" -s /usr/share/httprint/signatures.txt
                ;;
            9)
                return
                ;;
            *)
                echo -e "${RED}[-] Invalid option${NC}"
                sleep 1
                ;;
        esac
        
        echo -e "\n${YELLOW}[*] Web scan completed for $target${NC}"
        read -p "Press enter to continue..."
    done
}

# Password Cracking
password_crack() {
    while true; do
        banner
        echo -e "${CYAN}[*] Password Cracking${NC}"
        echo -e "${YELLOW}-------------------------------------------------------${NC}"
        echo -e "1. Hydra SSH Brute-force"
        echo -e "2. Hydra FTP Brute-force"
        echo -e "3. Hydra HTTP Form Brute-force"
        echo -e "4. John the Ripper Hash Cracking"
        echo -e "5. Hashcat Cracking (GPU)"
        echo -e "6. Wordlist Generator"
        echo -e "7. Back to Main Menu${NC}"
        echo -e "${YELLOW}-------------------------------------------------------${NC}"
        
        read -p "Select an option: " choice
        
        case $choice in
            1)
                read -p "Enter target IP: " target
                read -p "Enter username (or file for multiple users): " user
                read -p "Enter password list: " passlist
                echo -e "\n${GREEN}[+] Starting SSH brute-force...${NC}"
                hydra -l "$user" -P "$passlist" "$target" ssh -t 4 -V
                ;;
            2)
                read -p "Enter target IP: " target
                read -p "Enter username (or file for multiple users): " user
                read -p "Enter password list: " passlist
                echo -e "\n${GREEN}[+] Starting FTP brute-force...${NC}"
                hydra -l "$user" -P "$passlist" "$target" ftp -V
                ;;
            3)
                read -p "Enter target URL: " target
                read -p "Enter username field (e.g., user): " user_field
                read -p "Enter password field (e.g., pass): " pass_field
                read -p "Enter failure string (e.g., Login failed): " fail_string
                read -p "Enter username (or file): " user
                read -p "Enter password list: " passlist
                echo -e "\n${GREEN}[+] Starting HTTP form brute-force...${NC}"
                hydra "$target" http-form-post "/path/to/login.php:$user_field=^USER^&$pass_field=^PASS^:$fail_string" -l "$user" -P "$passlist" -V
                ;;
            4)
                read -p "Enter hash file path: " hash_file
                read -p "Enter wordlist path: " wordlist
                echo -e "\n${GREEN}[+] Starting hash cracking with John...${NC}"
                john --format=auto --wordlist="$wordlist" "$hash_file"
                echo -e "\n${CYAN}[*] Showing cracked passwords:${NC}"
                john --show "$hash_file"
                ;;
            5)
                if ! command -v hashcat &> /dev/null; then
                    echo -e "${RED}[-] Hashcat not installed!${NC}"
                    read -p "Press enter to continue..."
                    continue
                fi
                echo -e "\n${CYAN}Available hash modes:${NC}"
                echo -e "0  | MD5"
                echo -e "100 | SHA1"
                echo -e "1400 | SHA256"
                echo -e "1800 | SHA512"
                echo -e "1000 | NTLM"
                echo -e "2500 | WPA/WPA2"
                read -p "Enter hash mode: " hash_mode
                read -p "Enter hash file path: " hash_file
                read -p "Enter wordlist path: " wordlist
                echo -e "\n${GREEN}[+] Starting Hashcat cracking...${NC}"
                hashcat -m "$hash_mode" -a 0 "$hash_file" "$wordlist" --force -O
                echo -e "\n${CYAN}[*] Showing results:${NC}"
                hashcat -m "$hash_mode" "$hash_file" --show
                ;;
            6)
                read -p "Enter base word: " base_word
                read -p "Enter output file: " out_file
                echo -e "\n${GREEN}[+] Generating wordlist variations...${NC}"
                crunch ${#base_word} ${#base_word} -t "$base_word"%% -o "$out_file"
                echo -e "${CYAN}[*] Wordlist generated at $out_file${NC}"
                ;;
            7)
                return
                ;;
            *)
                echo -e "${RED}[-] Invalid option${NC}"
                sleep 1
                ;;
        esac
        
        read -p "Press enter to continue..."
    done
}

# Reconnaissance
recon() {
    while true; do
        banner
        echo -e "${CYAN}[*] Reconnaissance${NC}"
        echo -e "${YELLOW}-------------------------------------------------------${NC}"
        echo -e "1. WHOIS Lookup"
        echo -e "2. DNS Lookup"
        echo -e "3. Subdomain Enumeration"
        echo -e "4. Port Check"
        echo -e "5. Email Harvesting"
        echo -e "6. Metadata Extraction"
        echo -e "7. Social Media Recon"
        echo -e "8. Back to Main Menu${NC}"
        echo -e "${YELLOW}-------------------------------------------------------${NC}"
        
        read -p "Select an option: " choice
        
        case $choice in
            1)
                read -p "Enter domain or IP: " target
                echo -e "\n${GREEN}[+] Performing WHOIS lookup...${NC}"
                whois "$target" | grep -Ei "Registrant|Admin|Tech|Name Server|Organization"
                ;;
            2)
                read -p "Enter domain: " target
                echo -e "\n${GREEN}[+] Performing DNS lookup...${NC}"
                echo -e "\n${CYAN}[*] A Records:${NC}"
                dig "$target" A +short
                echo -e "\n${CYAN}[*] MX Records:${NC}"
                dig "$target" MX +short
                echo -e "\n${CYAN}[*] TXT Records:${NC}"
                dig "$target" TXT +short
                echo -e "\n${CYAN}[*] NS Records:${NC}"
                dig "$target" NS +short
                ;;
            3)
                read -p "Enter domain: " target
                echo -e "\n${GREEN}[+] Enumerating subdomains...${NC}"
                echo -e "\n${CYAN}[*] Using crt.sh:${NC}"
                curl -s "https://crt.sh/?q=%25.$target&output=json" | jq -r '.[].name_value' | sort -u
                echo -e "\n${CYAN}[*] Using sublist3r:${NC}"
                if command -v sublist3r &> /dev/null; then
                    sublist3r -d "$target"
                else
                    echo -e "${YELLOW}[!] sublist3r not installed. Consider installing for better subdomain enumeration.${NC}"
                fi
                ;;
            4)
                read -p "Enter domain or IP: " target
                read -p "Enter port number: " port
                echo -e "\n${GREEN}[+] Checking port $port...${NC}"
                nc -zvw3 "$target" "$port" 2>&1 | grep --color=auto "succeeded\|open"
                ;;
            5)
                read -p "Enter domain: " target
                echo -e "\n${GREEN}[+] Harvesting emails...${NC}"
                theharvester -d "$target" -b google,linkedin,bing,pgp
                ;;
            6)
                read -p "Enter file path: " file_path
                echo -e "\n${GREEN}[+] Extracting metadata...${NC}"
                if command -v exiftool &> /dev/null; then
                    exiftool "$file_path"
                else
                    echo -e "${YELLOW}[!] exiftool not installed. Installing now...${NC}"
                    sudo apt install exiftool -y
                    exiftool "$file_path"
                fi
                ;;
            7)
                read -p "Enter username: " username
                echo -e "\n${GREEN}[+] Searching social media...${NC}"
                if command -v sherlock &> /dev/null; then
                    sherlock "$username"
                else
                    echo -e "${YELLOW}[!] sherlock not installed. Consider installing for social media recon.${NC}"
                fi
                ;;
            8)
                return
                ;;
            *)
                echo -e "${RED}[-] Invalid option${NC}"
                sleep 1
                ;;
        esac
        
        read -p "Press enter to continue..."
    done
}

# Vulnerability Analysis
vuln_analysis() {
    while true; do
        banner
        echo -e "${CYAN}[*] Vulnerability Analysis${NC}"
        echo -e "${YELLOW}-------------------------------------------------------${NC}"
        echo -e "1. OpenVAS Scan"
        echo -e "2. Nessus Scan"
        echo -e "3. Lynis System Audit"
        echo -e "4. Searchsploit Vulnerability Search"
        echo -e "5. CVE Details Lookup"
        echo -e "6. Back to Main Menu${NC}"
        echo -e "${YELLOW}-------------------------------------------------------${NC}"
        
        read -p "Select an option: " choice
        
        case $choice in
            1)
                if command -v openvas &> /dev/null; then
                    read -p "Enter target IP or hostname: " target
                    echo -e "\n${GREEN}[+] Starting OpenVAS scan...${NC}"
                    openvas-start
                    echo -e "${YELLOW}[!] OpenVAS scan started. Check the web interface for results.${NC}"
                else
                    echo -e "${RED}[-] OpenVAS not installed!${NC}"
                fi
                ;;
            2)
                if command -v nessus &> /dev/null; then
                    read -p "Enter target IP or hostname: " target
                    echo -e "\n${GREEN}[+] Starting Nessus scan...${NC}"
                    systemctl start nessusd
                    echo -e "${YELLOW}[!] Nessus scan started. Check the web interface for results.${NC}"
                else
                    echo -e "${RED}[-] Nessus not installed!${NC}"
                fi
                ;;
            3)
                if command -v lynis &> /dev/null; then
                    echo -e "\n${GREEN}[+] Starting Lynis system audit...${NC}"
                    sudo lynis audit system
                else
                    echo -e "${RED}[-] Lynis not installed!${NC}"
                fi
                ;;
            4)
                read -p "Enter search term (e.g., apache 2.4): " term
                echo -e "\n${GREEN}[+] Searching for exploits...${NC}"
                searchsploit "$term"
                ;;
            5)
                read -p "Enter CVE ID (e.g., CVE-2020-0601): " cve_id
                echo -e "\n${GREEN}[+] Looking up CVE details...${NC}"
                curl -s "https://cve.circl.lu/api/cve/$cve_id" | jq .
                ;;
            6)
                return
                ;;
            *)
                echo -e "${RED}[-] Invalid option${NC}"
                sleep 1
                ;;
        esac
        
        read -p "Press enter to continue..."
    done
}

# Reporting
generate_report() {
    banner
    echo -e "${CYAN}[*] Generate Report${NC}"
    echo -e "${YELLOW}-------------------------------------------------------${NC}"
    
    read -p "Enter target name: " target_name
    read -p "Enter findings file path: " findings_file
    read -p "Enter output file name (without extension): " report_name
    
    timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
    report_file="${report_name}_${timestamp}.html"
    
    echo -e "\n${GREEN}[+] Generating report...${NC}"
    
    # HTML Report Header
    echo "<!DOCTYPE html>
<html>
<head>
    <title>Penetration Test Report - $target_name</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }
        .header { background-color: #2c3e50; color: white; padding: 20px; text-align: center; border-radius: 5px; }
        .section { margin-bottom: 30px; border-bottom: 1px solid #eee; padding-bottom: 20px; }
        .finding { background-color: #f9f9f9; padding: 15px; border-left: 4px solid #e74c3c; margin-bottom: 15px; border-radius: 3px; }
        .critical { border-left-color: #e74c3c; }
        .high { border-left-color: #f39c12; }
        .medium { border-left-color: #f1c40f; }
        .low { border-left-color: #3498db; }
        .info { border-left-color: #2ecc71; }
        h1, h2, h3 { color: #2c3e50; }
        .footer { text-align: center; margin-top: 30px; font-size: 0.9em; color: #7f8c8d; }
    </style>
</head>
<body>
    <div class='header'>
        <h1>Penetration Test Report</h1>
        <h2>$target_name</h2>
        <p>Generated on $(date) by HACKCTF</p>
    </div>" > "$report_file"
    
    # Process findings
    while IFS= read -r line; do
        if [[ "$line" =~ ^#\ \[(Critical|High|Medium|Low|Info)\] ]]; then
            severity=${BASH_REMATCH[1]}
            title=${line#*[}
            title=${title%]*}
            title=${title#* }
            echo "<div class='finding $severity'>
        <h3>$severity: $title</h3>
        <p>" >> "$report_file"
        else
            echo "$line<br>" >> "$report_file"
        fi
    done < "$findings_file"
    
    # HTML Report Footer
    echo "</div>
    <div class='footer'>
        <p>Report generated by HACKCTF v$VERSION</p>
        <p>Confidential - For authorized personnel only</p>
    </div>
</body>
</html>" >> "$report_file"
    
    echo -e "\n${GREEN}[+] Report generated: $report_file${NC}"
    read -p "Press enter to continue..."
}

# Main Menu
main_menu() {
    while true; do
        banner
        echo -e "${CYAN}[*] Main Menu${NC}"
        echo -e "${YELLOW}-------------------------------------------------------${NC}"
        echo -e "1. Network Scanning"
        echo -e "2. Web Scanning"
        echo -e "3. Password Cracking"
        echo -e "4. Reconnaissance"
        echo -e "5. Vulnerability Analysis"
        echo -e "6. Generate Report"
        echo -e "7. Check Dependencies"
        echo -e "8. Update HACKCTF"
        echo -e "9. Exit${NC}"
        echo -e "${YELLOW}-------------------------------------------------------${NC}"
        
        read -p "Select an option: " choice
        
        case $choice in
            1)
                network_scan
                ;;
            2)
                web_scan
                ;;
            3)
                password_crack
                ;;
            4)
                recon
                ;;
            5)
                vuln_analysis
                ;;
            6)
                generate_report
                ;;
            7)
                check_dependencies
                ;;
            8)
                echo -e "\n${GREEN}[+] Updating HACKCTF...${NC}"
                git clone https://github.com/bytehackedits/HACKCTF.git /tmp/HACKCTF
                if [ -f /tmp/HACKCTF/hackctf.sh ]; then
                    sudo cp /tmp/HACKCTF/hackctf.sh /usr/local/bin/hackctf
                    sudo chmod +x /usr/local/bin/hackctf
                    rm -rf /tmp/HACKCTF
                    echo -e "${GREEN}[+] Update complete! Restarting...${NC}"
                    sleep 2
                    exec "$0" "$@"
                else
                    echo -e "${RED}[-] Update failed!${NC}"
                fi
                ;;
            9)
                echo -e "\n${GREEN}[+] Exiting... Happy Hacking!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}[-] Invalid option${NC}"
                sleep 1
                ;;
        esac
    done
}

# Initial checks
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${YELLOW}[!] Warning: Some tools might require root privileges${NC}"
    sleep 2
fi

# Check if running in a terminal
if [ ! -t 0 ]; then
    echo -e "${RED}[-] This script must be run in a terminal${NC}"
    exit 1
fi

# Check for updates on startup
echo -e "${CYAN}[*] Checking for updates...${NC}"
if ping -q -c 1 -W 1 github.com >/dev/null; then
    latest_version=$(curl -s https://raw.githubusercontent.com/bytehackedits/HACKCTF/main/version.txt)
    if [ "$latest_version" != "$VERSION" ]; then
        echo -e "${YELLOW}[!] New version available ($latest_version). Consider updating!${NC}"
        sleep 2
    fi
fi

check_dependencies
main_menu
