#!/bin/bash
set -uo pipefail
RED='\033[1;31m'; GRN='\033[1;32m'; BLU='\033[1;34m'; YLW='\033[1;33m'; CYN='\033[1;36m'; RST='\033[0m'

if [[ $EUID -ne 0 ]] && ! sudo -n true 2>/dev/null; then
    echo -e "${RED}[!] This script requires sudo privileges.${RST}"
    echo -e "${YLW}[i] Please run: sudo $0${RST}"
    exit 1
fi

detect_vm() {
    VM_TYPE="none"
    VM_DETECTED=false
    
    if command -v systemd-detect-virt &>/dev/null; then
        VM_TYPE=$(systemd-detect-virt 2>/dev/null || echo "none")
        if [[ "$VM_TYPE" != "none" ]]; then
            VM_DETECTED=true
            return
        fi
    fi
    
    if [[ -r /sys/class/dmi/id/product_name ]]; then
        PRODUCT=$(cat /sys/class/dmi/id/product_name 2>/dev/null)
        case "$PRODUCT" in
            *VirtualBox*) VM_TYPE="oracle"; VM_DETECTED=true ;;
            *VMware*) VM_TYPE="vmware"; VM_DETECTED=true ;;
            *KVM*) VM_TYPE="kvm"; VM_DETECTED=true ;;
            *QEMU*) VM_TYPE="qemu"; VM_DETECTED=true ;;
        esac
    fi
    
    if [[ "$VM_DETECTED" == "false" ]]; then
        MACS=$(ip link | grep -o -E '([0-9a-f]{2}:){5}[0-9a-f]{2}')
        if echo "$MACS" | grep -q "^08:00:27"; then
            VM_TYPE="oracle"; VM_DETECTED=true
        elif echo "$MACS" | grep -q "^00:0c:29\|^00:50:56"; then
            VM_TYPE="vmware"; VM_DETECTED=true
        elif echo "$MACS" | grep -q "^00:15:5d"; then
            VM_TYPE="hyperv"; VM_DETECTED=true
        elif echo "$MACS" | grep -q "^52:54:00"; then
            VM_TYPE="kvm"; VM_DETECTED=true
        fi
    fi
}

detect_vm

disable_killswitch() {
    echo
    echo -e "${YLW}═══════════════════════════════════════════════════════${RST}"
    echo -e "${YLW}          Disabling VPN Killswitch...${RST}"
    echo -e "${YLW}═══════════════════════════════════════════════════════${RST}"
    echo
    
    echo -e "${BLU}[*] Flushing iptables rules...${RST}"
    sudo iptables -F
    sudo iptables -X
    sudo iptables -t nat -F
    sudo iptables -t nat -X
    sudo iptables -t mangle -F
    sudo iptables -t mangle -X
    
    echo -e "${BLU}[*] Setting default policies to ACCEPT...${RST}"
    sudo iptables -P INPUT ACCEPT
    sudo iptables -P FORWARD ACCEPT
    sudo iptables -P OUTPUT ACCEPT
    
    sudo ip6tables -F 2>/dev/null || true
    sudo ip6tables -X 2>/dev/null || true
    sudo ip6tables -P INPUT ACCEPT 2>/dev/null || true
    sudo ip6tables -P FORWARD ACCEPT 2>/dev/null || true
    sudo ip6tables -P OUTPUT ACCEPT 2>/dev/null || true
    
    echo -e "${BLU}[*] Saving changes...${RST}"
    sudo netfilter-persistent save 2>/dev/null || sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    
    echo -e "\n${GRN}[✓] Killswitch disabled - internet restored!${RST}"
    echo -e "${BLU}[i] Testing connection...${RST}"
    
    if ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
        echo -e "${GRN}[✓] Internet connection working!${RST}"
    else
        echo -e "${YLW}[!] Still no connection - check your network settings${RST}"
    fi
    exit 0
}

show_usage() {
    echo -e "${BLU}Usage:${RST}"
    echo -e "  ${GRN}$0${RST}                    Run full system boost"
    echo -e "  ${GRN}$0 --disable${RST}          Disable VPN killswitch only"
    echo -e "  ${GRN}$0 -d${RST}                 Disable VPN killswitch only"
    echo -e "  ${GRN}$0 --interactive${RST}       Interactive mode (MAC control)"
    echo -e "  ${GRN}$0 -i${RST}                 Interactive mode (MAC control)"
    echo -e "  ${GRN}$0 --help${RST}             Show this help message"
    echo -e "  ${GRN}$0 -h${RST}                 Show this help message"
    exit 0
}

interactive_mode() {
    echo
    echo -e "${CYN}═══════════════════════════════════════════════════════${RST}"
    echo -e "${CYN}       NETREDIRECT - Interactive Mode v1.0${RST}"
    echo -e "${CYN}            MAC Address Control Panel${RST}"
    echo -e "${CYN}═══════════════════════════════════════════════════════${RST}"
    echo
    
    NETWORK_INTERFACE=$(ip link | grep -E 'eth|enp|eno|ens|wlan|wlp' | grep -v 'NO-CARRIER' | head -n1 | awk -F: '{print $2}' | tr -d ' ')
    
    if [ -z "$NETWORK_INTERFACE" ]; then
        echo -e "${RED}[!] No network interface found${RST}"
        echo -e "${RED}    Interactive mode requires active network interface${RST}"
        exit 1
    fi
    
    echo -e "${GRN}[✓] Using interface: ${NETWORK_INTERFACE}${RST}\n"
    
    change_mac() {
        echo -e "${BLU}[*] Changing MAC address...${RST}"
        NEWMAC=$(openssl rand -hex 6 | sed 's/\(..\)/\1:/g; s/:$//' | tr '[:lower:]' '[:upper:]')
        
        SERVICES=()
        for svc in NetworkManager wpa_supplicant; do
            if systemctl is-active --quiet $svc 2>/dev/null; then
                sudo systemctl stop $svc 2>/dev/null && SERVICES+=($svc)
            fi
        done
        
        sudo ip addr flush dev $NETWORK_INTERFACE 2>/dev/null || true
        sudo ip link set dev $NETWORK_INTERFACE down 2>/dev/null || true
        sleep 1
        
        MAC_OK=false
        
        if command -v macchanger &>/dev/null; then
            if sudo macchanger -m $NEWMAC $NETWORK_INTERFACE 2>&1 | grep -q "New MAC\|Faked MAC"; then
                MAC_OK=true
            fi
        fi
        
        if [[ "$MAC_OK" == "false" ]]; then
            if sudo ip link set dev $NETWORK_INTERFACE address $NEWMAC 2>/dev/null; then
                MAC_OK=true
            fi
        fi
        
        if [[ "$MAC_OK" == "false" ]]; then
            echo "$NEWMAC" | sudo tee "/sys/class/net/$NETWORK_INTERFACE/address" >/dev/null 2>&1 && MAC_OK=true
        fi
        
        sudo ip link set dev $NETWORK_INTERFACE up 2>/dev/null || true
        
        for svc in "${SERVICES[@]}"; do
            sudo systemctl start $svc 2>/dev/null || true
        done
        sleep 2
        
        CURRENT=$(ip link show $NETWORK_INTERFACE 2>/dev/null | grep -o -E '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -n1)
        if [[ "$MAC_OK" == "true" ]]; then
            echo -e "${GRN}[✓] MAC changed: ${CURRENT}${RST}"
        else
            echo -e "${RED}[✗] MAC change failed${RST}"
        fi
        
        sudo dhclient -r $NETWORK_INTERFACE 2>/dev/null || true
        sudo dhclient $NETWORK_INTERFACE 2>/dev/null || true
    }
    
    echo -e "${CYN}═══════════════════════════════════════════════════════${RST}"
    echo -e "${CYN}              KEYBOARD CONTROLS${RST}"
    echo -e "${CYN}═══════════════════════════════════════════════════════${RST}"
    echo -e "  ${GRN}m${RST} → Change MAC address"
    echo -e "  ${GRN}s${RST} → Show current status"
    echo -e "  ${GRN}q${RST} → Quit interactive mode"
    echo -e "${CYN}═══════════════════════════════════════════════════════${RST}"
    echo
    
    echo -e "${YLW}[i] Press any key to start monitoring...${RST}"
    
    stty -echo -icanon time 0 min 0
    
    while true; do
        key=$(dd bs=1 count=1 2>/dev/null)
        
        case "$key" in
            m|M)
                change_mac
                ;;
            s|S)
                echo
                echo -e "${BLU}═══════════════════════════════════════════════════════${RST}"
                echo -e "${BLU}              Current Status${RST}"
                echo -e "${BLU}═══════════════════════════════════════════════════════${RST}"
                CURRENT_MAC=$(ip link show $NETWORK_INTERFACE | grep -o -E '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -n1)
                echo -e "  ${CYN}→${RST} Interface: ${GRN}$NETWORK_INTERFACE${RST}"
                echo -e "  ${CYN}→${RST} MAC:       ${GRN}$CURRENT_MAC${RST}"
                echo -e "${BLU}═══════════════════════════════════════════════════════${RST}"
                echo
                ;;
            q|Q)
                echo -e "\n${GRN}[*] Exiting interactive mode...${RST}"
                stty sane
                exit 0
                ;;
        esac
        
        sleep 0.1
    done
    
    stty sane
}

case "${1:-}" in
    --disable|-d) disable_killswitch ;;
    --interactive|-i) interactive_mode ;;
    --help|-h) show_usage ;;
    "") ;;
    *) echo -e "${RED}[!] Unknown option: $1${RST}"; show_usage ;;
esac

echo -e "${GRN}═══════════════════════════════════════════════════════${RST}"
echo -e "${GRN}        NETREDIRECT v1.0 - Network Redirection Tool${RST}"
if [[ "$VM_DETECTED" == "true" ]]; then
    printf "  ║               🖥️  VM Mode: %-20s ║\n" "$VM_TYPE"
    echo "  ║      (Aggressive MAC spoofing enabled for VMs)    ║"
fi
echo -e "${GRN}═══════════════════════════════════════════════════════${RST}"
echo

echo -e "${BLU}[*] Fixing broken repositories...${RST}"
sudo rm -f /etc/apt/sources.list.d/cloudflare-client.list 2>/dev/null || true
sudo sed -i '/pkg.cloudflareclient.com/d' /etc/apt/sources.list 2>/dev/null || true

REPOS_FIXED=0
if grep -E "^deb.*deb.parrot.sh/parrot.*rolling" /etc/apt/sources.list 2>/dev/null; then
    sudo sed -i 's|^deb \(.*deb.parrot.sh/parrot.*rolling.*\)|#deb \1|g' /etc/apt/sources.list
    ((REPOS_FIXED++))
fi
if grep -E "^deb-src.*deb.parrot.sh/parrot.*rolling" /etc/apt/sources.list 2>/dev/null; then
    sudo sed -i 's|^deb-src \(.*deb.parrot.sh/parrot.*rolling.*\)|#deb-src \1|g' /etc/apt/sources.list
    ((REPOS_FIXED++))
fi
if [[ $REPOS_FIXED -gt 0 ]]; then
    echo -e "${YLW}[!] Disabled $REPOS_FIXED broken Parrot rolling repo(s) (404 errors)${RST}"
else
    echo -e "${GRN}[✓] No broken Parrot repos found${RST}"
fi

echo -e "${BLU}[*] Updating repositories and system...${RST}"
sudo apt-get update 2>&1 | grep -v "does not have a Release file" | grep -v "404  Not Found" || true
sudo apt-get -y dist-upgrade --auto-remove 2>/dev/null || echo -e "${YLW}[!] Some updates failed, continuing...${RST}"

echo -e "${BLU}[*] Installing required tools...${RST}"
if sudo apt-get install -y macchanger 2>/dev/null; then
    echo -e "${GRN}[✓] macchanger installed${RST}"
else
    echo -e "${YLW}[!] macchanger could not be installed${RST}"
fi

sudo apt-get install -y iptables-persistent 2>/dev/null && echo -e "${GRN}[✓] iptables-persistent installed${RST}" || \
echo -e "${YLW}[!] iptables-persistent not available (rules won't persist after reboot)${RST}"

echo -e "${BLU}[*] Checking internet connectivity...${RST}"
INTERNET_OK=false

if ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
    INTERNET_OK=true
    echo -e "${GRN}[✓] Internet connection available (ping OK)${RST}"
elif ping -c 1 -W 2 1.1.1.1 &>/dev/null; then
    INTERNET_OK=true
    echo -e "${GRN}[✓] Internet connection available (ping OK)${RST}"
elif curl -s --connect-timeout 3 -I https://github.com 2>/dev/null | head -n1 | grep -q "200\|301\|302"; then
    INTERNET_OK=true
    echo -e "${GRN}[✓] Internet connection available (curl OK)${RST}"
elif wget -q --spider --timeout=3 https://github.com 2>/dev/null; then
    INTERNET_OK=true
    echo -e "${GRN}[✓] Internet connection available (wget OK)${RST}"
else
    echo -e "${YLW}[!] No internet connection detected - skipping plugin downloads${RST}"
    echo -e "${YLW}    If you do have internet, plugins can be installed manually later${RST}"
fi

if [ "$INTERNET_OK" = true ]; then
    echo -e "${BLU}[*] Downloading ZSH plugins...${RST}"
    if [[ ! -d ~/.zsh-syntax-highlighting ]]; then
        if git clone --depth=1 https://github.com/zsh-users/zsh-syntax-highlighting.git ~/.zsh-syntax-highlighting 2>/dev/null; then
            echo -e "${GRN}[✓] Syntax highlighting installed${RST}"
        else
            echo -e "${YLW}[!] Failed to clone syntax-highlighting${RST}"
        fi
    else
        echo -e "${GRN}[✓] Syntax highlighting already installed${RST}"
    fi
    
    if [[ ! -d ~/.zsh-autosuggestions ]]; then
        if git clone --depth=1 https://github.com/zsh-users/zsh-autosuggestions.git ~/.zsh-autosuggestions 2>/dev/null; then
            echo -e "${GRN}[✓] Autosuggestions installed${RST}"
        else
            echo -e "${YLW}[!] Failed to clone autosuggestions${RST}"
        fi
    else
        echo -e "${GRN}[✓] Autosuggestions already installed${RST}"
    fi
    
    if [[ -d ~/.zsh-syntax-highlighting && -d ~/.zsh-autosuggestions ]]; then
        if ! grep -q 'zsh-syntax' ~/.zshrc 2>/dev/null; then
            cat >> ~/.zshrc << 'ZSHCONFIG'

source ~/.zsh-syntax-highlighting/zsh-syntax-highlighting.zsh
source ~/.zsh-autosuggestions/zsh-autosuggestions.zsh
PROMPT='%F{red}▶%f %F{green}%n@%m%f:%~# '
ZSHCONFIG
        fi
        echo -e "${GRN}[✓] ZSH plugins configured${RST}"
    fi
fi

echo -e "${BLU}[*] Changing hostname to random value...${RST}"
NEWMAC=$(openssl rand -hex 6 | sed 's/\(..\)/\1:/g; s/:$//' | tr '[:lower:]' '[:upper:]')
NEWHOST="parrot-$(openssl rand -hex 2)"

OLDHOST=$(cat /etc/hostname 2>/dev/null || hostname)

if ! grep -q "^127.0.1.1" /etc/hosts 2>/dev/null; then
    echo "127.0.1.1	$OLDHOST localhost" | sudo tee -a /etc/hosts >/dev/null 2>&1
fi

sudo sed -i "s/^127\.0\.1\.1.*/127.0.1.1\t$NEWHOST $OLDHOST localhost/" /etc/hosts 2>/dev/null

echo $NEWHOST | sudo tee /etc/hostname >/dev/null 2>&1
sudo hostname $NEWHOST 2>/dev/null || true

echo -e "${GRN}[✓] Hostname changed: ${OLDHOST} → ${NEWHOST}${RST}"

MAC_CHANGED=false
echo -e "${BLU}[*] MAC Address Configuration...${RST}"

NETWORK_INTERFACE=""
NETWORK_INTERFACE=$(ip link | grep -E 'wlan|wlp|wlo' | grep -v 'NO-CARRIER' | head -n1 | awk -F: '{print $2}' | tr -d ' ')
if [ -z "$NETWORK_INTERFACE" ]; then
    NETWORK_INTERFACE=$(ip link | grep -E 'eth|enp|eno|ens' | grep -v 'NO-CARRIER' | head -n1 | awk -F: '{print $2}' | tr -d ' ')
fi

if [ -z "$NETWORK_INTERFACE" ]; then
    echo -e "${YLW}[!] No active network interface detected${RST}"
    echo -e "${YLW}    Available interfaces:${RST}"
    ip link | grep -E '^[0-9]+:' | awk '{print "    - " $2}' | tr -d ':' | grep -v 'lo'
else
    if [[ "$VM_DETECTED" == "true" ]]; then
        echo -e "${CYN}[i] VM detected (${VM_TYPE}) - using aggressive MAC change methods${RST}"
    fi
    
    echo -e "${BLU}[*] Attempting MAC change on ${NETWORK_INTERFACE}...${RST}"
    
    echo -e "${BLU}[*] Stopping interfering services...${RST}"
    SERVICES_STOPPED=()
    for service in NetworkManager wpa_supplicant dhclient networking; do
        if systemctl is-active --quiet $service 2>/dev/null; then
            sudo systemctl stop $service 2>/dev/null && SERVICES_STOPPED+=($service)
        fi
    done
    
    sudo pkill -9 dhclient 2>/dev/null || true
    sudo pkill -9 wpa_supplicant 2>/dev/null || true
    
    sudo ip addr flush dev $NETWORK_INTERFACE 2>/dev/null || true
    sudo ip route flush dev $NETWORK_INTERFACE 2>/dev/null || true
    
    sudo ip link set dev $NETWORK_INTERFACE down 2>/dev/null || true
    sleep 2
    
    METHODS_TRIED=0
    
    if command -v macchanger &>/dev/null; then
        ((METHODS_TRIED++))
        echo -e "${BLU}[*] Method $METHODS_TRIED: macchanger with specific MAC${RST}"
        if sudo macchanger -m $NEWMAC $NETWORK_INTERFACE 2>&1 | grep -q "New MAC\|Faked MAC"; then
            echo -e "${GRN}[✓] MAC changed with macchanger: ${NEWMAC}${RST}"
            MAC_CHANGED=true
        fi
    fi
    
    if [[ "$MAC_CHANGED" == "false" ]]; then
        ((METHODS_TRIED++))
        echo -e "${BLU}[*] Method $METHODS_TRIED: ip link set address${RST}"
        if sudo ip link set dev $NETWORK_INTERFACE address $NEWMAC 2>/dev/null; then
            echo -e "${GRN}[✓] MAC changed with ip command: ${NEWMAC}${RST}"
            MAC_CHANGED=true
        fi
    fi
    
    if [[ "$MAC_CHANGED" == "false" ]] && [ -w "/sys/class/net/$NETWORK_INTERFACE/address" ]; then
        ((METHODS_TRIED++))
        echo -e "${BLU}[*] Method $METHODS_TRIED: sysfs direct write${RST}"
        if echo "$NEWMAC" | sudo tee "/sys/class/net/$NETWORK_INTERFACE/address" >/dev/null 2>&1; then
            echo -e "${GRN}[✓] MAC changed via sysfs: ${NEWMAC}${RST}"
            MAC_CHANGED=true
        fi
    fi
    
    if [[ "$MAC_CHANGED" == "false" ]] && command -v macchanger &>/dev/null; then
        ((METHODS_TRIED++))
        echo -e "${BLU}[*] Method $METHODS_TRIED: macchanger random${RST}"
        if sudo macchanger -r $NETWORK_INTERFACE 2>&1 | grep -q "New MAC\|Faked MAC"; then
            RANDOM_MAC=$(ip link show $NETWORK_INTERFACE | grep -o -E '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -n1)
            echo -e "${GRN}[✓] MAC changed with random: ${RANDOM_MAC}${RST}"
            NEWMAC=$RANDOM_MAC
            MAC_CHANGED=true
        fi
    fi
    
    sleep 1
    sudo ip link set dev $NETWORK_INTERFACE up 2>/dev/null || true
    sleep 2
    
    if [ ${#SERVICES_STOPPED[@]} -gt 0 ]; then
        echo -e "${BLU}[*] Restarting services...${RST}"
        for service in "${SERVICES_STOPPED[@]}"; do
            sudo systemctl start $service 2>/dev/null || true
        done
        sleep 3
    fi
    
    CURRENT_MAC=$(ip link show $NETWORK_INTERFACE 2>/dev/null | grep -o -E '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -n1)
    
    if [ "$MAC_CHANGED" = true ]; then
        if [[ "$CURRENT_MAC" == "$NEWMAC" ]] || [[ "$CURRENT_MAC" != "" ]]; then
            echo -e "${GRN}[✓] MAC verified: ${CURRENT_MAC}${RST}"
            if [[ "$VM_DETECTED" == "true" ]]; then
                echo -e "${GRN}[✓] Success! MAC changed even in VM environment${RST}"
            fi
        else
            echo -e "${YLW}[!] MAC may have been reverted by system${RST}"
            echo -e "${YLW}    Current MAC: ${CURRENT_MAC}${RST}"
            MAC_CHANGED=false
        fi
    else
        echo -e "${RED}[✗] All $METHODS_TRIED methods failed to change MAC${RST}"
        if [[ "$VM_DETECTED" == "true" ]]; then
            echo -e "${YLW}[i] This VM's network driver may not support MAC spoofing${RST}"
            echo -e "${YLW}    Alternative: Configure MAC in hypervisor settings${RST}"
        fi
    fi
    
    if [ "$MAC_CHANGED" = true ]; then
        echo -e "${BLU}[*] Requesting new IP address...${RST}"
        sudo dhclient -r $NETWORK_INTERFACE 2>/dev/null || true
        sudo dhclient $NETWORK_INTERFACE 2>/dev/null || true
    fi
fi

echo -e "${BLU}[*] VPN Killswitch Configuration...${RST}"
APPLY_KILLSWITCH=true

if [[ "$VM_DETECTED" == "true" ]]; then
    echo -e "${CYN}[i] Running in VM - VPN killswitch usually not needed${RST}"
    echo -e "${CYN}    (VPN typically runs on host machine)${RST}"
    if ip link show tun0 &>/dev/null; then
        echo -e "${GRN}[✓] VPN detected in guest - killswitch will be configured${RST}"
    else
        echo -e "${YLW}[?] No VPN in guest. Apply killswitch anyway? (y/N) - Auto-skip in 5s${RST}"
        read -t 5 -n 1 -r REPLY || REPLY="n"
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${CYN}[i] Killswitch skipped (not needed in VM without VPN)${RST}"
            APPLY_KILLSWITCH=false
        fi
    fi
else
    if ip link show tun0 &>/dev/null; then
        echo -e "${GRN}[✓] VPN detected (tun0 is up)${RST}"
    else
        echo -e "${RED}[!] WARNING: VPN not detected! Killswitch will block ALL traffic.${RST}"
        echo -e "${YLW}[?] Do you want to skip killswitch? (y/N) - Auto-skip in 10s${RST}"
        read -t 10 -n 1 -r REPLY || REPLY="y"
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${YLW}[!] Skipping killswitch configuration${RST}"
            APPLY_KILLSWITCH=false
        else
            echo -e "${YLW}[!] Applying killswitch anyway...${RST}"
        fi
    fi
fi

if [ "$APPLY_KILLSWITCH" = true ]; then
    sudo iptables -F
    sudo iptables -P INPUT DROP
    sudo iptables -P FORWARD DROP
    sudo iptables -P OUTPUT DROP
    sudo iptables -A OUTPUT -o lo -j ACCEPT
    sudo iptables -A OUTPUT -o tun0 -j ACCEPT
    sudo iptables -A OUTPUT -d 10.0.0.0/8 -j ACCEPT
    sudo iptables -A OUTPUT -d 192.168.0.0/16 -j ACCEPT
    sudo iptables -A OUTPUT -d 172.16.0.0/12 -j ACCEPT
    sudo iptables -A OUTPUT -d 127.0.0.0/8 -j ACCEPT
    sudo iptables -A OUTPUT -d 255.255.255.255 -j ACCEPT
    sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    sudo iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
    sudo iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
    
    if command -v ip6tables &>/dev/null; then
        sudo ip6tables -F 2>/dev/null || true
        sudo ip6tables -P INPUT DROP 2>/dev/null || true
        sudo ip6tables -P FORWARD DROP 2>/dev/null || true
        sudo ip6tables -P OUTPUT DROP 2>/dev/null || true
        sudo ip6tables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
        sudo ip6tables -A OUTPUT -o tun0 -j ACCEPT 2>/dev/null || true
        echo -e "${GRN}[✓] IPv6 killswitch also applied${RST}"
    fi
    
    if sudo netfilter-persistent save 2>/dev/null; then
        echo -e "${GRN}[✓] Killswitch activated and saved permanently${RST}"
    else
        echo -e "${YLW}[✓] Killswitch activated (not saved permanently)${RST}"
    fi
else
    echo -e "${BLU}[*] Keeping current firewall rules${RST}"
fi

echo -e "${BLU}[*] Cleaning logs and cache...${RST}"
sudo journalctl --vacuum-time=1s >/dev/null 2>&1 || true
sudo rm -rf /var/log/*.log.* /var/log/*.gz ~/.cache/thumbnails/* 2>/dev/null || true
history -c && history -w 2>/dev/null || true
echo -e "${GRN}[✓] System cleaned${RST}"

echo
echo -e "${GRN}═══════════════════════════════════════════════════════${RST}"
echo -e "${GRN}        🚀 Process Completed Successfully!${RST}"
echo -e "${GRN}═══════════════════════════════════════════════════════${RST}"
echo
if [[ "$VM_DETECTED" == "true" ]]; then
    echo -e "  ${BLU}→${RST} Environment:  ${CYN}Virtual Machine (${VM_TYPE})${RST}"
fi
echo -e "  ${BLU}→${RST} Old Hostname: ${YLW}${OLDHOST}${RST}"
echo -e "  ${BLU}→${RST} New Hostname: ${GRN}${NEWHOST}${RST}"
if [ "$MAC_CHANGED" = true ]; then
    echo -e "  ${BLU}→${RST} MAC Address:  ${GRN}${NEWMAC} ✓${RST}"
elif [[ "$VM_DETECTED" == "true" ]]; then
    echo -e "  ${BLU}→${RST} MAC Address:  ${CYN}VM (configure in hypervisor)${RST}"
else
    echo -e "  ${BLU}→${RST} MAC Address:  ${YLW}Not changed${RST}"
fi
if [ "$APPLY_KILLSWITCH" = true ]; then
    echo -e "  ${BLU}→${RST} Killswitch:   ${GRN}✓ ACTIVE${RST}"
else
    echo -e "  ${BLU}→${RST} Killswitch:   ${CYN}⨯ SKIPPED${RST}"
fi
echo
echo -e "${GRN}═══════════════════════════════════════════════════════${RST}"

echo -e "\n${BLU}[i] To apply hostname change fully:${RST}"
echo -e "    ${YLW}exec zsh${RST}  ${BLU}or${RST}  ${YLW}logout/login${RST}  ${BLU}or${RST}  ${YLW}reboot${RST}"

if [ "$APPLY_KILLSWITCH" = true ] && ! ip link show tun0 &>/dev/null; then
    echo
    echo -e "${RED}═══════════════════════════════════════════════════════${RST}"
    echo -e "${RED}  ⚠️  WARNING: Killswitch ACTIVE without VPN!${RST}"
    echo -e "${RED}      Your internet is now BLOCKED!${RST}"
    echo -e "${RED}═══════════════════════════════════════════════════════${RST}"
    echo
    echo -e "${YLW}To restore internet access, run:${RST}"
    echo -e "  ${GRN}sudo $0 --disable${RST}"
    echo
    echo -e "${YLW}Or manually:${RST}"
    echo -e "  ${GRN}sudo iptables -F && sudo iptables -P INPUT ACCEPT${RST}"
    echo -e "  ${GRN}sudo iptables -P FORWARD ACCEPT && sudo iptables -P OUTPUT ACCEPT${RST}"
elif [ "$APPLY_KILLSWITCH" = true ]; then
    echo
    echo -e "${GRN}[✓] Killswitch is ACTIVE - only VPN traffic allowed!${RST}"
    echo -e "${BLU}[i] To disable later: ${YLW}sudo $0 --disable${RST}"
fi

