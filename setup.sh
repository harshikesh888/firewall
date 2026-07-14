#!/bin/bash
# Firewall Setup Script — supports Debian/Ubuntu, Arch, Fedora/RHEL, openSUSE
# Configures iptables/nftables to redirect traffic to NFQueue for processing

set -e

QUEUE_NUM=${1:-0}
CHAIN_NAME="FW_CHAIN"
INTERFACE=${2:-eth0}

echo "=== Firewall Setup ==="
echo "Queue:     $QUEUE_NUM"
echo "Chain:     $CHAIN_NAME"
echo "Interface: $INTERFACE"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "[!] Run as root: sudo ./setup.sh"
    exit 1
fi

# --- Detect package manager and install deps ---
install_deps() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "[*] Detected Debian/Ubuntu"
        apt-get update -qq
        apt-get install -y -qq libnetfilter-queue-dev libnetfilter-queue1 iptables-persistent
    elif command -v pacman >/dev/null 2>&1; then
        echo "[*] Detected Arch Linux"
        pacman -S --needed --noconfirm libnetfilter_queue iptables nftables
    elif command -v dnf >/dev/null 2>&1; then
        echo "[*] Detected Fedora/RHEL"
        dnf install -y libnetfilter_queue-devel iptables
    elif command -v zypper >/dev/null 2>&1; then
        echo "[*] Detected openSUSE"
        zypper install -y libnetfilter_queue-devel iptables
    else
        echo "[!] Unsupported package manager"
        exit 1
    fi
}

install_deps

# --- Clean previous rules ---
iptables -D INPUT -j $CHAIN_NAME 2>/dev/null || true
iptables -D OUTPUT -j $CHAIN_NAME 2>/dev/null || true
iptables -F $CHAIN_NAME 2>/dev/null || true
iptables -X $CHAIN_NAME 2>/dev/null || true

# --- Create chain and redirect to NFQueue ---
iptables -N $CHAIN_NAME
iptables -A $CHAIN_NAME -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass

iptables -I INPUT 1 -j $CHAIN_NAME
iptables -I OUTPUT 1 -j $CHAIN_NAME

echo "[+] iptables rules configured"
echo "[+] Traffic on $INTERFACE processed by NFQueue #$QUEUE_NUM"

echo ""
echo "Current iptables rules:"
iptables -L $CHAIN_NAME -v -n

echo ""
echo "[*] Now run the firewall:"
echo "    sudo ./firewall -q $QUEUE_NUM"
