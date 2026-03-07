#!/bin/bash

# Params
# 1 - Path which holds the scripts 
# 2 - ID to use to run the service, defaults to the logged in user's ID
# 3 - The AES key
# 4 - The host to listen on eg 0.0.0.0
# 5 - The port to listen on
# 6 - The process timeout configuration for PyShell
# 7 - Whether to open an NFT firewall port for PyShell

PYSHELL_PATH="$1"
PYSHELL_ID="${2:-`whoami`}"
PYSHELL_KEY=$3
PYSHELL_HOST=$4
PYSHELL_PORT=$5
PYSHELL_TIMEOUT="${6:-1800}"
PYSHELL_FIREWALL="${7:-false}"

function exitFailed() {
    echo "${1:-Failed}"
    exit 1
}

if ! sed -e "s/{{PYSHELL_ID}}/$PYSHELL_ID/g" \
        -e "s|{{PYSHELL_PATH}}|$PYSHELL_PATH|g" \
        -e "s|{{PYTHON3_VENV_BIN}}|$PYSHELL_PATH/venv/bin|g" \
        -e "s|{{PYSHELL_KEY}}|$PYSHELL_KEY|g" \
        -e "s|{{PYSHELL_HOST}}|$PYSHELL_HOST|g" \
        -e "s|{{PYSHELL_PORT}}|$PYSHELL_PORT|g" \
        -e "s|{{PYSHELL_TIMEOUT}}|$PYSHELL_TIMEOUT|g" \
        "$PYSHELL_PATH/pyshell.service.template" > "$PYSHELL_PATH/pyshell.service"; then
    exitFailed "Service file expansion failed"
fi 

if ! sudo cp "$PYSHELL_PATH/pyshell.service" /lib/systemd/system/; then
    exitFailed "Service file copy to systemd failed"
fi 

if [ -f /etc/os-release ]; then
    ID=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
    ID_LIKE=$(grep '^ID_LIKE=' /etc/os-release | cut -d= -f2 | tr -d '"')
    if [[ "$ID" == "debian" || "$ID_LIKE" == *"debian"* ]]; then
        if ! dpkg -l | grep -qw python3-venv; then
            echo "Installing python3-venv because it was not found."
            sudo DEBIAN_FRONTEND=noninteractive apt -qq -y install python3-venv
        fi  
    fi
fi

rm -rf "$PYSHELL_PATH/venv"
if ! /usr/bin/env python3 -m venv "$PYSHELL_PATH/venv"; then 
    exitFailed "Python virtual environment creation failed"
fi 

if ! "$PYSHELL_PATH/venv/bin/pip" install flask cryptography waitress psutil; then
    exitFailed "Python pip install in the virtual environment failed"
fi 

# Open firewall ports if indicated, will create firewall NFT rules table too, if needed.
if [[ "${PYSHELL_FIREWALL,,}" != "false" ]]; then
    printf "\n\nOpening PyShell port in NFT firewall\n"
    if [[ "${PYSHELL_FIREWALL,,}" == "true" ]]; then
        NFT_TABLE=pyshellfirewall
    else 
        NFT_TABLE=$PYSHELL_FIREWALL
    fi

    # Create the filter table if it doesn't exist
    if ! sudo nft list table inet "$NFT_TABLE" > /dev/null 2>&1; then
        if ! sudo nft add table inet "$NFT_TABLE"; then exitFailed "Firewall table creation error"; fi
        if ! sudo nft add chain inet "$NFT_TABLE" input '{ type filter hook input priority filter; policy accept; }'; then exitFailed "Firewall chain creation error"; fi
    fi

    # Delete existing pyshell port rule if present
    sudo nft -a list chain inet "$NFT_TABLE" input 2>/dev/null | grep "tcp dport $PYSHELL_PORT" | grep -o 'handle [0-9]*' | awk '{print $2}' | while read -r handle; do
        sudo nft delete rule inet "$NFT_TABLE" input handle "$handle" 2>/dev/null
    done
        
    if ! sudo nft add rule inet "$NFT_TABLE" input tcp dport "$PYSHELL_PORT" accept; then exitFailed "Firewall port opening error"; fi
    if ! sudo nft list ruleset | sudo tee /etc/nftables.conf; then exitFailed "Firewall save rules error"; fi
    if ! sudo systemctl enable --now nftables; then exitFailed "Firewall service enable error"; fi
    if ! sudo systemctl restart nftables; then exitFailed "Firewall reload error"; fi
fi

sudo systemctl daemon-reload
if ! sudo systemctl enable pyshell.service; then
    exitFailed "Service file start with systemd failed"
fi 
if ! sudo systemctl restart pyshell.service; then
    exitFailed "Service file start with systemd failed"
fi 

echo Done.
exit 0