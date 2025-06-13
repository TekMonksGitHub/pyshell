#!/bin/bash

# Params
# 1 - Path which holds the scripts 
# 2 - ID to use to run the service, defaults to the logged in user's ID

PYSHELL_PATH="$1"
PYSHELL_ID="${2:-`whoami`}"
PYSHELL_KEY=$3
PYSHELL_HOST=$4
PYSHELL_PORT=$5
PYSHELL_TIMEOUT="${6:-1800}"

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

rm -rf "$PYSHELL_PATH/venv"
if ! /usr/bin/env python3 -m venv "$PYSHELL_PATH/venv"; then 
    exitFailed "Python virtual environment creation failed"
fi 

if ! "$PYSHELL_PATH/venv/bin/pip" install flask cryptography waitress; then
    exitFailed "Python pip install in the virtual environment failed"
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