#!/bin/bash

# Params
# 1 - Host
# 2 - Port
# 3 - ID to use to SSH
# 4 - Password for this ID
# 5 - Directory PYSHELL_PATH to deploy the shell files to
# 6 - Pyshell's AES key
# 7 - Pyshell's AES host
# 8 - Pyshell's AES port
# 9 - Pyshell's user
# 10 - Pyshell's AES default process timeout (default: 1800)
#
# Eg ./deploy.sh 91.232.105.77 64760 root \
#       fjeoifeio90r8ropfp304fe2r9flko23fk03dqef /kloudust/system \
#       48984jfkj90824edoj098398ioqjd902u821 0.0.0.0 64761 root 1800

SCRIPT_DIR=$(dirname "$0")
PYSHELLDIR=$(realpath "$SCRIPT_DIR/../")
HOST=$1
SSHPORT=$2
ID=$3
PASS=$4
PYSHELL_PATH=$5
PYSHELL_KEY=$6
PYSHELL_HOST=$7
PYSHELL_PORT=$8
PYSHELL_ID=$9
PYSHELL_TIMEOUT="${10:-1800}"


function exitFailed() {
    echo "${1:-Failed}"
    exit 1
}


if ! sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$ID@$HOST" -p $SSHPORT "bash -c \"mkdir -p \\\"$PYSHELL_PATH\\\"\""; then 
    exitFailed "Remote directory creation failed"
fi

if ! cat "$PYSHELLDIR/pyshell.py" | sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no $ID@$HOST -p $SSHPORT "cat > '$PYSHELL_PATH/pyshell.py'"; then
    exitFailed "Script upload failed"
fi

if ! cat "$SCRIPT_DIR/pyshell.service.template" | sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no $ID@$HOST -p $SSHPORT "cat > '$PYSHELL_PATH/pyshell.service.template'"; then
    exitFailed "Service file upload failed"
fi

if ! sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no $ID@$HOST -p $SSHPORT 'bash -s' < "$SCRIPT_DIR/remotedeploy.sh" "$PYSHELL_PATH" $PYSHELL_ID $PYSHELL_KEY $PYSHELL_HOST $PYSHELL_PORT $PYSHELL_TIMEOUT; then
    exitFailed "Script remote deployment failed"
fi

