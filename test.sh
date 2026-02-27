#!/bin/bash

OS=`uname -a`
CUSTOM_CMD=$1

echo OS details follow
printf "$OS\n"

sleep 2     # this should trigger a wait response

if [ -n "$CUSTOM_CMD" ]; then
    printf "\nCustom command output follows\n"
    bash -c $CUSTOM_CMD
fi
exit 0