#!/usr/bin/env bash
#
# sets the encryption password unless it has already been set
#

source load_environment
source /venv/bin/activate

if ! ace enc test -p "$SAQ_ENC" &> /dev/null
then
    echo "setting encryption password"
    ace enc set -o --password="$SAQ_ENC"
else
    echo "encryption password verified"
fi
