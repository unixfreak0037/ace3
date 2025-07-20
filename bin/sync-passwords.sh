#!/usr/bin/env bash
source load_environment
source /venv/bin/activate

# sync the passwords in the encrypted zip file
if [ -n "$ACE_ZIP_PASSWORD" ]
then
    unzip -o -P "$ACE_ZIP_PASSWORD" passwords.zip

    if [ -e passwords.json ]
    then
        echo "syncing passwords"
        ace enc config import passwords.json
        # don't let this sit around
        rm -f passwords.json
    fi
fi
