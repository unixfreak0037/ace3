#!/usr/bin/env bash
source /venv/bin/activate
source load_environment

if ! ( ace user list | awk '{print $2}' | egrep '^analyst$' )
then
    ace user add --password=analyst -d analyst analyst analyst@localhost
fi
