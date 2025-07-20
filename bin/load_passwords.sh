#!/usr/bin/env bash
source load_environment
source /venv/bin/activate

# make sure the passwords are loaded and up to date
if [ -n "$ACE_ZIP_PASSWORD" ]
then
    # see if there is a difference between what is in the database and what is in the encrypted export file
    if cmp <(unzip -qq -c -P "$ACE_ZIP_PASSWORD" passwords.zip passwords.json | python -m json.tool --sort-keys) <(ace --skip-initialize-automation-user enc config export - | python -m json.tool --sort-keys) &> /dev/null
    then
        echo "passwords have not been modified"
    else
        echo "importing passwords"
        ace enc config import <(unzip -qq -c -P "$ACE_ZIP_PASSWORD" passwords.zip passwords.json)
    fi
fi
