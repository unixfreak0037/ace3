#!/usr/bin/env bash

cd /opt/ace
source /venv/bin/activate
source load_environment
source docker/startup/start.sh

if [ -e data/var/services/engine ]
then
    rm data/var/services/engine
fi

while :; do sleep 1; done
