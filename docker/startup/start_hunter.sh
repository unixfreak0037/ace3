#!/usr/bin/env bash

cd /opt/ace
source /venv/bin/activate
source load_environment
source docker/startup/start.sh

if [ -e data/var/services/hunter ]
then
    rm data/var/services/hunter
fi

./ace -L etc/logging_configs/service_hunter.ini service start hunter
