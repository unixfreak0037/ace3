#!/usr/bin/env bash

cd /opt/ace
source /venv/bin/activate
source load_environment
source docker/startup/start.sh

if [ -e data/var/services/background_executor ]
then
    rm data/var/services/background_executor
fi

./ace -L etc/logging_configs/service_background_executor.ini service start background_executor

