#!/usr/bin/env bash

cd /opt/ace
source /venv/bin/activate
source load_environment
source docker/startup/start.sh

if [ -e data/var/services/network_semaphore ]
then
    rm data/var/services/network_semaphore
fi

./ace -L etc/logging_configs/service_network_semaphore.ini service start network_semaphore
