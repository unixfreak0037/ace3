#!/usr/bin/env bash

cd /opt/ace
source /venv/bin/activate
source load_environment
source docker/startup/start.sh

if [ -e data/var/services/yara ]
then
    rm data/var/services/yara
fi

./ace -L etc/logging_configs/service_yara.ini service start yara
