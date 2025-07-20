#!/usr/bin/env bash

cd /opt/ace
source /venv/bin/activate
source load_environment
source docker/startup/start.sh

if [ -e data/var/services/remediation ]
then
    rm data/var/services/remediation
fi

./ace -L etc/logging_configs/service_remediation.ini service start remediation

