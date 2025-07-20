#!/usr/bin/env bash

cd /opt/ace
source /venv/bin/activate
source load_environment
source docker/startup/start.sh

if [ -e data/var/services/remote_email_collector ]
then
    rm data/var/services/remote_email_collector
fi

./ace -L etc/logging_configs/service_remote_email_collector.ini service start remote_email_collector

