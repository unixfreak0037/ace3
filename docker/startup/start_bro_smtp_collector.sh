#!/usr/bin/env bash

cd /opt/ace
source /venv/bin/activate
source load_environment
source docker/startup/start.sh

if [ -e data/var/services/bro_smtp_collector ]
then
    rm data/var/services/bro_smtp_collector
fi

./ace -L etc/logging_configs/service_bro_smtp_collector.ini service start bro_smtp_collector
