#!/usr/bin/env bash

cd /opt/ace
source /venv/bin/activate
source load_environment
source docker/startup/start.sh

uwsgi --ini etc/uwsgi_api.ini 
