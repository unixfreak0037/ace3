#!/usr/bin/env bash

cd /opt/ace
source /venv/bin/activate
source load_environment
source docker/startup/start.sh

./ace -L etc/debug_logging.ini start-gui
