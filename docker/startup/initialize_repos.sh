#!/usr/bin/env bash

cd /opt/ace
source /venv/bin/activate
source load_environment
source docker/startup/start.sh

bin/site/initialize_repos.sh
bin/site/initialize_external_data.sh
