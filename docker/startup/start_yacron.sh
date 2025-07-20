#!/usr/bin/env bash

cd /opt/ace
source /venv/bin/activate
source load_environment
source docker/startup/start.sh

# the different cron environments need different env vars settings
# that may include sensitive data
# we don't want to include those in the image we build

target_dir=.yacron
mkdir -p $target_dir
echo $ACE_TARGET > $target_dir/ACE_TARGET
echo $SAQ_ENC > $target_dir/SAQ_ENC
echo $ACE_DB_PASSWORD > $target_dir/ACE_DB_PASSWORD
echo $MYSQL_ROOT_PASSWORD > $target_dir/MYSQL_ROOT_PASSWORD
echo $ACE_ZIP_PASSWORD > $target_dir/ACE_ZIP_PASSWORD

yacron -c etc/yacron-$ACE_TARGET.yml
