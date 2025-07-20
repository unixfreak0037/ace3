#!/usr/bin/env bash

#
# generates an icinga alert when an alert storage directory is > 1GB
#
# review the alert data and determine what can be changed so that
# not so much disk space is used
#

cd /opt/ace
source load_environment

find data/$(ace config -v global.node) -maxdepth 2 -mindepth 2 -type d -print0 | du -cs --files0-from=- | sort -nr | sed -e 1d | awk '{ if ($1 > 2000000) { print $0 } }' | grep -v -F -f data/external/analyst-data/large_alert_exclusion > data/var/large_alerts.txt
