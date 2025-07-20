#!/usr/bin/env bash

#
# checks the current workload and generates an alert
# if the workload exceeds some threshold
#

source /venv/bin/activate
source load_environment
cd /opt/ace

#
# to tweak this look at the mini awk script
# the $2 variable is the count
#

ace display-workload | sed -ne '/^ -- WORKLOAD/,/^$/ p' | sed -ne '3,$ p' | grep -v '^$' | awk '{ if (($1 == "email" && $2 > 80000) || ($1 == "correlation" && $2 > 150)) { print $0 } }' > data/var/workload.txt 2> /dev/null

# if this has anything in it then we're overloaded
if [ -s data/var/workload.txt ]
then
    mv data/var/workload.txt data/var/ice_analysis_falling_behind.failed
else
    # otherwise we're good
    rm -f data/var/workload.txt data/var/ice_analysis_falling_behind.failed
fi
