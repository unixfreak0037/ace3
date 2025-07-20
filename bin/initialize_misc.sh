#!/usr/bin/env bash

#
# this script is used to initialize the misc directory
#

# install john the ripper
if [ ! -d /opt/misc/john-1.9.0-jumbo-1 ]
then
    echo "building john the ripper"
    cd /opt/misc \
        && git clone https://github.com/openwall/john.git john-1.9.0-jumbo-1 \
        && cd john-1.9.0-jumbo-1/src \
        && ./configure \
        && make -sj
fi
