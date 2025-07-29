#!/usr/bin/env bash

cd /opt/ace && \
    find integrations -type d -maxdepth 1 -mindepth 1 | while read dir
    do
        echo "installing $dir"
        (cd $dir && ./install.sh)
    done
