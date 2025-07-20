#!/usr/bin/env bash

#
# drive space hack
#
# some of the systems we're using have very limited drive space
# so we use this hack to prevent ace from breaking the system
# by filling up the drive with analysis data
#

loopback_target_path="$1"
loopback_size="$2"

if [ -z "$loopback_target_path" ]
then
    echo "missing parameters"
    exit 1
fi

if [ -z "$loopback_size" ]
then
    echo "missing parameters"
    exit 1
fi

if [ -e "$loopback_target_path" ]
then
    echo "$loopback_target_path already exists"
    exit 1
fi

TMP_DIR=$(mktemp -d)

touch $loopback_target_path && \
    truncate -s $loopback_size "$loopback_target_path" && \
    mke2fs -t ext4 -F "$loopback_target_path" && \
    mount "$loopback_target_path" "$TMP_DIR" && \
    chown ace:ace "$TMP_DIR" && \
    umount "$TMP_DIR"
