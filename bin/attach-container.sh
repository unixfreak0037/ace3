#!/usr/bin/env bash

USER="ace"
while getopts "u:" opt
do
    case ${opt} in
        u)
            USER="$OPTARG"
            ;;
        *)
            echo "invalid command line option ${opt}"
            exit 1
            ;;
    esac
done
shift $((OPTIND-1))

docker exec -it -u $USER $(docker ps --filter "name=-dev" --format "{{.Names}}" | sort -V | head -n1) /bin/bash -il
