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

docker exec -it -u $USER $(bin/get-dev-container.sh) /bin/bash -il
