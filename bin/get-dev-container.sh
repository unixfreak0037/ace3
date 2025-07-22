#!/usr/bin/env bash

docker ps --filter "name=-dev" --format "{{.Names}}" | sort -V | head -n1