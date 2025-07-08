#!/bin/bash

echo 'Running Protos container'
# delete container if it exists
docker rm -f protos-container 2>/dev/null || true && \
docker run -p 1080:1080 -v "${PWD}:/root" --privileged --name protos-container -ti tpe-protos-image bash