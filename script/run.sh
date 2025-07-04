#!/bin/bash

echo 'Running Protos container'
docker run -p 1080:1080 -v "${PWD}:/root" --privileged -ti tpe-protos-image