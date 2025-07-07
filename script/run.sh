#!/bin/bash

echo 'Running Protos container'
docker run -p 1080:1080 -v "${PWD}:/root" --privileged --name protos-container -ti tpe-protos-image
