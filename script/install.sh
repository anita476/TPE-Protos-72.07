#!/bin/bash

# for libraries needed in linux environment
apt install check --yes # to run tests
apt install ncat --yes # to connect client
apt install iproute2 --yes # to check if server is running
apt install dialog --yes # to run admin interface
apt-get install libncurses-dev --yes
apt-get install libdialog-dev --yes # development headers for dialog
apt-get install libncursesw5-dev --yes # wide character support for ncurses
apt-get install libc6-dev --yes # math library for sqrt function
apt-get install libtinfo-dev --yes # terminal info library
apt-get install libpanel-dev --yes # panel library for ncurses
