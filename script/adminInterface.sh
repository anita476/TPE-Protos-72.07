#!/bin/bash

#just for testing compile the client main.c file
gcc ../src/client/main.c -o client.out



# CLIENT[1] is the app’s stdin; CLIENT[0] is its stdout
# e.g. write "foo" to it with:   echo foo >&"${CLIENT[1]}"
#       read from it with:        read -r line <&"${CLIENT[0]}"

USR=$(dialog --title "Username" --inputbox "Enter your username:" 0 0 3>&1 1>&2 2>&3 3>&-); clear

PASS=$(dialog --title "Password" --clear --insecure --passwordbox "Enter your password:" 0 0 3>&1 1>&2 2>&3 3>&-); clear



if [[ "$USR" != "nep" || "$PASS" != "nep" ]]; then
    dialog --title "Error" --msgbox "Username or password cannot be empty." 0 0
    exit 1
fi
echo $USR
echo $PASS
OPTION=$(dialog --title "Admin Interface" --menu "Choose an option:" 0 0 0 \
    1 "View System Status" \
    2 "Manage Users" \
    3 "Configure Settings" \
    4 "Exit" 3>&1 1>&2 2>&3);
clear
echo $OPTION