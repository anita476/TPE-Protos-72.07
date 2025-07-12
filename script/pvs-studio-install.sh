apt update
apt install wget

wget -q -O - https://files.viva64.com/etc/pubkey.txt | apt-key add -
wget -O /etc/apt/sources.list.d/viva64.list https://files.viva64.com/etc/viva64.list

apt update

apt install pvs-studio

pvs-studio-analyzer credentials "PVS-Studio Free" "FREE-FREE-FREE-FREE"