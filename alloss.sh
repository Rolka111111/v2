#!/bin/bash

# Fungsi untuk Debian/Ubuntu
install_debian_ubuntu() {
    echo "Deteksi: Debian/Ubuntu"
    apt update -y && apt upgrade -y
    apt install -y wget curl ruby lolcat
    gem install lolcat
    wget -q https://raw.githubusercontent.com/scriptsvpnlt/v2/main/ins.sh
    chmod +x ins.sh
    ./ins.sh
}

# Fungsi untuk Alpine Linux
install_alpine() {
    echo "Deteksi: Alpine Linux"
    apk update && apk upgrade
    apk add --no-cache wget curl ruby ruby-irb
    gem install lolcat
    wget -q https://raw.githubusercontent.com/scriptsvpnlt/v2/main/ins.sh
    chmod +x ins.sh
    ./ins.sh
}

# Deteksi OS
if [ -f /etc/debian_version ]; then
    install_debian_ubuntu
elif [ -f /etc/alpine-release ]; then
    install_alpine
else
    echo "OS tidak dikenali. Harap konfigurasi secara manual."
    exit 1
fi
