#!/bin/bash

REPO="https://raw.githubusercontent.com/LunatiX-nc/excorzscriptlunatix/main/"

# Fungsi untuk memeriksa dan mengunduh file
function download_files() {
    wget -q -O /etc/systemd/system/limitvmess.service "${REPO}files/limitvmess.service" && chmod +x /etc/systemd/system/limitvmess.service >/dev/null 2>&1
    wget -q -O /etc/systemd/system/limitvless.service "${REPO}files/limitvless.service" && chmod +x /etc/systemd/system/limitvless.service >/dev/null 2>&1
    wget -q -O /etc/systemd/system/limittrojan.service "${REPO}files/limittrojan.service" && chmod +x /etc/systemd/system/limittrojan.service >/dev/null 2>&1
    wget -q -O /etc/systemd/system/limitshadowsocks.service "${REPO}files/limitshadowsocks.service" && chmod +x /etc/systemd/system/limitshadowsocks.service >/dev/null 2>&1
    wget -q -O /etc/xray/quota-vme "${REPO}files/quota-vme" >/dev/null 2>&1
    wget -q -O /etc/xray/quota-vle "${REPO}files/quota-vle" >/dev/null 2>&1
    wget -q -O /etc/xray/quota-tro "${REPO}files/quota-tro" >/dev/null 2>&1
    wget -q -O /etc/xray/quota-ssr "${REPO}files/quota-ssr" >/dev/null 2>&1

    chmod +x /etc/xray/quota-vme
    chmod +x /etc/xray/quota-vle
    chmod +x /etc/xray/quota-tro
    chmod +x /etc/xray/quota-ssr
}

# Fungsi untuk mengatur layanan pada systemd
function setup_systemd_services() {
    systemctl daemon-reload
    systemctl enable --now limitvmess
    systemctl enable --now limitvless
    systemctl enable --now limittrojan
    systemctl enable --now limitshadowsocks
}

# Fungsi untuk mengatur layanan pada OpenRC
function setup_openrc_services() {
    mv /etc/systemd/system/limitvmess.service /etc/init.d/limitvmess
    mv /etc/systemd/system/limitvless.service /etc/init.d/limitvless
    mv /etc/systemd/system/limittrojan.service /etc/init.d/limittrojan
    mv /etc/systemd/system/limitshadowsocks.service /etc/init.d/limitshadowsocks

    chmod +x /etc/init.d/limitvmess
    chmod +x /etc/init.d/limitvless
    chmod +x /etc/init.d/limittrojan
    chmod +x /etc/init.d/limitshadowsocks

    rc-update add limitvmess default
    rc-update add limitvless default
    rc-update add limittrojan default
    rc-update add limitshadowsocks default

    /etc/init.d/limitvmess start
    /etc/init.d/limitvless start
    /etc/init.d/limittrojan start
    /etc/init.d/limitshadowsocks start
}

# Periksa sistem init (systemd atau OpenRC)
function setup_services() {
    if command -v systemctl &> /dev/null; then
        echo "Menggunakan systemd..."
        setup_systemd_services
    elif command -v rc-update &> /dev/null; then
        echo "Menggunakan OpenRC..."
        setup_openrc_services
    else
        echo "Sistem init tidak dikenal. Harap konfigurasi secara manual."
        exit 1
    fi
}

# Eksekusi langkah-langkah
download_files
setup_services

echo "Konfigurasi selesai!"
