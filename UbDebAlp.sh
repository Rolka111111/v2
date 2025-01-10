#!/bin/bash
clear
# -------------------------------
# Universal Installer for Domain Setup
# Supports Debian 10/11/12 & Ubuntu 20/22/24
# -------------------------------

# Data Telegram
TIMES="10"
CHATID="5970831071-1"
KEY="7633327456:AAGE7JpWbJyVly-fcQ8B3S1ctqq-qYOM-1"
URL="https://api.telegram.org/bot$KEY/sendMessage"
TIME=$(date '+%d %b %Y')

# Repo
GIT_USER="Rolka111111"
GIT_REPO="v2"
GIT_BRANCH="main"
REPO="https://raw.githubusercontent.com/${GIT_USER}/${GIT_REPO}/${GIT_BRANCH}/"
REPO_SLOWDNS="https://raw.githubusercontent.com/${GIT_USER}/${GIT_REPO}/${GIT_BRANCH}/"


#set -e  # Stop script on error

# Fungsi untuk cek root
check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Script harus dijalankan sebagai root."
    exit 1
  fi
}

# Fungsi untuk deteksi OS
detect_os() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION_ID=$(echo "$VERSION_ID" | cut -d'.' -f1)
  else
    echo "Tidak dapat mendeteksi sistem operasi."
    exit 1
  fi
}

# Fungsi untuk install dependencies di Debian/Ubuntu
install_dependencies_debian_ubuntu() {
  echo "Memperbarui repository..."
  apt update -y && apt upgrade -y
  apt-get update
  echo "Menginstal dependencies..."
  apt install -y \
    build-essential \
    curl wget git jq
}

# Fungsi untuk install dependencies di Alpine Linux
install_dependencies_alpine() {
  echo "Memperbarui repository..."
  apk update && apk upgrade

  echo "Menginstal dependencies..."
  apk add --no-cache \
    build-base \
    curl wget git jq
}


#function Detect_openVZ() {
#COLOR1="\033[92;1m"
#NC="\033[0m"
# Detect virtualized environment
#if [ "$(systemd-detect-virt)" == "openvz" ]; then
    #echo "OpenVZ is not supported"
    #exit 1
#fi
#}

#Detect_openVZ


# Fungsi utama
main() {
  check_root
  detect_os

  echo -e "\e[92;1mOperating system detected: $OS $VERSION_ID \e[0m"
  if [[ "$OS" == "debian" || "$OS" == "ubuntu" ]]; then
    install_dependencies_debian_ubuntu
  elif [[ "$OS" == "alpine" ]]; then
    install_dependencies_alpine
  else
    echo "Sistem operasi tidak didukung: $OS $VERSION_ID"
    exit 1
  fi

  echo "Instalasi selesai untuk $OS $VERSION_ID."
}

# Jalankan fungsi utama
main


# mkdir -p /etc
# echo "0YejtpvJWrAjoPj-tPfWHJbPv0nd108oHOZv-UGj" > /etc/cloudflare.key
# echo "mezzqueen293@gmail.com" > /etc/cloudflare.email
# chmod 600 /etc/cloudflare.key /etc/cloudflare.email


# ip
Ip_Vps=$(curl -sS ipv4.icanhazip.com)
#set -euo pipefail

# Deteksi IP Publik
IP=$(hostname -I | awk '{print $1}')

# Buat direktori yang diperlukan
mkdir -p /etc/xray /var/lib/LT /var/log/xray
chown www-data:www-data /var/log/xray
chmod 755 /var/log/xray
touch /var/log/xray/access.log /var/log/xray/error.log

# Variabel untuk Cloudflare API
#CF_KEY=$(cat /etc/cloudflare.key)  # Simpan API Key di file ini
#CF_ID=$(cat /etc/cloudflare.email)  # Simpan Email Cloudflare di file ini
function pasang_domain() {
clear
echo -e "   \e[97;1m ===========================================\e[0m"
echo -e "   \e[1;32m    Please Select a Domain bellow type.     \e[0m"
echo -e "   \e[97;1m ===========================================\e[0m"
echo -e "   \e[1;32m  1). \e[97;1m Domain Pribadi \e[0m"
echo -e "   \e[1;32m  2). \e[97;1m Domain Random  \e[0m"
echo -e "   \e[97;1m ===========================================\e[0m"
echo -e ""
read -p "   Just Input a number [1-2]:   " host
echo ""
if [[ $host == "1" ]]; then
clear
echo -e "   \e[97;1m ===========================================\e[0m"
echo -e "   \e[97;1m             INPUT YOUR DOMAIN              \e[0m"
echo -e "   \e[97;1m ===========================================\e[0m"
echo -e ""
read -p "   input your domain :   " host1
echo "IP=" >> /var/lib/LT/ipvps.conf
echo $host1 > /etc/xray/domain
echo $host1 > /root/domain
echo ""
elif [[ $host == "2" ]]; then
wget ${REPO}files/cf.sh && chmod +x cf.sh && ./cf.sh
rm -f /root/cf.sh
clear
else
print_install "Random Subdomain/Domain is Used"
clear
fi
}
pasang_domain


function DETECTED() {
# Define necessary variables
export IP=$(curl -sS icanhazip.com || echo "0.0.0.0")
Ip_Vps=$(curl -sS ipv4.icanhazip.com || echo "0.0.0.0")

# Mengambil data berdasarkan IP VPS
data=$(curl -s https://raw.githubusercontent.com/${GIT_USER}/vps_access/main/ip | grep "$Ip_Vps")

# Memisahkan kolom
username=$(echo "$data" | awk '{print $2}') # Nama pengguna
exp=$(echo "$data" | awk '{print $3}')      # Tanggal kedaluwarsa (kolom kedua)
ip=$(echo "$data" | awk '{print $4}')       # IP VPS

# Save public IP to /etc/xray/ipvps
curl -s ifconfig.me > /etc/xray/ipvps

# Create necessary directories
mkdir -p /var/lib/LT >/dev/null 2>&1

# Export additional variables
export tanggal=$(date -d "0 days" +"%d-%m-%Y - %X")
export OS_Name=$(grep -w PRETTY_NAME /etc/os-release | sed 's/PRETTY_NAME=//g' | tr -d '"')
export Kernel=$(uname -r)
export Arch=$(uname -m)
export IP=$(curl -s https://ipinfo.io/ip/)

}

DETECTED

clear
# Fungsi warna
red() { echo -e "\\033[31;1m${*}\\033[0m"; }
green() { echo -e "\\033[32;1m${*}\\033[0m"; }

# Fungsi animasi loading
fun_bar() {
    local cmd="$1"
    local delay=0.1
    local symbols=(
        "⠋"
        "⠙"
        "⠹"
        "⠸"
        "⠼"
        "⠴"
        "⠦"
        "⠧"
        "⠇"
        "⠏"
    )
    local spin_length=${#symbols[@]}

    # Jalankan perintah di latar belakang
    (${cmd}) >/dev/null 2>&1 &
    local pid=$!

    # Tampilkan animasi loading
    echo -ne "\033[92;1m[ PROCESSING ]\033[0m - \033[33;1m["
    tput civis  # Sembunyikan kursor
    while kill -0 $pid 2>/dev/null; do
        for ((i = 0; i < spin_length; i++)); do
            echo -ne "${symbols[i]}"
            sleep $delay
            echo -ne "\b"
        done
    done
    echo -ne "]\033[1;32m - DONE!\033[0m\n"
    tput cnorm  # Tampilkan kembali kursor
}

# Fungsi dummy untuk demonstrasi
base_package() {
  clear
  echo "Menginstal paket dasar..."

  # Deteksi OS dan Versi
  source /etc/os-release
  OS=$ID
  VER=$VERSION_ID
  PRETTY_NAME=$PRETTY_NAME

  if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
    # Instalasi paket-paket umum
    apt install -y \
      zip pwgen openssl netcat socat cron bash-completion figlet bmon \
      ntpdate sudo debconf-utils vnstat libnss3-dev libnspr4-dev pkg-config \
      libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev \
      flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev \
      libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl build-essential \
      gcc g++ python htop lsof tar ruby zip unzip p7zip-full \
      python3-pip libc6 util-linux msmtp-mta ca-certificates bsd-mailx iptables \
      iptables-persistent netfilter-persistent net-tools gnupg gnupg2 \
      lsb-release shc cmake git screen xz-utils apt-transport-https dnsutils \
      openvpn easy-rsa chrony speedtest-cli

    # Hapus paket yang tidak diperlukan
    echo "Menghapus paket yang tidak diperlukan..."
    apt remove --purge -y exim4 ufw firewalld
    apt autoremove -y
    apt clean all

    # Konfigurasi iptables-persistent
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

    # Sinkronisasi waktu
    echo "Sinkronisasi waktu..."
    systemctl enable chronyd || systemctl enable chrony
    systemctl restart chronyd || systemctl restart chrony
    ntpdate pool.ntp.org
    chronyc sourcestats -v || true
    chronyc tracking -v || true

  elif [[ "$OS" == "alpine" ]]; then

    # Instalasi paket-paket umum
    apk add --no-cache \
      zip pwgen openssl netcat-openbsd socat cron bash-completion figlet bmon \
      ntp sudo vnstat libnss libcap-ng flex bison make bc rsyslog \
      dos2unix zlib libressl-dev sqlite sed perl build-base gcc g++ \
      python3 htop lsof tar ruby zip unzip p7zip python3-pip libc6-compat \
      util-linux msmtp ca-certificates mailx iptables ip6tables ebtables \
      nftables iproute2 screen xz dnsutils openvpn chrony speedtest-cli

    # Sinkronisasi waktu
    echo "Sinkronisasi waktu..."
    rc-update add chronyd
    rc-service chronyd restart
    chronyc sourcestats -v || true
    chronyc tracking -v || true

  else
    echo "Sistem Operasi tidak didukung: $PRETTY_NAME"
    exit 1
  fi

  echo "Instalasi paket dasar selesai untuk $PRETTY_NAME."
}
    first_setup() {
    timedatectl set-timezone Asia/Jakarta
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

    # Deteksi OS dan Versi
    OS_ID=$(grep -w ID /etc/os-release | cut -d= -f2 | tr -d '"')
    OS_VERSION=$(grep -w VERSION_ID /etc/os-release | cut -d= -f2 | tr -d '"')
    OS_NAME=$(grep -w PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')

    echo "Detected OS: $OS_NAME"

    if [[ "$OS_ID" == "ubuntu" ]]; then
        # Ubuntu
        echo "Setting up HAProxy for Ubuntu $OS_VERSION"
        apt-get install -y --no-install-recommends software-properties-common

        if [[ "$OS_VERSION" == "20.04" ]]; then
            add-apt-repository ppa:vbernat/haproxy-2.0 -y
            apt-get install -y haproxy=2.0.\*
        elif [[ "$OS_VERSION" == "22.04" ]]; then
            add-apt-repository ppa:vbernat/haproxy-2.4 -y
            apt-get install -y haproxy=2.4.\*
        elif [[ "$OS_VERSION" == "24.04" ]]; then
            add-apt-repository ppa:vbernat/haproxy-2.6 -y
            apt-get install -y haproxy=2.6.\*
        else
            echo "Ubuntu $OS_VERSION is not supported."
            exit 1
        fi

    elif [[ "$OS_ID" == "debian" ]]; then
        # Debian
        echo "Setting up HAProxy for Debian $OS_VERSION"
        curl -fsSL https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg

        if [[ "$OS_VERSION" == "10" ]]; then
            echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net buster-backports-1.8 main" \
                >/etc/apt/sources.list.d/haproxy.list
            apt-get install -y haproxy=1.8.\*
        elif [[ "$OS_VERSION" == "11" ]]; then
            echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net bullseye-backports-2.4 main" \
                >/etc/apt/sources.list.d/haproxy.list
            apt-get install -y haproxy=2.4.\*
        elif [[ "$OS_VERSION" == "12" ]]; then
            echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net bookworm-backports-2.6 main" \
                >/etc/apt/sources.list.d/haproxy.list
            apt-get install -y haproxy=2.6.\*
        else
            echo "Debian $OS_VERSION is not supported."
            exit 1
        fi

    elif [[ "$OS_ID" == "alpine" ]]; then
        # Alpine Linux
        echo "Setting up HAProxy for Alpine Linux"
        apk add haproxy
        echo "HAProxy installed successfully on Alpine Linux."

    else
        # OS Tidak Didukung
        echo "Your OS ($OS_NAME) is not supported."
        exit 1
    fi
}

    pasang_ssl() {
  clear

  # Hapus sertifikat lama jika ada
  rm -rf /etc/xray/xray.key /etc/xray/xray.crt

  # Ambil nama domain dari file
  domain=$(cat /etc/xray/domain 2>/dev/null || echo "")
  if [[ -z "$domain" ]]; then
    echo "Domain tidak ditemukan! Pastikan file /etc/xray/domain ada dan berisi domain."
    exit 1
  fi

  # Deteksi OS dan layanan web
  source /etc/os-release
  OS=$ID
  STOPWEBSERVER=$(lsof -i:80 | awk 'NR==2 {print $1}')

  # Hentikan layanan yang menggunakan port 80
  if [[ ! -z "$STOPWEBSERVER" ]]; then
    echo "Menghentikan layanan yang menggunakan port 80: $STOPWEBSERVER..."
    pkill -f $STOPWEBSERVER || systemctl stop $STOPWEBSERVER || true
  fi

  # Hentikan nginx jika ada
  if [[ "$OS" == "debian" || "$OS" == "ubuntu" ]]; then
    systemctl stop nginx || true
  elif [[ "$OS" == "alpine" ]]; then
    service nginx stop || true
  fi

  # Persiapkan direktori untuk ACME.sh
  rm -rf /root/.acme.sh
  mkdir -p /root/.acme.sh

  # Unduh ACME.sh
  echo "Mengunduh ACME.sh..."
  curl -s https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
  chmod +x /root/.acme.sh/acme.sh

  # Upgrade ACME.sh
  echo "Upgrade ACME.sh..."
  /root/.acme.sh/acme.sh --upgrade --auto-upgrade

  # Set server default ke Let's Encrypt
  echo "Set ACME server ke Let's Encrypt..."
  /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt

  # Terbitkan sertifikat SSL
  echo "Menerbitkan sertifikat SSL untuk domain: $domain..."
  /root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256

  # Instal sertifikat ke lokasi yang diinginkan
  echo "Menginstal sertifikat SSL..."
  /root/.acme.sh/acme.sh --installcert -d "$domain" \
    --fullchainpath /etc/xray/xray.crt \
    --keypath /etc/xray/xray.key \
    --ecc

  # Set izin untuk file sertifikat
  chmod 600 /etc/xray/xray.key /etc/xray/xray.crt

  echo "Sertifikat SSL berhasil dipasang untuk $domain"

  # Mulai ulang layanan nginx jika ada
  if [[ "$OS" == "debian" || "$OS" == "ubuntu" ]]; then
    systemctl restart nginx || true
  elif [[ "$OS" == "alpine" ]]; then
    service nginx restart || true
  fi
}
    nginx_initial_setup() {
  echo "Mengatur konfigurasi dasar Nginx..."

  # Direktori konfigurasi Nginx
  CONFIG_DIR="/etc/nginx/sites-available"
  LINK_DIR="/etc/nginx/sites-enabled"
  DEFAULT_CONF="/etc/nginx/nginx.conf"

  # Buat direktori jika belum ada (untuk Debian/Ubuntu)
  if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
    mkdir -p "$CONFIG_DIR" "$LINK_DIR"

    # Tambahkan konfigurasi dasar
    cat > "$CONFIG_DIR/default" <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    server_name _;

    root /var/www/html;
    index index.html index.htm;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
    ln -sf "$CONFIG_DIR/default" "$LINK_DIR/default"

  elif [[ "$OS" == "alpine" ]]; then
    # Konfigurasi dasar untuk Alpine Linux
    mkdir -p /etc/nginx/http.d
    cat > /etc/nginx/http.d/default.conf <<EOF
server {
    listen 80 default_server;
    server_name _;

    root /var/www/html;
    index index.html index.htm;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
  fi

  # Test konfigurasi dan restart Nginx
  nginx -t || { echo "Konfigurasi Nginx gagal. Periksa file konfigurasi."; exit 1; }
  systemctl restart nginx || rc-service nginx restart
  echo "Nginx berhasil dikonfigurasi dan dijalankan."
}
   nginx_install() {
  # Deteksi OS dan Versi
  source /etc/os-release
  OS=$ID
  VER=$VERSION_ID
  PRETTY_NAME=$PRETTY_NAME

  echo "Setup Nginx untuk OS: $PRETTY_NAME"

  if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
    # Instalasi untuk Ubuntu/Debian
    apt update -y
    apt install -y nginx
    echo "Nginx berhasil diinstal untuk $PRETTY_NAME"
    
  elif [[ "$OS" == "alpine" ]]; then
    # Instalasi untuk Alpine Linux
    apk update
    apk add --no-cache nginx
    echo "Nginx berhasil diinstal untuk $PRETTY_NAME"
    
    # Pastikan direktori log tersedia di Alpine
    mkdir -p /var/log/nginx
    touch /var/log/nginx/access.log /var/log/nginx/error.log
    
  else
    echo -e "Sistem Operasi tidak didukung: $PRETTY_NAME"
    exit 1
  fi

  # Konfigurasi dasar dan pengaktifan Nginx
  nginx_initial_setup
}

  make_folder_xray() {
  echo "Memulai konfigurasi folder Xray..."

  # Hapus file database lama jika ada
  rm -rf /etc/lunatic/{vmess/.vmess.db,vless/.vless.db,trojan/.trojan.db,shadowsocks/.shadowsocks.db,ssh/.ssh.db,bot/.bot.db}

  # Buat direktori utama
  mkdir -p /etc/lunatic \
           /etc/limit \
           /usr/bin/xray \
           /var/log/xray \
           /var/www/html \
           /usr/sbin/local \
           /usr/local/sbin

  # Buat direktori khusus layanan
  for service in vmess vless trojan shadowsocks ssh; do
    mkdir -p /etc/lunatic/$service/{ip,detail,usage}
  done

  # Direktori tambahan untuk bot dan fitur lainnya
  mkdir -p /etc/lunatic/bot/{telegram,notif}
  mkdir -p /etc/lunatic/noobzvpns/detail

  # Set izin untuk direktori log
  chmod -R 755 /var/log/xray

  # Buat file penting
  touch /etc/xray/domain \
        /var/log/xray/{access.log,error.log} \
        /etc/lunatic/{vmess/.vmess.db,vless/.vless.db,trojan/.trojan.db,shadowsocks/.shadowsocks.db,ssh/.ssh.db,bot/.bot.db,noobzvpns/.noobzvpns.db} \
        /etc/lunatic/bot/notif/{key,id}

  # Isi file database dengan template awal
  for db in vmess vless trojan shadowsocks ssh noobzvpns; do
    if [[ ! -f /etc/lunatic/$db/.${db}.db ]]; then
      echo "& plughin Account" > /etc/lunatic/$db/.${db}.db
    fi
  done

  echo "Folder Xray berhasil dikonfigurasi."
}

  install_xray() {
clear
echo " install xray core "
       domainSock_dir="/run/xray";! [ -d $domainSock_dir ] && mkdir  $domainSock_dir
   chown www-data.www-data $domainSock_dir
       latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
   bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version $latest_version
   wget -O /etc/xray/config.json "${REPO}cfg_conf_js/config.json" >/dev/null 2>&1
   wget -O /etc/systemd/system/runn.service "${REPO}files/runn.service" >/dev/null 2>&1
      domain=$(cat /etc/xray/domain)
      IPVS=$(cat /etc/xray/ipvps)
   echo " install "
   clear
   curl -s ipinfo.io/city >>/etc/xray/city
   curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp
   wget -O /etc/haproxy/haproxy.cfg "${REPO}cfg_conf_js/haproxy.cfg" >/dev/null 2>&1
   wget -O /etc/nginx/conf.d/xray.conf "${REPO}cfg_conf_js/xray.conf" >/dev/null 2>&1
   sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
   sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
   curl ${REPO}cfg_conf_js/nginx.conf > /etc/nginx/nginx.conf
   cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem
   chmod +x /etc/systemd/system/runn.service
   rm -rf /etc/systemd/system/xray.service.d

# xray service
cat >/etc/systemd/system/xray.service <<EOF
Description=Xray Service
Documentation=https://github.com
After=network.target nss-lookup.target
[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
filesNPROC=10000
filesNOFILE=1000000
[Install]
WantedBy=multi-user.target
EOF
echo " berhasil "
}

  pasang_ssh() {
  clear
  # Unduh dan atur file password PAM
  wget -O /etc/pam.d/common-password "${REPO}files/password" >/dev/null 2>&1
  chmod +x /etc/pam.d/common-password

  # Menyesuaikan cara untuk berbagai distribusi OS
  if [[ -f /etc/debian_version ]]; then
    # Konfigurasi keyboard layout untuk Debian/Ubuntu
    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/compose select No compose key"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string us"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English (US)"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English (US)"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/switch select No temporary switch"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/toggle select No toggling"
  elif [[ -f /etc/alpine-release ]]; then
    # Konfigurasi keyboard layout untuk Alpine
    apk add --no-cache kbd
    setup-keymap -k us
    rc-update add keymaps
  else
    echo "OS tidak dikenal atau tidak didukung untuk konfigurasi keyboard."
    exit 1
  fi

  # Atur rc-local service
  cat > /etc/systemd/system/rc-local.service <<-EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF

  # Buat file rc.local jika belum ada
  if [ ! -f /etc/rc.local ]; then
    cat > /etc/rc.local <<-EOF
#!/bin/bash
exit 0
EOF
    chmod +x /etc/rc.local
  fi

  # Aktifkan rc-local service
  systemctl enable rc-local
  systemctl start rc-local.service

  # Nonaktifkan IPv6
  echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
  if ! grep -q "disable_ipv6" /etc/rc.local; then
    sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
  fi

  # Atur zona waktu ke Asia/Jakarta
  ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

  # Nonaktifkan AcceptEnv pada konfigurasi SSH untuk keamanan
  sed -i 's/^AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

  # Restart SSH service agar perubahan diterapkan
  systemctl restart ssh
}

  udp_mini(){
  clear

  # Unduh dan atur file script limit-quota.sh
  wget raw.githubusercontent.com/${GIT_USER}/${GIT_REPO}/${GIT_BRANCH}/files/limit-quota.sh && chmod +x limit-quota.sh && ./limit-quota.sh

  # Unduh dan atur file script lock-service.sh
  wget raw.githubusercontent.com/${GIT_USER}/${GIT_REPO}/${GIT_BRANCH}/files/lock-service.sh && chmod +x lock-service.sh && ./lock-service.sh

  # Membuat direktori dan mengunduh script limit-ip
  mkdir -p /usr/bin/limit-ip
  wget -q -O /usr/bin/limit-ip "${REPO}files/limit-ip"
  chmod +x /usr/bin/*
  sed -i 's/\r//' /usr/bin/limit-ip

  # Membuat layanan systemd untuk limit-ip
  cat >/etc/systemd/system/vmip.service << EOF
[Unit]
Description=My
After=network.target
[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/limit-ip vmip
Restart=always
[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl restart vmip
  systemctl enable vmip

  cat >/etc/systemd/system/vlip.service << EOF
[Unit]
Description=My
After=network.target
[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/limit-ip vlip
Restart=always
[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl restart vlip
  systemctl enable vlip

  cat >/etc/systemd/system/trip.service << EOF
[Unit]
Description=My
After=network.target
[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/limit-ip trip
Restart=always
[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl restart trip
  systemctl enable trip

  cat >/etc/systemd/system/ssip.service << EOF
[Unit]
Description=My
After=network.target
[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/limit-ip ssip
Restart=always
[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl restart ssip
  systemctl enable ssip

  # Membuat direktori dan mengunduh udp-mini
  mkdir -p /usr/lunatic/
  wget -q -O /usr/lunatic/udp-mini "${REPO}files/udp-mini"
  chmod +x /usr/lunatic/udp-mini

  # Mengunduh file service systemd untuk udp-mini
  wget -q -O /etc/systemd/system/udp-mini-1.service "${REPO}files/udp-mini-1.service"
  wget -q -O /etc/systemd/system/udp-mini-2.service "${REPO}files/udp-mini-2.service"
  wget -q -O /etc/systemd/system/udp-mini-3.service "${REPO}files/udp-mini-3.service"

  # Menonaktifkan dan menghentikan service udp-mini
  systemctl disable udp-mini-1
  systemctl stop udp-mini-1
  systemctl enable udp-mini-1
  systemctl start udp-mini-1

  systemctl disable udp-mini-2
  systemctl stop udp-mini-2
  systemctl enable udp-mini-2
  systemctl start udp-mini-2

  systemctl disable udp-mini-3
  systemctl stop udp-mini-3
  systemctl enable udp-mini-3
  systemctl start udp-mini-3
}

  ins_SSHD() {
  clear
  echo "Configuring SSH Daemon..."

  # Unduh konfigurasi sshd
  wget -q -O /etc/ssh/sshd_config "${REPO}files/sshd" >/dev/null 2>&1

  # Pastikan file berhasil diunduh
  if [[ -f /etc/ssh/sshd_config ]]; then
    chmod 600 /etc/ssh/sshd_config  # Tingkatkan keamanan file

    # Restart SSH service
    if systemctl is-active --quiet ssh; then
      systemctl restart ssh
    else
      # Jika tidak ada systemd (misalnya di Alpine), restart SSH menggunakan service
      if command -v service >/dev/null 2>&1; then
        service ssh restart
      fi
    fi

    # Menampilkan status SSH service
    systemctl status ssh --no-pager || service ssh status
    echo "SSHD configuration updated successfully."
  else
    echo "Failed to update SSHD configuration. Please check your repository URL."
  fi
}

  ins_dropbear() {
  clear
  echo "Installing and Configuring Dropbear..."

  # Install dropbear (Menyesuaikan dengan distribusi OS)
  if [[ -f /etc/debian_version || -f /etc/lsb-release ]]; then
    # Debian/Ubuntu (menggunakan apt)
    apt-get update
    apt-get install -y dropbear >/dev/null 2>&1
  elif [[ -f /etc/alpine-release ]]; then
    # Alpine Linux (menggunakan apk)
    apk update
    apk add dropbear >/dev/null 2>&1
  else
    echo "Unsupported OS. Unable to install Dropbear."
    exit 1
  fi

  # Unduh konfigurasi dropbear
  wget -q -O /etc/default/dropbear "${REPO}cfg_conf_js/dropbear.conf" >/dev/null 2>&1

  # Pastikan file berhasil diunduh
  if [[ -f /etc/default/dropbear ]]; then
    chmod 600 /etc/default/dropbear  # Tingkatkan keamanan file

    # Restart Dropbear service sesuai dengan sistem manajer layanan
    if systemctl is-active --quiet dropbear; then
      systemctl restart dropbear
      systemctl status dropbear --no-pager
    else
      # Untuk Alpine, menggunakan openrc atau service jika systemd tidak ada
      if command -v service >/dev/null 2>&1; then
        service dropbear restart
        service dropbear status
      elif command -v rc-service >/dev/null 2>&1; then
        rc-service dropbear restart
        rc-service dropbear status
      else
        echo "Failed to restart Dropbear service. Unsupported service manager."
        exit 1
      fi
    fi

    echo "Dropbear installed and configured successfully."
  else
    echo "Failed to configure Dropbear. Please check your repository URL."
  fi
}

  ins_vnstat() {
  clear
  echo "Installing vnStat..."

  # Menangani instalasi paket dasar berdasarkan distribusi OS
  if [[ -f /etc/debian_version || -f /etc/lsb-release ]]; then
    # Debian/Ubuntu
    apt-get update
    apt-get install -y vnstat libsqlite3-dev >/dev/null 2>&1
  elif [[ -f /etc/alpine-release ]]; then
    # Alpine Linux
    apk update
    apk add vnstat sqlite-dev >/dev/null 2>&1
  else
    echo "Unsupported OS. Unable to install vnStat."
    exit 1
  fi

  # Unduh dan pasang vnStat versi terbaru
  VNSTAT_VERSION="2.6"
  wget -q https://humdi.net/vnstat/vnstat-${VNSTAT_VERSION}.tar.gz
  if [[ -f vnstat-${VNSTAT_VERSION}.tar.gz ]]; then
    tar zxvf vnstat-${VNSTAT_VERSION}.tar.gz >/dev/null 2>&1
    cd vnstat-${VNSTAT_VERSION}
    ./configure --prefix=/usr --sysconfdir=/etc >/dev/null 2>&1 && make >/dev/null 2>&1 && make install >/dev/null 2>&1
    cd ..
    rm -rf vnstat-${VNSTAT_VERSION} vnstat-${VNSTAT_VERSION}.tar.gz
  else
    echo "Failed to download vnStat source. Please check your network or URL."
    return 1
  fi

  # Konfigurasi vnStat
  if [[ -z "$NET" ]]; then
    NET="eth0"
  fi

  vnstat -u -i "$NET"
  sed -i "s/Interface \"eth0\"/Interface \"$NET\"/g" /etc/vnstat.conf
  chown vnstat:vnstat /var/lib/vnstat -R

  # Restart dan aktifkan layanan berdasarkan distribusi
  if [[ -f /etc/debian_version || -f /etc/lsb-release ]]; then
    # Debian/Ubuntu menggunakan systemd
    systemctl enable vnstat >/dev/null 2>&1
    systemctl restart vnstat >/dev/null 2>&1
    systemctl status vnstat --no-pager
  elif [[ -f /etc/alpine-release ]]; then
    # Alpine menggunakan OpenRC
    rc-update add vnstat default
    rc-service vnstat restart
    rc-service vnstat status
  else
    echo "Failed to manage vnStat service. Unsupported service manager."
    exit 1
  fi

  echo "vnStat installation completed successfully."
}

  ins_openvpn() {
  clear
  echo "Installing OpenVPN..."

  # Menangani instalasi OpenVPN berdasarkan distribusi OS
  if [[ -f /etc/debian_version || -f /etc/lsb-release ]]; then
    # Debian/Ubuntu
    apt-get update
    apt-get install -y openvpn openvpn3 -y >/dev/null 2>&1
  elif [[ -f /etc/alpine-release ]]; then
    # Alpine Linux
    apk update
    apk add openvpn3 openvpn3-cli >/dev/null 2>&1
  else
    echo "Unsupported OS. Unable to install OpenVPN."
    exit 1
  fi

  # Unduh dan jalankan installer OpenVPN jika diperlukan (jika menggunakan custom script)
  wget -q -O /tmp/openvpn-install.sh "${REPO}files/openvpn"
  if [[ -f /tmp/openvpn-install.sh ]]; then
    chmod +x /tmp/openvpn-install.sh
    bash /tmp/openvpn-install.sh
    systemctl restart openvpn >/dev/null 2>&1
    systemctl status openvpn --no-pager
    echo "OpenVPN installation completed successfully."
  else
    echo "Failed to download OpenVPN installer. Please check your repository URL."
    return 1
  fi

  # Bersihkan file sementara
  rm -f /tmp/openvpn-install.sh

  # Mengonfigurasi dan mengaktifkan OpenVPN service
  if [[ -f /etc/debian_version || -f /etc/lsb-release ]]; then
    # Debian/Ubuntu menggunakan systemd
    systemctl enable openvpn >/dev/null 2>&1
    systemctl restart openvpn >/dev/null 2>&1
    systemctl status openvpn --no-pager
  elif [[ -f /etc/alpine-release ]]; then
    # Alpine menggunakan OpenRC
    rc-update add openvpn default
    rc-service openvpn restart
    rc-service openvpn status
  else
    echo "Failed to manage OpenVPN service. Unsupported service manager."
    exit 1
  fi

  echo "OpenVPN installation completed successfully."
}

  ins_backup() {
  clear
  echo "Installing backup tools..."

  # Menangani instalasi rclone berdasarkan OS
  if [[ -f /etc/debian_version || -f /etc/lsb-release ]]; then
    # Debian/Ubuntu
    apt-get update
    apt-get install rclone msmtp-mta ca-certificates bsd-mailx git -y >/dev/null 2>&1
  elif [[ -f /etc/alpine-release ]]; then
    # Alpine
    apk update
    apk add rclone msmtp ca-certificates mailx git make gcc g++ libc-dev -y >/dev/null 2>&1
  else
    echo "Unsupported OS. Unable to install rclone and other tools."
    exit 1
  fi

  # Konfigurasi rclone dengan file konfigurasi dari repository
  printf "q\n" | rclone config
  wget -q -O /root/.config/rclone/rclone.conf "${REPO}cfg_conf_js/rclone.conf"
  if [[ $? -ne 0 ]]; then
    echo "Failed to download rclone configuration."
    return 1
  fi

  # Install wondershaper untuk pembatasan bandwidth
  cd /bin
  # git clone https://github.com/LunaticTunnel/wondershaper.git >/dev/null 2>&1
  git clone  https://github.com/magnific0/wondershaper.git >/dev/null 2>&1
  cd wondershaper
  sudo make install >/dev/null 2>&1
  cd
  rm -rf wondershaper

  # Konfigurasi msmtp untuk pengiriman email
  cat <<EOF > /etc/msmtprc
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
account default
host smtp.gmail.com
port 587
auth on
user oceantestdigital@gmail.com
from oceantestdigital@gmail.com
password jokerman77
logfile ~/.msmtp.log
EOF

  # Atur kepemilikan file msmtp
  chown -R www-data:www-data /etc/msmtprc

  # Unduh dan jalankan script untuk IP server
  wget -q -O /etc/ipserver "${REPO}files/ipserver"
  if [[ -f /etc/ipserver ]]; then
    bash /etc/ipserver
  else
    echo "Failed to download the IP server script."
    return 1
  fi

  echo "Backup tools installation completed successfully."
}

  ins_swab() {
  clear
  echo "Installing Gotop and configuring swap..."

  # Mendapatkan versi terbaru dari Gotop
  gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
  gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v$gotop_latest_linux_amd64.deb"

  # Instalasi Gotop bergantung pada OS
  if [[ -f /etc/debian_version || -f /etc/lsb-release ]]; then
    # Debian/Ubuntu
    curl -sL "$gotop_link" -o /tmp/gotop.deb
    if [[ $? -ne 0 ]]; then
      echo "Failed to download Gotop."
      return 1
    fi
    dpkg -i /tmp/gotop.deb >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
      echo "Failed to install Gotop."
      return 1
    fi
  elif [[ -f /etc/alpine-release ]]; then
    # Alpine
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v$gotop_latest_linux_amd64.tar.gz"
    curl -sL "$gotop_link" -o /tmp/gotop.tar.gz
    if [[ $? -ne 0 ]]; then
      echo "Failed to download Gotop."
      return 1
    fi
    tar -xzf /tmp/gotop.tar.gz -C /usr/local/bin
  else
    echo "Unsupported OS. Unable to install Gotop."
    return 1
  fi

  # Membuat dan mengaktifkan swap file
  if [[ ! -f /swapfile ]]; then
    dd if=/dev/zero of=/swapfile bs=1024 count=1048576
    mkswap /swapfile
    chown root:root /swapfile
    chmod 0600 /swapfile >/dev/null 2>&1
    swapon /swapfile >/dev/null 2>&1

    # Menambahkan swap file ke /etc/fstab untuk persistensi
    echo "/swapfile      swap    swap    defaults    0 0" >> /etc/fstab
  else
    echo "Swap file already exists."
  fi

  # Menyinkronkan waktu dengan NTP server
  if [[ -f /etc/debian_version || -f /etc/lsb-release ]]; then
    # Debian/Ubuntu
    apt-get install chrony -y >/dev/null 2>&1
    systemctl enable chrony
    systemctl start chrony
  elif [[ -f /etc/alpine-release ]]; then
    # Alpine
    apk add chrony -y >/dev/null 2>&1
    rc-update add chronyd default
    service chronyd start
  else
    echo "Unable to install and configure chrony. NTP sync skipped."
  fi

  # Menginstal dan menjalankan BBR (TCP Congestion Control)
  wget ${REPO}files/bbr.sh && chmod +x bbr.sh && ./bbr.sh
  if [[ $? -ne 0 ]]; then
    echo "Failed to run BBR script."
    return 1
  fi

  echo "Gotop installed and swap file configured successfully."
}

 ins_Fail2ban() {
  clear
  echo "Installing Fail2ban and configuring SSH banner..."

  # Mengecek apakah Fail2ban sudah terinstal sebelumnya
  if command -v fail2ban-client >/dev/null 2>&1; then
    echo "Fail2ban is already installed."
  else
    # Instalasi Fail2ban bergantung pada OS
    if [[ -f /etc/debian_version || -f /etc/lsb-release ]]; then
      # Debian/Ubuntu
      apt-get update
      apt-get install fail2ban -y >/dev/null 2>&1
      if [[ $? -ne 0 ]]; then
        echo "Failed to install Fail2ban."
        return 1
      fi
    elif [[ -f /etc/alpine-release ]]; then
      # Alpine
      apk update
      apk add fail2ban >/dev/null 2>&1
      if [[ $? -ne 0 ]]; then
        echo "Failed to install Fail2ban."
        return 1
      fi
    else
      echo "Unsupported OS. Unable to install Fail2ban."
      return 1
    fi
  fi

  # Mengecek jika direktori /usr/local/ddos ada, jika ada minta uninstall
  if [ -d '/usr/local/ddos' ]; then
    echo "Please uninstall the previous version first."
    return 1
  else
    mkdir /usr/local/ddos
  fi

  # Menambahkan banner SSH untuk login
  echo "Banner /etc/banner.txt" >> /etc/ssh/sshd_config
  sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/banner.txt"@g' /etc/default/dropbear

  # Mengunduh dan mengonfigurasi banner
  wget -q -O /etc/banner.txt "${REPO}banner/issue.net"
  if [[ $? -ne 0 ]]; then
    echo "Failed to download the banner file."
    return 1
  fi

  # Mengaktifkan Fail2ban dan SSH
  systemctl restart ssh
  systemctl enable fail2ban
  systemctl start fail2ban

  # Mengonfigurasi Fail2ban
  systemctl status fail2ban --no-pager
  echo "Fail2ban installed and SSH banner configured successfully."
}

  ins_epro(){
  clear
  echo "Installing Epro and configuring services..."

  # Mengunduh file ws dan tun.conf
  wget -O /usr/bin/ws "${REPO}files/ws" >/dev/null 2>&1
  if [[ $? -ne 0 ]]; then
    echo "Failed to download ws script."
    return 1
  fi

  wget -O /usr/bin/tun.conf "${REPO}cfg_conf_js/tun.conf" >/dev/null 2>&1
  if [[ $? -ne 0 ]]; then
    echo "Failed to download tun.conf."
    return 1
  fi

  # Mengunduh dan mengatur file ws.service
  wget -O /etc/systemd/system/ws.service "${REPO}files/ws.service" >/dev/null 2>&1
  if [[ $? -ne 0 ]]; then
    echo "Failed to download ws.service."
    return 1
  fi
  chmod +x /etc/systemd/system/ws.service
  chmod +x /usr/bin/ws
  chmod 644 /usr/bin/tun.conf

  # Mengatur layanan ws untuk dijalankan saat startup dan memulai layanan
  systemctl disable ws
  systemctl stop ws
  systemctl enable ws
  systemctl start ws
  systemctl restart ws

  # Mengunduh geosite.dat dan geoip.dat untuk Xray
  wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
  if [[ $? -ne 0 ]]; then
    echo "Failed to download geosite.dat."
    return 1
  fi
  wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1
  if [[ $? -ne 0 ]]; then
    echo "Failed to download geoip.dat."
    return 1
  fi

  # Mengunduh file ftvpn dan memberi hak akses eksekusi
  wget -O /usr/sbin/ftvpn "${REPO}files/ftvpn" >/dev/null 2>&1
  if [[ $? -ne 0 ]]; then
    echo "Failed to download ftvpn."
    return 1
  fi
  chmod +x /usr/sbin/ftvpn

  # Menambahkan aturan iptables untuk memblokir lalu lintas torrent
  iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
  iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
  iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
  iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
  iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
  iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
  iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
  iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
  iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
  iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
  iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
  iptables-save > /etc/iptables.up.rules
  iptables-restore -t < /etc/iptables.up.rules

  # Memastikan netfilter-persistent terpasang (Debian/Ubuntu)
  if [[ -f /etc/debian_version || -f /etc/lsb-release ]]; then
    apt-get install -y netfilter-persistent >/dev/null 2>&1
    netfilter-persistent save
    netfilter-persistent reload
  elif [[ -f /etc/alpine-release ]]; then
    # Alpine tidak memiliki netfilter-persistent, menggunakan iptables langsung
    service iptables save
    service iptables restart
  fi

  # Pembersihan paket yang tidak diperlukan
  if [[ -f /etc/debian_version || -f /etc/lsb-release ]]; then
    apt autoclean -y >/dev/null 2>&1
    apt autoremove -y >/dev/null 2>&1
  elif [[ -f /etc/alpine-release ]]; then
    apk del --purge >/dev/null 2>&1
  fi

  echo "Epro installation and configuration completed."
}

  ins_restart(){
  clear
  echo "Restarting all services..."

  # Menggunakan init.d untuk restart layanan pada sistem yang lebih tua atau yang tidak menggunakan systemd
  if [[ -f /etc/init.d/nginx ]]; then
    /etc/init.d/nginx restart
  fi
  if [[ -f /etc/init.d/openvpn ]]; then
    /etc/init.d/openvpn restart
  fi
  if [[ -f /etc/init.d/ssh ]]; then
    /etc/init.d/ssh restart
  fi
  if [[ -f /etc/init.d/dropbear ]]; then
    /etc/init.d/dropbear restart
  fi
  if [[ -f /etc/init.d/fail2ban ]]; then
    /etc/init.d/fail2ban restart
  fi
  if [[ -f /etc/init.d/vnstat ]]; then
    /etc/init.d/vnstat restart
  fi
  if [[ -f /etc/init.d/cron ]]; then
    /etc/init.d/cron restart
  fi

  # Restart layanan menggunakan systemctl (untuk Debian/Ubuntu yang mendukung systemd)
  if [[ -d /etc/systemd/system ]]; then
    systemctl restart haproxy
    systemctl daemon-reload
    systemctl start netfilter-persistent
  fi

  # Mengaktifkan layanan agar otomatis berjalan saat boot (untuk sistem dengan systemd)
  if [[ -d /etc/systemd/system ]]; then
    systemctl enable --now nginx
    systemctl enable --now xray
    systemctl enable --now rc-local
    systemctl enable --now dropbear
    systemctl enable --now openvpn
    systemctl enable --now cron
    systemctl enable --now haproxy
    systemctl enable --now netfilter-persistent
    systemctl enable --now ws
    systemctl enable --now fail2ban
  fi

  # Menggunakan OpenRC untuk Alpine (jika systemd tidak ada)
  if [[ -f /etc/alpine-release ]]; then
    # Restart layanan dengan OpenRC (untuk Alpine)
    /etc/init.d/nginx restart
    /etc/init.d/openvpn restart
    /etc/init.d/ssh restart
    /etc/init.d/dropbear restart
    /etc/init.d/fail2ban restart
    /etc/init.d/vnstat restart
    /etc/init.d/cron restart

    # Mengaktifkan layanan agar otomatis berjalan saat boot
    rc-update add nginx default
    rc-update add openvpn default
    rc-update add ssh default
    rc-update add dropbear default
    rc-update add fail2ban default
    rc-update add cron default
  fi

  # Membersihkan riwayat terminal untuk menjaga privasi
  history -c
  echo "unset HISTFILE" >> /etc/profile

  # Membersihkan file sementara
  cd
  rm -f /root/openvpn
  rm -f /root/key.pem
  rm -f /root/cert.pem

  # Menampilkan pesan sukses
  echo -e "\e[32mAll services have been successfully restarted and configured.\e[0m"
}


  ins_menu(){
clear
# install menu shell
  wget ${REPO}feature/LunatiX2
  unzip LunatiX2
  chmod +x menu/*
  mv menu/* /usr/local/sbin
  rm -rf menu
  rm -rf LunatiX2
# install menu py
  wget ${REPO}feature/LunatiX_py
  unzip LunatiX_py
  chmod +x menu/*
  mv menu/* /usr/bin
  rm -rf menu
  rn -rf LunatiX_py
}

 ins_profile() {
  clear

  # Mengatur .profile untuk memanggil menu python
  cat >/root/.profile <<EOF
if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi
mesg n || true
python3 /usr/bin/menu
EOF

  # Menambahkan cron job untuk berbagai keperluan
  cat >/etc/cron.d/xp_all <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 0 * * * root /usr/local/sbin/xp
END

  cat >/etc/cron.d/logclean <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/10 * * * * root /usr/local/sbin/clearlog
END

  cat >/etc/cron.d/daily_reboot <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 5 * * * root /sbin/reboot
END

  # Membersihkan log nginx dan xray secara rutin
  echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
  echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray

  # Mengatur layanan cron
  service cron restart

  # Menyimpan waktu reboot harian
  cat >/home/daily_reboot <<-END
5
END

  # Mengatur rc-local.service
  cat >/etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF

  # Menambahkan konfigurasi iptables di /etc/rc.local
  cat >/etc/rc.local <<EOF
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF
  chmod +x /etc/rc.local

  # Menambahkan shell yang tidak diperbolehkan
  echo "/bin/false" >>/etc/shells
  echo "/usr/sbin/nologin" >>/etc/shells

  # Menentukan waktu reboot (AM/PM)
  AUTOREB=$(cat /home/daily_reboot)
  SETT=11
  if [ $AUTOREB -gt $SETT ]; then
    TIME_DATE="PM"
  else
    TIME_DATE="AM"
  fi
}


  ins_udp() {
  cd
  rm -rf /root/udp
  mkdir -p /etc/udp

  # Mengatur zona waktu ke GMT+7 (Asia/Jakarta)
  echo "Change to time GMT+7"
  ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

  # Mengunduh udp-custom
  echo "Downloading udp-custom"
  wget -q --show-progress --load-cookies /tmp/cookies.txt "https://docs.google.com/uc?export=download&confirm=$(wget --quiet --save-cookies /tmp/cookies.txt --keep-session-cookies --no-check-certificate 'https://docs.google.com/uc?export=download&id=1ixz82G_ruRBnEEp4vLPNF2KZ1k8UfrkV' -O- | sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/\1\n/p')&id=1ixz82G_ruRBnEEp4vLPNF2KZ1k8UfrkV" -O /etc/udp/udp-custom && rm -rf /tmp/cookies.txt
  chmod +x /etc/udp/udp-custom

  # Mengunduh konfigurasi default
  echo "Downloading default config"
  wget -q --show-progress --load-cookies /tmp/cookies.txt "https://docs.google.com/uc?export=download&confirm=$(wget --quiet --save-cookies /tmp/cookies.txt --keep-session-cookies --no-check-certificate 'https://docs.google.com/uc?export=download&id=1klXTiKGUd2Cs5cBnH3eK2Q1w50Yx3jbf' -O- | sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/\1\n/p')&id=1klXTiKGUd2Cs5cBnH3eK2Q1w50Yx3jbf" -O /etc/udp/config.json && rm -rf /tmp/cookies.txt
  chmod 644 /etc/udp/config.json

  # Menyesuaikan konfigurasi systemd berdasarkan parameter
  if [ -z "$1" ]; then
    cat <<EOF > /etc/systemd/system/udp-custom.service
[Unit]
Description=UDP Custom by ePro Dev. Team

[Service]
User=root
Type=simple
ExecStart=/etc/udp/udp-custom server
WorkingDirectory=/etc/udp/
Restart=always
RestartSec=2s

[Install]
WantedBy=default.target
EOF
  else
    cat <<EOF > /etc/systemd/system/udp-custom.service
[Unit]
Description=UDP Custom by ePro Dev. Team

[Service]
User=root
Type=simple
ExecStart=/etc/udp/udp-custom server -exclude $1
WorkingDirectory=/etc/udp/
Restart=always
RestartSec=2s

[Install]
WantedBy=default.target
EOF
  fi

  # Mengecek apakah systemd tersedia atau tidak, untuk Alpine gunakan OpenRC
  if command -v systemctl &>/dev/null; then
    # Jika systemd tersedia, gunakan systemctl
    echo "Starting service udp-custom using systemd"
    systemctl start udp-custom &>/dev/null
    echo "Enabling service udp-custom using systemd"
    systemctl enable udp-custom &>/dev/null
  else
    # Jika systemd tidak tersedia (misalnya di Alpine), gunakan OpenRC
    echo "Starting service udp-custom using OpenRC"
    rc-service udp-custom start &>/dev/null
    echo "Enabling service udp-custom using OpenRC"
    rc-update add udp-custom default &>/dev/null
  fi

  clear
}

  enable_services() {
  clear

  # Mengecek apakah systemd tersedia
  if command -v systemctl &>/dev/null; then
    # Jika systemd tersedia, gunakan systemctl
    systemctl daemon-reload
    systemctl start netfilter-persistent
    systemctl enable --now rc-local
    systemctl enable --now cron
    systemctl enable --now netfilter-persistent
    systemctl restart nginx
    systemctl restart xray
    systemctl restart cron
    systemctl restart haproxy
    systemctl restart lock-vme
    systemctl restart lock-vle
    systemctl restart lock-ssr
    systemctl restart lock-ssh
    systemctl restart lock-tro
    systemctl restart kill-vme
    systemctl restart kill-vle
    systemctl restart kill-ssr
    systemctl restart kill-ssh
    systemctl restart kill-tro
  else
    # Jika systemd tidak tersedia (misalnya di Alpine), gunakan OpenRC
    echo "systemd tidak tersedia, menggunakan OpenRC"
    
    # Mulai layanan dengan OpenRC
    rc-service netfilter-persistent start
    rc-update add netfilter-persistent default
    
    rc-service cron start
    rc-update add cron default
    
    rc-service nginx restart
    rc-service xray restart
    rc-service haproxy restart
    rc-service lock-vme restart
    rc-service lock-vle restart
    rc-service lock-ssr restart
    rc-service lock-ssh restart
    rc-service lock-tro restart
    rc-service kill-vme restart
    rc-service kill-vle restart
    rc-service kill-ssr restart
    rc-service kill-ssh restart
    rc-service kill-tro restart
  fi

  clear
}

  clear_all() {
  # Membersihkan history terminal
  history -c

  # Menghapus file dan direktori yang tidak diperlukan
  rm -rf /root/menu
  rm -rf /root/*.zip
  rm -rf /root/*.sh
  rm -rf /root/LICENSE
  rm -rf /root/README.md
  rm -rf /etc/xray/domain
  rm -rf /root/LunatiX2
  rm -rf /root/LunatiX_py
  rm -rf /root/UDP
  rm -rf /root/udp
  rm -rf /root/install.log
  rm -rf /root/snap
  rm -rf /root/nsdomain

  # Menampilkan waktu yang telah berlalu sejak start (menggunakan start time)
  secs_to_human "$(($(date +%s) - ${start}))"

  # Mengatur hostname server ke username yang diberikan
  if command -v hostnamectl &>/dev/null; then
    # Jika hostnamectl tersedia (Debian/Ubuntu)
    sudo hostnamectl set-hostname $username
  else
    # Jika hostnamectl tidak tersedia (Alpine)
    echo "Mengubah hostname menggunakan perintah hostname"
    sudo hostname $username
    echo "$username" > /etc/hostname
  fi
}

  sending_notif() {
  # Variabel Konfigurasi
  USRSC=$(wget -qO- "https://raw.githubusercontent.com/${GIT_USER}/vps_access/main/ip" | grep "$Ip_Vps" | awk '{print $2}')
  EXPSC=$(wget -qO- "https://raw.githubusercontent.com/${GIT_USER}/vps_access/main/ip" | grep "$Ip_Vps" | awk '{print $3}')
  TIMEZONE=$(date +"%H:%M:%S")
  domain=$(cat /etc/xray/domain || echo "Domain tidak ditemukan")
  TIME=$(date +"%Y-%m-%d")

  # Pesan Telegram
  TEXT="
<code>────────────────────</code>
<b> 🟢 NOTIFICATIONS INSTALL 🟢</b>
<code>────────────────────</code>
<code>ID     : </code><code>$USRSC</code>
<code>Domain : </code><code>$domain</code>
<code>Date   : </code><code>$TIME</code>
<code>Time   : </code><code>$TIMEZONE</code>
<code>Ip vps : </code><code>$Ip_Vps</code>
<code>Exp Sc : </code><code>$EXPSC</code>
<code>────────────────────</code>
<i>Automatic Notification from Github</i>
"

  # Tombol Inline Telegram
  BUTTONS='{"inline_keyboard":[[{"text":"⭐ᴏʀᴅᴇʀ⭐","url":"https://t.me/ian_khvicha"},{"text":"⭐ɪɴꜱᴛᴀʟʟ⭐","url":"https://wa.me/6283189774145"}]]}'

  # Kirim ke Telegram
  if curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" \
      --data-urlencode "reply_markup=$BUTTONS" "$URL" >/dev/null; then
    echo "Notifikasi berhasil dikirim ke Telegram."
  else
    echo "Gagal mengirim notifikasi ke Telegram."
  fi
}

# Universal For all os debian 10/11/12 ubuntu 20/22/24
# and added universal all os alphine linux
# Lunatic Tunneling project My scripts
# me adress : Bandung Barat , jawabarat , jati , saguling


# Menjalankan fungsi dengan animasi loading
clear
echo -e "\033[1;37mDownloading base pkg......\033[0m"
fun_bar base_package
echo -e "\033[1;37mDownloading Swapp.........\033[0m"
fun_bar ins_swab
echo -e "\033[1;37mDownloading haproxy.......\033[0m"
fun_bar first_setup
echo -e "\033[1;37mInstall ssl domain......\033[0m"
fun_bar pasang_ssl
echo -e "\033[1;37mDownloading nginx.........\033[0m"
fun_bar nginx_install
echo -e "\033[1;37mMake Xray Folder........\033[0m"
fun_bar make_folder_xray
echo -e "\033[1;37mDownloading Xray..........\033[0m"
fun_bar install_xray
echo -e "\033[1;37mDownloading ssh Packs.....\033[0m"
fun_bar pasang_ssh
echo -e "\033[1;37mDownloading Badvpn........\033[0m"
fun_bar udp_mini
echo -e "\033[1;37mDownloading SSHD..........\033[0m"
fun_bar ins_SSHD
echo -e "\033[1;37mDownloading Dropbear......\033[0m"
fun_bar ins_dropbear
echo -e "\033[1;37mDownloading Vnstat........\033[0m"
fun_bar ins_vnstat
echo -e "\033[1;37mDownloading Openvpn.......\033[0m"
fun_bar ins_openvpn
echo -e "\033[1;37mDownloading RcLone........\033[0m"
fun_bar ins_backup
echo -e "\033[1;37mDownloading Fail2ban......\033[0m"
fun_bar ins_Fail2ban
echo -e "\033[1;37mDownloading WsEPRO........\033[0m"
fun_bar ins_epro
echo -e "\033[1;37mRestart All service.....\033[0m"
fun_bar ins_restart
echo -e "\033[1;37mDownloading pack menu.....\033[0m"
fun_bar ins_menu
echo -e "\033[1;37mDownloading pack profile..\033[0m"
fun_bar ins_profile
echo -e "\033[1;37mDownloading Udp Custom....\033[0m"
fun_bar ins_udp
echo -e "\033[1;37mEnabled all service.....\033[0m"
fun_bar enable_services
echo -e "\033[1;37mSend Notifications......\033[0m"
fun_bar sending_notif
echo -e "\033[1;37mDelete packs caches.....\033[0m"
fun_bar clear_all

echo -e "\033[1;32mAll processes complete!\033[0m"

sleep 2
function GO_DISPLAY() {
clear
echo -e ""
echo -e "   \e[97;1m ===========================================\e[0m"
echo -e "   \e[92;1m     Install Succesfully bro! Good Job!     \e[0m"
echo -e "   \e[97;1m ===========================================\e[0m"
echo ""
read -p "$( echo -e "Press ${YELLOW}[ ${NC}${YELLOW}Enter${NC} ${YELLOW}]${NC} TO REBOOT") "

# Mengecek OS dan melakukan reboot sesuai dengan OS yang digunakan
if command -v reboot &>/dev/null; then
  # Jika perintah reboot tersedia (Debian/Ubuntu)
  reboot
else
  # Jika perintah reboot tidak ditemukan, gunakan shutdown -r (Alpine)
  shutdown -r now
fi
}

GO_DISPLAY
