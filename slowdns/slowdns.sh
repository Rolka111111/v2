#!/bin/bash
# ===============================================

# Install squid (works for Debian/Ubuntu, but Alpine uses a different package name)
if [ -f /etc/debian_version ]; then
  sudo apt install squid -y
elif [ -f /etc/alpine-release ]; then
  sudo apk add squid -y
fi

# Setting IPtables
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300

# Handle netfilter-persistent for Debian/Ubuntu
if [ -f /etc/debian_version ]; then
  netfilter-persistent save
  netfilter-persistent reload
fi

# Delete directory
rm -rf /root/nsdomain
rm nsdomain

# Input nameserver manually to Cloudflare
touch /etc/xray/nsdomain
Host=inject.cloud
sub=ns.`(</dev/urandom tr -dc a-z0-9 | head -c5)`
SUB_DOMAIN=${sub}.inject.cloud
NS_DOMAIN=${SUB_DOMAIN}
echo $NS_DOMAIN > /etc/xray/nsdomain

# Install necessary packages
if [ -f /etc/debian_version ]; then
  apt update -y
  apt install -y python3 python3-dnslib net-tools dnsutils git curl wget screen cron iptables sudo gnutls-bin dos2unix debconf-utils
elif [ -f /etc/alpine-release ]; then
  apk update -y
  apk add python3 py3-dnslib net-tools dnsutils git curl wget screen cron iptables sudo gnutls dos2unix
fi

# Reload cron service
if [ -f /etc/debian_version ]; then
  service cron reload
  service cron restart
elif [ -f /etc/alpine-release ]; then
  rc-service crond restart
fi

# Configure SlowDNS
rm -rf /etc/slowdns
mkdir -m 777 /etc/slowdns
wget -q -O /etc/slowdns/server.key "https://raw.githubusercontent.com/rzlftwaa-cloud/scriptsme/main/slowdns/server.key"
wget -q -O /etc/slowdns/server.pub "https://raw.githubusercontent.com/rzlftwaa-cloud/scriptsme/main/slowdns/server.pub"
wget -q -O /etc/slowdns/sldns-server "https://raw.githubusercontent.com/rzlftwaa-cloud/scriptsme/main/slowdns/sldns-server"
wget -q -O /etc/slowdns/sldns-client "https://raw.githubusercontent.com/rzlftwaa-cloud/scriptsme/main/slowdns/sldns-client"
cd
chmod +x /etc/slowdns/server.key
chmod +x /etc/slowdns/server.pub
chmod +x /etc/slowdns/sldns-server
chmod +x /etc/slowdns/sldns-client

# Install client-sldns.service
cat > /etc/systemd/system/client-sldns.service << END
[Unit]
Description=Client SlowDNS By CyberVPN
Documentation=https://www.xnxx.com
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/etc/slowdns/sldns-client -udp 8.8.8.8:53 --pubkey-file /etc/slowdns/server.pub $nameserver 127.0.0.1:58080
Restart=on-failure

[Install]
WantedBy=multi-user.target
END

# Install server-sldns.service
cat > /etc/systemd/system/server-sldns.service << END
[Unit]
Description=Server SlowDNS By Cybervpn
Documentation=https://xhamster.com
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/etc/slowdns/sldns-server -udp :5300 -privkey-file /etc/slowdns/server.key $nameserver 127.0.0.1:22
Restart=on-failure

[Install]
WantedBy=multi-user.target
END

# Permission service slowdns
cd
chmod +x /etc/systemd/system/client-sldns.service
chmod +x /etc/systemd/system/server-sldns.service

# Stop previous processes if any
pkill sldns-server
pkill sldns-client

# Reload systemd and enable services
systemctl daemon-reload
systemctl stop client-sldns
systemctl stop server-sldns

systemctl enable client-sldns
systemctl enable server-sldns

# Start services
systemctl start client-sldns
systemctl start server-sldns

# Restart services
systemctl restart client-sldns
systemctl restart server-sldns
