#!/bin/sh
set -eu
mkdir -p /data /opt/vpnstan/data /run/nginx /var/lib/unbound
cat > /etc/unbound/unbound.conf <<'UNBOUND'
server:
    interface: 127.0.0.1
    port: 5353
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes
    access-control: 127.0.0.0/8 allow
    root-hints: "/etc/unbound/root.hints"
    hide-identity: yes
    hide-version: yes
    prefetch: yes
    qname-minimisation: yes
    harden-below-nxdomain: yes
    cache-min-ttl: 30
    cache-max-ttl: 86400
UNBOUND
unbound-checkconf /etc/unbound/unbound.conf
unbound -c /etc/unbound/unbound.conf

PORT="${PORT:-8080}"
cat > /etc/nginx/http.d/default.conf <<NGINX
server {
    listen 0.0.0.0:${PORT};
    server_name _;
    client_max_body_size 2m;
    location = /health {
        proxy_pass http://127.0.0.1:3000/health;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    location ^~ /ws {
        proxy_pass http://127.0.0.1:10000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
    location ^~ /vmess {
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
NGINX
nginx -t
nginx -g 'daemon off;' &
exec python3 /opt/vpnstan/web/server.py
