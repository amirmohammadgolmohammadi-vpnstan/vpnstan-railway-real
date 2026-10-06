FROM alpine:3.22
ARG XRAY_VERSION=26.7.28
RUN apk add --no-cache python3 py3-pip nginx ca-certificates curl unzip unbound && \
    pip3 install --no-cache-dir --break-system-packages qrcode && \
    curl -fsSL "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip" -o /tmp/xray.zip && \
    unzip -q /tmp/xray.zip -d /tmp/xray && \
    install -m 0755 /tmp/xray/xray /usr/local/bin/xray && \
    rm -rf /tmp/xray /tmp/xray.zip && curl -fsSL https://www.internic.net/domain/named.root -o /etc/unbound/root.hints && mkdir -p /etc/unbound
WORKDIR /opt/vpnstan
COPY web /opt/vpnstan/web
COPY scripts/start.sh /start-vpnstan.sh
RUN chmod 755 /start-vpnstan.sh
ENV VPNSTAN_PANEL_PORT=3000
ENV VPNSTAN_USERNAME=admin
ENV VPNSTAN_PASSWORD=admin
ENV VPNSTAN_DB=/data/vpnstan.db
ENV VPNSTAN_NODE_PORT=443
ENV VPNSTAN_WS_PATH=/ws
ENV VPNSTAN_SUB_PATH=sub
ENV XRAY_INBOUND_PORT=10000
ENV XRAY_VMESS_PORT=10001
ENV VPNSTAN_XHTTP_PATH=/xhttp
ENV XRAY_API_ADDR=127.0.0.1:10085
EXPOSE 8080
ENTRYPOINT ["/start-vpnstan.sh"]
