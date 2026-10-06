# راه‌اندازی سریع Railway

### 1) Volume
Service → Volumes → Add Volume → Mount Path: `/data`

### 2) Variables
اگر Target Port دامنه را 8080 می‌گذاری:
`PORT=8080`

سایر مقادیر: `VPNSTAN_NODE_PORT=443`, `VPNSTAN_WS_PATH=/ws`, `VPNSTAN_SUB_PATH=sub`.

### 3) Networking
یک Domain بساز. Target Port باید دقیقاً با PORT یکی باشد.

### 4) Healthcheck
`/health`

### 5) تست
دامنه را باز کن. سپس `/health` باید JSON با `ok: true` و `xray: true` برگرداند.

### 6) VLESS
در پنل یک Client بساز. لینک VLESS تولیدشده را در HAPP یا کلاینت سازگار وارد کن. پورت VLESS `443` است؛ پورت پنل Railway همان پورت Target است و با پورت VLESS یکی نیست.
