# VPNSTAN v24.1 — Railway crash fixed

This build fixes the Railway startup crash caused by unescaped Nginx variables in the generated config. It also retains the earlier fixes for per-user Xray traffic accounting (`uplink/downlink` mapping), makes multi-client subscriptions valid in SQLite, aggregates usage in `Subscription-Userinfo` and `/sub-status`, and adds VLESS + XHTTP as an HTTP transport behind the existing Railway reverse proxy.

**Railway note:** REALITY is not enabled on the Railway HTTP ingress in this build because Railway terminates the public HTTPS connection before the service. REALITY requires end-to-end TLS handshake visibility at the Xray node. Use a direct TCP node for REALITY rather than advertising a configuration that cannot work.

# vpnstan — Standalone Railway + Xray

نسخه مستقل و بدون 3X-UI/WireGuard. پنل، Subscription و Xray Core در یک سرویس Railway اجرا می‌شوند.

## Railway
1. Repository را Deploy کن.
2. یک Railway Volume با Mount Path `/data` بساز.
3. در Variables مقدار `PORT=8080` بگذار اگر Target Port دامنه را 8080 تنظیم کرده‌ای.
4. Target Port دامنه را دقیقاً برابر PORT بگذار.
5. Healthcheck را `/health` بگذار.
6. یک Railway Domain یا Custom Domain بساز و HTTPS را نگه دار.

Railway باید برنامه را روی `PORT` اجراشده health-check کند.

## Variables
- `PORT=8080` (در صورت استفاده از Target Port 8080)
- `VPNSTAN_USERNAME=admin`
- `VPNSTAN_PASSWORD=یک رمز قوی`
- `VPNSTAN_NODE_PORT=443`
- `VPNSTAN_WS_PATH=/ws`
- `VPNSTAN_SUB_PATH=sub`
- `VPNSTAN_DB=/data/vpnstan.db`

## Connection
کانفیگ‌ها VLESS + WebSocket + TLS هستند. TLS روی دامنه عمومی Railway terminate می‌شود و Nginx مسیر `/ws` را به Xray داخلی روی `127.0.0.1:10000` می‌فرستد.

پورت 8080/2096 پنل داخلی Railway است؛ پورت کانفیگ VLESS در این معماری 443 است.

## Subscription
- `/sub/<subscription-id>` → خروجی Base64 برای کلاینت‌ها
- `/sub/<subscription-id>?html=1` → صفحه حرفه‌ای اطلاعات ساب
- `/subjson/<subscription-id>` → JSON Xray
- `/qr/<subscription-id>` → QR کانفیگ

صفحه ساب حجم کل، مصرف، باقی‌مانده، آپلود، دانلود، انقضا، وضعیت و کانفیگ را نشان می‌دهد.

## Traffic
Xray StatsService برای upload/download فعال است. مصرف هر کاربر هر چند ثانیه جمع می‌شود و وقتی سقف GB یا تاریخ انقضا برسد، کاربر غیرفعال و Xray با لیست جدید بازخوانی می‌شود.

## Default login
`admin / admin` — بعد از اولین Deploy حتماً رمز را در Variables عوض کن.

## نسخه مدیریت اکانت و پروتکل‌ها
- حساب‌های پنل در SQLite نگهداری می‌شوند.
- اولین اکانت از `VPNSTAN_USERNAME` و `VPNSTAN_PASSWORD` ساخته می‌شود و نقش آن `admin` است.
- ادمین می‌تواند اکانت پنل بسازد، نقش user/admin بدهد، فعال/غیرفعال کند و حذف کند.
- هر کاربر می‌تواند از «حساب من» نام کاربری و رمز عبور خود را تغییر دهد.
- برای کلاینت‌ها پروتکل‌های VLESS، WireGuard و DNS در رابط پنل قابل انتخاب‌اند.
- VLESS تنها پروتکل این نسخه است که از مسیر HTTP/HTTPS + WebSocket روی Railway به‌صورت مستقیم توسط Xray سرو می‌شود.
- WireGuard به‌صورت پروفایل و تنظیمات Endpoint/Public Key در پنل پشتیبانی می‌شود؛ برای اتصال عمومی باید یک Endpoint WireGuard واقعی با مسیر شبکه مناسب داشته باشید. دامنه HTTP عمومی Railway برای عبور UDP WireGuard کافی نیست؛ Railway برای سرویس‌های غیرHTTP قابلیت TCP Proxy دارد و HTTP/HTTPS و TCP را جداگانه مسیریابی می‌کند.
- DNS در این نسخه به‌عنوان Resolver/تنظیم DNS برای پروفایل ثبت می‌شود و خودش یک تونل VPN مستقل نیست.

## v20.1 fixes
- Fixed Xray stats API invocation to use `--server=127.0.0.1:10085`.
- Fixed DNS-over-HTTPS POST handling so compatible DNS clients can send `application/dns-message` requests.
- DNS token remains the per-profile credential; no public resolver IP is presented as the user's dedicated server.


## V25 UI/Subscription fixes

- Multiple clients are grouped under one Subscription in the panel.
- Dashboard shows unique Subscription count.
- Edit modal/API flow is hardened.
- Subscription QR points to the Subscription URL.
- Static assets are versioned to avoid stale browser cache.
