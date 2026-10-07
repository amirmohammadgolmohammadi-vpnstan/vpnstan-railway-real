# vpnstan — Standalone Railway + Xray

نسخه مستقل و بدون 3X-UI/WireGuard. پنل، Subscription و Xray Core در یک سرویس Railway اجرا می‌شوند.

## Railway
1. Repository را Deploy کن.
2. نیازی به ساخت Railway Volume یا پوشه `/data` نیست؛ برنامه پوشه داده داخلی خودش را خودکار می‌سازد.
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
- `VPNSTAN_DB=/opt/vpnstan/data/vpnstan.db`

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

## v26.1 fixes
- Fixed Xray stats API invocation to use `--server=127.0.0.1:10085`.
- Fixed DNS-over-HTTPS POST handling so compatible DNS clients can send `application/dns-message` requests.
- DNS token remains the per-profile credential; no public resolver IP is presented as the user's dedicated server.

## v26 Master / Child Panels
- Overview is separated as `نمای کلی / Overview`.
- Dedicated sections: Clients, Configs, Subscriptions, DNS, Settings, Account.
- Admin can create child panels on the same installation without a second Railway service.
- Each child panel gets its own login, permissions, detected source IP, optional allowed-IP restriction, and isolated client list.
- Child panels do not see master-panel clients; their clients are stored with a panel scope.
- Xray remains shared by the parent installation, so all active client configs can be served by the same node.


## V26 merged options
این نسخه گزینه‌های پنل V25 را روی هسته V26 اضافه می‌کند:
- VLESS / VMess / Trojan / WireGuard / DNS
- Transport: WebSocket / XHTTP / gRPC / HTTPUpgrade
- چند مسیر مستقل برای VLESS، VMess و Trojan
- تنظیم مسیرها و gRPC Service از بخش تنظیمات
- حفظ امکانات V26: فارسی/English، پنل مادر/فرزند، مجوزها، DNS اختصاصی، Subscription و چند کانفیگ
- ساختار GitHub شامل `web/` و `scripts/`
