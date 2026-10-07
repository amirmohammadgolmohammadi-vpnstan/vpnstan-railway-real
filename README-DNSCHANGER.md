# DNSChanger for IPv4/IPv6 — VPNSTAN v26

این نسخه دو خروجی DNS دارد: DoH برای برنامه‌های سازگار، و DNS معمولی روی TCP برای DNSChanger.

## Railway
1. سرویس را Deploy کن.
2. در Settings → Networking → TCP Proxy یک TCP Proxy برای پورت داخلی `5354` بساز. Railway برای آن یک Host و Port عمومی می‌دهد. Railway طبق مستندات، TCP Proxy را برای سرویس‌های غیر-HTTP ارائه می‌کند؛ UDP عمومی در این مسیر ارائه نمی‌شود.
3. پنل VPNSTAN بعد از فعال شدن TCP Proxy، `RAILWAY_TCP_PROXY_DOMAIN` و `RAILWAY_TCP_PROXY_PORT` را از متغیرهای Railway می‌خواند و در بخش DNS نمایش می‌دهد.
4. در DNSChanger یک DNS سفارشی بساز و Host/Port نمایش‌داده‌شده را با حالت TCP وارد کن، در صورتی که نسخهٔ نصب‌شدهٔ برنامه گزینهٔ TCP/Port را نشان دهد.

## نکته
DNSChanger رسمی برای وارد کردن DNSهای سفارشی IPv4/IPv6 طراحی شده است. DoH URL پنل در فیلد Primary DNS قابل وارد کردن نیست.
