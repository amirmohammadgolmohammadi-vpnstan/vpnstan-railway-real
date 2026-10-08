# VPNSTAN v26 — Traffic REAL FIX 2

این نسخه مشکل آمار مصرف را از بخش API داخلی Xray اصلاح می‌کند.

- API داخلی Xray از inbound نوع `tunnel` با `rewriteAddress` استفاده می‌کند.
- StatsService فعال است.
- برای کاربران email پایدار `vpnstan-UUID` ثبت می‌شود.
- آمار `uplink/downlink` از `xray api statsquery` و در صورت نیاز `xray api stats` خوانده می‌شود.
- مصرف در SQLite ذخیره و در `/sub-status/<id>` و صفحه ساب نمایش داده می‌شود.

مطابق مستندات رسمی Xray، API inbound برای StatsService باید به outbound API route شود و آمار کاربر از رکوردهای `user>>>email>>>traffic>>>uplink/downlink` قابل دریافت است.
