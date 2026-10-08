# VPNSTAN v26 — Live Traffic Fix

این نسخه صفحه Subscription را به آمار Xray متصل‌تر می‌کند.

- `/sub-status/<sub_id>` قبل از پاسخ یک snapshot تازه از Xray می‌گیرد.
- صفحه Subscription هر ۱ ثانیه وضعیت را دوباره می‌خواند.
- مصرف upload + download به‌صورت تجمعی در SQLite نگهداری می‌شود.
- اگر شمارنده Xray بعد از restart صفر شود، شمارنده ذخیره‌شده حفظ می‌شود و از مقدار جدید ادامه می‌دهد.

برای آمار واقعی، Xray باید با `StatsService`، `stats: {}` و `statsUserUplink/statsUserDownlink` اجرا شود. طبق مستندات رسمی Project X، آمار per-user از رکوردهای `user>>>[email]>>>traffic>>>uplink/downlink` خوانده می‌شود.
