# VPNSTAN v28 — Bot Hub API

این نسخه API امن برای اتصال Bot Hub کلودفلر دارد.

## API Key
پس از اجرای پنل، وارد بخش «تنظیمات» شو. قسمت «API اتصال Bot Hub» کلید را نشان می‌دهد.
اگر کلید را regenerate کنی، کلید قبلی فوراً باطل می‌شود.

## اتصال در Bot Hub
نوع پنل: `vpnstan`
Base URL: آدرس عمومی همین VPNSTAN، بدون `/api`
API Key: کلیدی که در تنظیمات VPNSTAN نمایش داده می‌شود.

Bot Hub از این مسیرها استفاده می‌کند:
- GET `/api/server/status`
- GET `/api/clients`
- GET `/api/traffic`

و برای مدیریت:
- POST `/api/clients/create`
- POST `/api/clients/{id}/renew`
- POST `/api/clients/{id}/volume`
- POST `/api/clients/{id}/toggle`
- POST `/api/clients/{id}/delete`

احراز هویت:
`Authorization: Bearer <API_KEY>` یا `X-API-Key: <API_KEY>`

در صورت تنظیم `VPNSTAN_BOT_API_KEY` در Railway، همان مقدار به‌عنوان کلید API استفاده می‌شود.
