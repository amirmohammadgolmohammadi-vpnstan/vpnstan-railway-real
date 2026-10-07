# VPNSTAN v26 — Subscription 502 Fix

Fixed a deadlock in the HTML subscription route `/sub/<id>`.

The route was collecting Xray statistics while holding `XRAY_LOCK`, then `sub_page()` attempted to acquire the same non-reentrant lock again. The main panel could remain available while `/sub/<id>` hung and Nginx returned 502.

This build keeps the professional subscription UI and collects Xray stats only once per request.
