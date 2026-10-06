# VPNSTAN V25

## Fixes
- Subscription groups are rendered by `sub_id`; multiple configs in one subscription are shown as one group.
- Dashboard shows unique subscription count.
- Subscription page QR encodes the subscription URL, not the first client config.
- Edit flow is hardened and exposed globally for inline buttons; Escape/outside-click closes the modal.
- Static assets use `?v=25.0` to avoid stale browser assets.
- Subscription page is branded V25 and uses a cache-busted management link.
- Existing traffic and UUIDs are preserved when editing a client.

## Tested
- Python syntax
- JavaScript syntax
- Create 3 clients in one subscription
- Verify all 3 share the same `sub_id`
- Edit one client from VLESS/XHTTP to VMess/gRPC
- Verify the edited client remains in the same subscription
- Verify subscription output contains all 3 configs
