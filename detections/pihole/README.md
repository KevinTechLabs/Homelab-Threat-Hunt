# Pi-hole additions (H10)

## 1. Close the DNS-over-HTTPS bypass

Add [`doh-denylist.txt`](doh-denylist.txt) as an exact denylist (Domains → Add, or `pihole deny` in v6). Apps that hard-code these DoH resolvers then fall back to normal DNS through Pi-hole.

DoH runs on port 443, so pfSense can't stop it by port. For the zones that should never bypass DNS (IoT, Lab, Guest), also enable **pfBlockerNG → IP → DoH/DoT/DoQ** blocking, which blocks the resolvers' IP addresses.

## 2. Sinkhole WPAD

Add this regex to the denylist, so no device that registers the name `wpad` can become everyone's web proxy:

```
(^|\.)wpad\.
```

Better still, turn WPAD off on Windows: Settings → Network & internet → Proxy → *Automatically detect settings* = Off.

## 3. Already working, leave as is

`mask.icloud.com` (iCloud Private Relay) and `_dns.resolver.arpa` (encrypted-DNS discovery) are already blocked by Pi-hole's built-in special-domain handling. Keep that setting on.
