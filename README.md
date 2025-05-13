# ZT2CF

Sync DNS records between ZeroTier and CloudFlare.

This repository is written by Google Gemini 2.5 Pro, published in public domain.

> Write a Go program using ZeroTier Central API and CloudFlare API, that when executed, sync the DNS records between a specified ZeroTier network and a specified cloudflare domain (let's say "example.com") and prefix (let's say "z"). In details: for every authorized devices in the ZeroTier network, add or update the A dns record of `<name>.<prefix>.<domain>` resolving to the device managed IP, where `<name>` is the device name in ZeroTier.

## Usage

Config using the following cmdline flags or environment variables:

- `-zt-token`, `ZT_TOKEN` : ZeroTier Central API Token: Generate one from https://my.zerotier.com/account.
- `-zt-network`, `ZT_NETWORK` : ZeroTier Network ID: The ID of the network you want to sync.
- `-cf-token`, `CF_TOKEN` : Cloudflare API Token: Create one from the Cloudflare dashboard (My Profile -> API Tokens -> Create Token) with Zone:DNS:Edit permissions for the specific zone.
- `-cf-zone`, `CF_ZONE` : Cloudflare Zone ID: Find this on the "Overview" page for your domain in the Cloudflare dashboard.
- `-domain`, `DOMAIN` : e.g. "example.com" or "z.example.com".
- `-delete-stale` : Enable deletion of stale DNS records in Cloudflare.
- `-dry-run` : Enable dry run mode (log changes without applying).

E.g.

```
zt2cf -cf-token <cf-token> -cf-zone <cf-zone> -zt-token <zt-token> -zt-network <zt-network> -domain z.example.me -dry-run
```
