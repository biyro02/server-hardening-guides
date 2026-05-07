# Cloudflare Hardening Guide

**Protecting a self-hosted VPS with Cloudflare proxy and origin IP cloaking**

> Cloudflare is not just a CDN. When configured correctly, it hides your server's real IP, absorbs DDoS, and enforces WAF rules — all on the free tier. The single most impactful thing you can do for a public web server is put Cloudflare in front of it and lock inbound access to Cloudflare IPs only.

---

## Table of Contents

1. [Why Cloudflare Changes Your Threat Model](#1-why-cloudflare-changes-your-threat-model)
2. [Initial Setup](#2-initial-setup)
3. [Origin IP Cloaking — the Critical Step](#3-origin-ip-cloaking--the-critical-step)
4. [SSL/TLS Configuration](#4-ssltls-configuration)
5. [Security Settings](#5-security-settings)
6. [WAF Rules](#6-waf-rules)
7. [Rate Limiting](#7-rate-limiting)
8. [Bot Management](#8-bot-management)
9. [DNS Security](#9-dns-security)
10. [Authenticated Origin Pulls](#10-authenticated-origin-pulls)
11. [Cloudflare API Token Restriction](#11-cloudflare-api-token-restriction)
12. [Verification Checklist](#12-verification-checklist)

---

## 1. Why Cloudflare Changes Your Threat Model

Without Cloudflare:
- Your server IP is public. Anyone can scan it, target it directly, or attempt to bypass your nginx rules.
- Every bot, scanner, and attacker hits your server. DDoS goes directly to your VPS. Layer 7 flood kills nginx before fail2ban even fires.
- Your `fail2ban + nginx rate limit` is your only layer against brute force.

With Cloudflare (properly configured):
- Your real server IP is hidden. Attackers who can't find your origin IP cannot attack it directly.
- Cloudflare absorbs volumetric DDoS before it reaches your server.
- Cloudflare's WAF stops known attack patterns (SQLi, XSS, WordPress exploits) before they reach PHP.
- Your server only receives traffic from Cloudflare's IP ranges — everything else is dropped at the firewall.

This transforms your server from "internet-facing" to "Cloudflare-backend." The entire threat surface shrinks.

> **"Cloudflare-bypass-via-Cloudflare" attack:** An attacker who discovers your origin IP can register their own Cloudflare account, add your IP as the origin for a domain they control, and route requests through Cloudflare's network. Your UFW firewall allows all Cloudflare IP ranges (Section 3), so the requests pass the firewall check. Critically: your WAF rules, rate limits, and bot protection configured in **your** Cloudflare zone do not apply — requests arrive as if from a clean Cloudflare source.
>
> **Authenticated Origin Pulls (Section 10) does NOT close this gap** — the Cloudflare client certificate used for AOP is issued by Cloudflare's CA and is the same for all CF accounts. A request routed through any Cloudflare account presents a valid AOP certificate.
>
> **The correct mitigations, in order of strength:**
>
> 1. **Custom origin-verify header (free tier):** In Cloudflare dashboard → Rules → Transform Rules → Modify Request Header → add a header `X-Origin-Verify: <strong-random-secret>`. In nginx, reject requests without it:
>    ```nginx
>    if ($http_x_origin_verify != "your-64-char-random-secret") {
>        return 403;
>    }
>    ```
>    An attacker routing through their own CF zone cannot inject this header. Keep the secret out of version control.
>
> 2. **Cloudflare Tunnel (`cloudflared` — strongest protection):** cloudflared creates an outbound tunnel from your server to Cloudflare. No inbound ports need to be open at all — not even to Cloudflare IPs. An attacker with any CF account cannot route to your origin because there is no listening socket to reach.

> **Critical dependency:** All of this assumes your origin IP is not already public. If your IP has been exposed (e.g. in DNS history, email headers, git commits, error messages, previous SSL cert logs at crt.sh), origin IP cloaking provides limited protection for past-exposed IPs. Mitigate by requesting a new IP from your VPS provider after setting up Cloudflare.

---

## 2. Initial Setup

- [ ] **Create a Cloudflare account** at cloudflare.com.

- [ ] **Add your domain** to Cloudflare.

  Cloudflare will scan your existing DNS records and import them.

- [ ] **Update your domain's nameservers** at your registrar to Cloudflare's nameservers.

  This can take up to 24 hours to propagate. Cloudflare will notify you when active.

- [ ] **Verify all DNS records are imported correctly** — especially MX records for email.

- [ ] **Enable the proxy (orange cloud) on your A/AAAA records.**

  A proxied record hides your origin IP. An unproxied (grey cloud) record exposes it.

  ```
  A    yourdomain.com        →  YOUR.SERVER.IP     [orange cloud = PROXIED]
  A    www.yourdomain.com    →  YOUR.SERVER.IP     [orange cloud = PROXIED]
  ```

  > **Do NOT proxy:** MX records (email), subdomains used for direct SSH access, internal records.

---

## 3. Origin IP Cloaking — the Critical Step

Cloudflare only hides your IP if traffic to your origin is locked down. If port 80/443 accepts connections from anywhere, an attacker can scan the internet and find your server directly.

- [ ] **Lock your server's firewall to accept HTTP/HTTPS only from Cloudflare IPs.**

  Cloudflare publishes their IP ranges at: https://www.cloudflare.com/ips/

  Apply with UFW on your VPS:

  ```bash
  # Remove any existing broad HTTP/HTTPS rules
  ufw delete allow 80/tcp
  ufw delete allow 443/tcp

  # Allow only Cloudflare IPv4 ranges on 80 and 443
  for ip in $(curl -s https://www.cloudflare.com/ips-v4); do
    ufw allow from "$ip" to any port 80 proto tcp
    ufw allow from "$ip" to any port 443 proto tcp
  done

  # If your server uses IPv6
  for ip in $(curl -s https://www.cloudflare.com/ips-v6); do
    ufw allow from "$ip" to any port 80 proto tcp
    ufw allow from "$ip" to any port 443 proto tcp
  done

  ufw reload
  ufw status verbose
  ```

  > **Keep SSH open to your own IP:** Do not accidentally lock yourself out. SSH (port 22 or custom) should already be allowed to your IP; this step only changes HTTP/HTTPS rules.

- [ ] **Configure nginx to restore real client IP from Cloudflare headers.** This is mandatory — without it, `$remote_addr` in nginx is a Cloudflare edge IP, not the visitor's real IP. Rate limiting, fail2ban, and IP-based access controls will all target Cloudflare's shared IPs instead of actual attackers.

  Add to your nginx config (in `http {}` block or per-server block):

  ```nginx
  # Tell nginx to trust Cloudflare IPs and extract real client IP from CF-Connecting-IP
  # Cloudflare IPv4 ranges (update periodically — or automate with the script below)
  set_real_ip_from 103.21.244.0/22;
  set_real_ip_from 103.22.200.0/22;
  set_real_ip_from 103.31.4.0/22;
  set_real_ip_from 104.16.0.0/13;
  set_real_ip_from 104.24.0.0/14;
  set_real_ip_from 108.162.192.0/18;
  set_real_ip_from 131.0.72.0/22;
  set_real_ip_from 141.101.64.0/18;
  set_real_ip_from 162.158.0.0/15;
  set_real_ip_from 172.64.0.0/13;
  set_real_ip_from 173.245.48.0/20;
  set_real_ip_from 188.114.96.0/20;
  set_real_ip_from 190.93.240.0/20;
  set_real_ip_from 197.234.240.0/22;
  set_real_ip_from 198.41.128.0/17;
  # Cloudflare IPv6 ranges
  set_real_ip_from 2400:cb00::/32;
  set_real_ip_from 2606:4700::/32;
  set_real_ip_from 2803:f800::/32;
  set_real_ip_from 2405:b500::/32;
  set_real_ip_from 2405:8100::/32;
  set_real_ip_from 2a06:98c0::/29;
  set_real_ip_from 2c0f:f248::/32;

  real_ip_header CF-Connecting-IP;
  real_ip_recursive on;
  ```

  > **What this does:** After this config, `$remote_addr` in nginx equals the visitor's real IP. Rate limiting zones, fail2ban log parsing, and access control rules all work on the correct IP. Without it, a single attacker can trigger your rate limit for ALL visitors (because they all share the same Cloudflare edge IP from nginx's perspective).
  >
  > **Automate IP range updates** — Cloudflare occasionally adds ranges. The quarterly update script in Section 3 can be extended to also regenerate nginx's `set_real_ip_from` block.


- [ ] **Create a cron job to keep Cloudflare IP rules current** — Cloudflare occasionally updates their IP ranges.

  Create `/usr/local/bin/update-cloudflare-ips.sh`:

  ```bash
  #!/usr/bin/env bash
  # Remove old Cloudflare UFW rules and re-add current ones
  # Run quarterly or after Cloudflare announces IP range changes

  # Remove existing Cloudflare rules (assumes they have comment)
  ufw status numbered | grep "Cloudflare" | awk -F'[][]' '{print $2}' | sort -rn | while read num; do
    ufw --force delete "$num"
  done

  for ip in $(curl -s https://www.cloudflare.com/ips-v4); do
    ufw allow from "$ip" to any port 80 proto tcp comment "Cloudflare"
    ufw allow from "$ip" to any port 443 proto tcp comment "Cloudflare"
  done

  ufw reload
  ```

  > **Practical note:** Cloudflare rarely changes their IP ranges and announces changes in advance. A quarterly manual review is fine for most setups.

- [ ] **Verify origin IP is hidden** — search for your server IP at crt.sh, Shodan, or Censys. If it appears, you need a new IP from your VPS provider before cloaking is effective.

---

## 4. SSL/TLS Configuration

- [ ] **Set SSL/TLS mode to "Full (strict)"** in Cloudflare dashboard.

  Cloudflare → SSL/TLS → Overview → Full (strict)

  > **Why not "Flexible"?** Flexible mode means Cloudflare fetches your origin over plain HTTP. Your traffic is encrypted between user and Cloudflare, but unencrypted between Cloudflare and your server — which means Cloudflare can read it. Full (strict) requires a valid certificate on your origin (Let's Encrypt works).

- [ ] **Enable Minimum TLS Version: TLS 1.2.**

  Cloudflare → SSL/TLS → Edge Certificates → Minimum TLS Version → TLS 1.2

- [ ] **Enable TLS 1.3.**

  Cloudflare → SSL/TLS → Edge Certificates → TLS 1.3 → On

- [ ] **Enable HSTS** via Cloudflare.

  Cloudflare → SSL/TLS → Edge Certificates → HTTP Strict Transport Security (HSTS)
  - Max Age: 6 months minimum (1 year recommended)
  - Include subdomains: Yes (if all subdomains use HTTPS)
  - Preload: Yes (after verifying the site will always be HTTPS)

  > **Preload warning:** HSTS preload is a one-way door. Once your domain is in the browser preload list, HTTP will not work even if you remove HSTS. Only enable this if you are committed to HTTPS permanently.

- [ ] **Enable Always Use HTTPS.**

  Cloudflare → SSL/TLS → Edge Certificates → Always Use HTTPS → On

---

## 5. Security Settings

- [ ] **Security Level: Medium** (or High for high-risk sites).

  Cloudflare → Security → Settings → Security Level

  - Off: No challenge pages
  - Essentially Off: Very permissive
  - Low: Challenges known bad IPs
  - **Medium (recommended):** Challenges suspicious IPs
  - High: Challenges most non-browser traffic
  - I'm Under Attack: JavaScript challenge for everyone (use only during an active attack)

- [ ] **Challenge Passage: 30 minutes.**

  How long a challenged IP is allowed through without re-challenge.

- [ ] **Browser Integrity Check: On.**

  Challenges requests with unusual User-Agent strings (curl, python-requests, scanners).

- [ ] **Privacy Pass Support: On** — reduces challenges for legitimate Tor users.

---

## 6. WAF Rules

Cloudflare's WAF blocks requests matching known attack patterns — SQLi, XSS, path traversal, WordPress exploits. On the free tier, you get the OWASP ruleset and basic managed rules.

- [ ] **Enable Cloudflare Managed Rules.**

  Cloudflare → Security → WAF → Managed Rules → On

- [ ] **Enable OWASP Core Rule Set.**

  If available on your plan, enable OWASP CRS with paranoia level 1-2.

- [ ] **Add custom WAF rule for wp-login.php** — challenge anyone not from your IP range.

  Cloudflare → Security → WAF → Custom Rules → Create rule:

  ```
  Rule name: Protect wp-login
  If: (http.request.uri.path contains "/wp-login.php") 
      AND (not ip.src in {YOUR.HOME.IP/32})
  Then: Managed Challenge
  ```

  > **Or for shared/dynamic IP:** Use country-based challenge as noise reduction.

  ```
  Rule name: wp-login country challenge
  If: (http.request.uri.path contains "/wp-login.php") 
      AND (not ip.geoip.country in {"TR"})
  Then: Managed Challenge
  ```

  > **Country filtering reduces noise, not attackers.** Modern credential-stuffing infrastructure uses residential proxies and geo-exit nodes in every country. A country gate will stop opportunistic scanners but will not stop a targeted attack. Treat it as a low-cost annoyance for bots, not a meaningful authentication control. Always combine with rate limiting and strong passwords or 2FA.

- [ ] **Block known bad user agents** — automated scanners, exploit frameworks.

  ```
  Rule name: Block scanner UAs
  If: (http.user_agent contains "sqlmap")
      OR (http.user_agent contains "nikto")
      OR (http.user_agent contains "masscan")
      OR (http.user_agent contains "zgrab")
  Then: Block
  ```

---

## 7. Rate Limiting

Cloudflare free tier includes basic rate limiting (up to 10,000 requests/10 minutes free).

- [ ] **Rate limit wp-login.php** — 5 requests per minute per IP.

  Cloudflare → Security → WAF → Rate Limiting Rules → Create rule:
  ```
  Path: /wp-login.php
  Method: POST
  Requests: 5 per 60 seconds
  Action: Block for 3600 seconds
  ```

- [ ] **Rate limit wp-admin** — 60 requests per minute (legitimate admins rarely exceed this).

  ```
  Path: /wp-admin/*
  Requests: 60 per 60 seconds
  Action: Managed Challenge
  ```

---

## 8. Bot Management

- [ ] **Enable Bot Fight Mode** (free tier).

  Cloudflare → Security → Bots → Bot Fight Mode → On

  This challenges requests from known bot IP ranges. Legitimate crawlers (Googlebot, Bingbot) are whitelisted.

- [ ] **Enable Super Bot Fight Mode** (Pro tier and above).

  Adds machine-learning based bot detection. Worth upgrading for high-traffic sites.

---

## 9. DNS Security

See also the DNS Security section in `local-to-production-checklist.md`.

- [ ] **All A/AAAA records for web services should be proxied** (orange cloud).

- [ ] **MX records must NOT be proxied** — email goes directly to your mail server.

- [ ] **Add CAA record** to restrict certificate issuance.

  ```
  Type: CAA
  Name: yourdomain.com
  Value: 0 issue "letsencrypt.org"
  ```

- [ ] **Enable DNSSEC** in Cloudflare.

  Cloudflare → DNS → Settings → DNSSEC → Enable

  After enabling, Cloudflare shows you the DS record to add at your registrar. Add it.

---

## 10. Authenticated Origin Pulls

Authenticated origin pulls ensure your origin server only accepts requests that came through Cloudflare — even if someone discovers your IP. Cloudflare sends a client certificate; your server verifies it.

- [ ] **Enable Authenticated Origin Pulls** in Cloudflare.

  Cloudflare → SSL/TLS → Origin Server → Authenticated Origin Pulls → On

- [ ] **Download Cloudflare's origin pull certificate.**

  The certificate is available at: https://developers.cloudflare.com/ssl/static/authenticated_origin_pull_ca.pem

  Save it to your server:

  ```bash
  curl -o /etc/ssl/cloudflare-origin-pull-ca.pem \
    https://developers.cloudflare.com/ssl/static/authenticated_origin_pull_ca.pem
  ```

- [ ] **Configure Nginx to verify Cloudflare's client certificate.**

  Add to your nginx server block:

  ```nginx
  ssl_client_certificate /etc/ssl/cloudflare-origin-pull-ca.pem;
  ssl_verify_client on;
  ```

  > **Lockout warning: `ssl_verify_client on` makes your origin unreachable without a Cloudflare client certificate.** During a Cloudflare outage, a DNS misconfiguration, or when you need to connect to the origin directly (e.g. to restore after a Cloudflare configuration error), nginx will reject all connections. Before enabling this, ensure you have an emergency access path that does not go through Cloudflare — typically your VPS provider's web console (Hetzner Console, DigitalOcean Droplet Console) or a dedicated management IP that bypasses the nginx listener. If you are using IP allowlisting (Section 3), that already limits origin access to Cloudflare IPs and provides similar protection; AOP then adds a second factor rather than being the sole gate.
  >
  > **Note:** This requires SSL termination at nginx level (not via Docker internal HTTP). If Cloudflare sends to port 80 (internal HTTP), AOP via mTLS does not apply — use IP allowlisting (Section 3) as your primary protection.
  >
  > **Let's Encrypt renewal with mTLS enabled:** HTTP-01 ACME challenge works through Cloudflare's proxy (Cloudflare forwards the challenge to origin and sends its own client cert). However, if your certbot is configured to contact the origin directly (bypassing Cloudflare), renewal will fail because nginx requires Cloudflare's client cert. **Use DNS-01 challenge** to avoid this entirely — certbot validates via a DNS TXT record and never makes an HTTP connection to your origin. With Cloudflare DNS, use the `certbot-dns-cloudflare` plugin with a scoped API token (Zone → DNS → Edit).

---

## 11. Cloudflare API Token Restriction

- [ ] **Never use the Global API Key** in scripts or CI/CD. It has full access to your entire Cloudflare account.

- [ ] **Create scoped API tokens** with minimum required permissions.

  Cloudflare → My Profile → API Tokens → Create Token

  For DNS-only operations (e.g. cert renewal via ACME/certbot):
  ```
  Zone → DNS → Edit
  Specific zone: yourdomain.com
  ```

  For cache purging in CI/CD:
  ```
  Zone → Cache Purge → Purge
  Specific zone: yourdomain.com
  ```

- [ ] **Set IP filtering on tokens** — restrict the API token to only work from your CI/CD server's IP.

- [ ] **Rotate tokens** after team member changes or potential exposure.

---

## 12. Verification Checklist

After completing the setup, verify everything works:

```bash
# Confirm your server only accepts Cloudflare IPs
# Try connecting directly to your origin IP (should fail for HTTP/HTTPS)
curl -v --max-time 5 http://YOUR.SERVER.IP/
# Expected: connection refused or timeout

# Confirm the site works through Cloudflare
curl -sI https://yourdomain.com | grep -iE "cf-ray|server"
# Should see: cf-ray header (Cloudflare) and server: cloudflare

# Confirm HTTPS enforcement
curl -sI http://yourdomain.com | grep -i location
# Should redirect to https://

# Verify HSTS header
curl -sI https://yourdomain.com | grep -i strict-transport
# Should return: strict-transport-security: max-age=...

# Check origin IP is not exposed in response headers
curl -sI https://yourdomain.com | grep -iE "x-powered-by|server|x-forwarded"

# Verify wp-login.php WAF rule fires
# (test from a non-whitelisted IP — should get challenge page, not the login form)
```

---

*Last reviewed: 2025 | Applies to: Cloudflare Free/Pro, Nginx*
