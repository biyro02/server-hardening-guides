# Server Hardening Guides

Production security checklists for self-hosted web applications — based on real-world hardening of a WordPress / Docker / Nginx stack on a VPS, validated through penetration testing, 16-vector red-team scenarios, and multi-model adversarial review.

## Who Is This For

**This is for you if:**
- You self-host a web application on a VPS (DigitalOcean, Vultr, OVH, Linode, or similar)
- You run Docker Compose workloads with Nginx as a reverse proxy
- You use WordPress, or a PHP-based application behind Nginx
- You have no dedicated security engineer — you are the security engineer
- You want to understand *why* each control exists, not just copy-paste commands

**This is not for you if:**
- You deploy to managed platforms (Heroku, Render, Fly.io, AWS ECS)
- You run Kubernetes
- You work in a regulated industry with compliance requirements (CIS benchmarks, SOC 2, PCI-DSS) — treat these as a floor, not a ceiling

**You will get the most out of this if:**
- You are comfortable with SSH, Docker, and basic Linux administration
- You are deploying your first production server and want to do it right
- You have an existing server and are asking "what have I missed?"

## What Is Notable About This

Most hardening guides list controls. These guides document the *mistakes found in the controls themselves*:

- **Chankro `disable_functions` bypass** — blocking `exec`, `system`, `shell_exec` is not enough. `putenv('LD_PRELOAD=/tmp/evil.so') + mail()` forks a sendmail subprocess that loads the shared object entirely outside PHP's `disable_functions` checks. `mail`, `putenv`, and `dl` must also be blocked.
- **nginx `add_header` inheritance** — any `location` block with its own `add_header` directive silently drops *all* `add_header` directives from the parent `server` block. Security headers set globally disappear for login pages, admin pages, and PHP endpoints — the highest-risk locations.
- **`opcache.restrict_api = ""`** — PHP documentation: "If non-empty, checks that the current working directory is within the specified path." An empty string means *no restriction at all*. Commenting "prevents scripts from modifying the opcode cache" while using `""` is the opposite of the stated intent.
- **fail2ban sshd backend on Ubuntu 22/24** — sshd logs exclusively to journald, not `/var/log/auth.log`. Using `backend = auto` with `logpath = /var/log/auth.log` silently bans nothing. The wrong backend produces zero errors and zero bans.
- **fail2ban wp-login regex matching successful logins** — `^<HOST> .* "POST /wp-login.php` matches every POST including your own successful logins. The filter must gate on response codes (401/403/429) or it bans the admin.
- **Cloudflare-bypass-via-Cloudflare** — an attacker who discovers the origin IP can route requests through their own Cloudflare account. Origin UFW rules allow all Cloudflare IP ranges, so the requests pass the firewall. The victim's WAF rules and rate limits do not apply. Authenticated Origin Pulls does not close this gap — the client certificate is issued by Cloudflare's CA and is the same for all accounts.
- **auditd and AIDE monitoring wrong paths** — both tools watch host filesystem paths. When WordPress runs in a Docker named volume, `/var/www/html` does not exist on the host. Rules targeting it are silently ignored.

These were found by running Nikto, WPScan, nmap, and custom scripts against a live setup; testing 16 attack vectors; and submitting each guide to ChatGPT, Claude Opus 4.7, and DeepSeek with adversarial review instructions.

## Contents

| File | What It Covers |
|------|----------------|
| [linux-server-hardening.md](linux-server-hardening.md) | Base Linux/VPS hardening: SSH, UFW+Docker firewall bypass, fail2ban, kernel sysctl, Docker security, attack surface reduction, filesystem hardening, encrypted backups (restic), log rotation, monitoring |
| [wordpress-server-hardening.md](wordpress-server-hardening.md) | WordPress-specific: wp-config constants, Nginx rules, PHP hardening (open_basedir, opcache, disable_functions), REST API lockdown, login security, WP-admin access strategy (IP allowlist / Basic Auth), plugin supply chain vetting, email security (SPF/DKIM/DMARC) |
| [local-to-production-checklist.md](local-to-production-checklist.md) | Full deployment lifecycle: env separation, secrets audit, Docker safety, post-deploy verification, rollback procedure, CI/CD security (branch protection, Dependabot, pinned Actions), DNS security (CAA records, registrar lock) |
| [cloudflare-hardening.md](cloudflare-hardening.md) | Cloudflare setup: origin IP cloaking, Cloudflare-only UFW lockdown, SSL Full Strict, WAF rules, rate limiting, bot fight mode, DNSSEC, authenticated origin pulls, API token restriction |
| [incident-response-checklist.md](incident-response-checklist.md) | What to do when compromised: evidence collection, isolation, investigation playbook, recovery, credential rotation, IOC reference |
| [disaster-recovery.md](disaster-recovery.md) | Recovery playbooks for 8 scenarios: accidental deletion, DB corruption, failed deployment, full server rebuild, ransomware, domain hijacking, Cloudflare account compromise, lost DB password. Includes monthly backup drill script and RTO estimates. |
| [security-audit-automation.md](security-audit-automation.md) | Recurring audit tools: Lynis, rkhunter, AIDE (file integrity), auditd, CrowdSec, scheduled WPScan, automated weekly security digest |

## How to Use

These are checklists, not scripts. Work through each item and understand *why* before applying — every entry explains the reasoning so you can make informed decisions for your setup.

**First deployment — work in order:**

1. `linux-server-hardening.md` — base server security
2. `wordpress-server-hardening.md` — application layer security
3. `local-to-production-checklist.md` — before and after going live
4. `cloudflare-hardening.md` — put Cloudflare in front (strongly recommended)

**Ongoing:**

5. `security-audit-automation.md` — set up recurring scans on day 1
6. `incident-response-checklist.md` — read it *before* you need it
7. `disaster-recovery.md` — read it *before* you need it; run the backup drill monthly

## What This Is Based On

These guides were written after:
- Running Nikto, WPScan, nmap, and custom scripts against a live production WordPress/Nginx/Docker setup
- Testing 16 attack vectors: brute-force, REST API abuse, PHP object injection, BREACH, request smuggling (CL.TE), cache poisoning, second-order stored XSS, timing oracle on nonce validation, supply chain simulation, ransomware-scenario red team
- Fixing every discovered vulnerability and validating the fixes
- Multi-model adversarial review: each guide was independently reviewed by ChatGPT 5.5, Claude Opus 4.7, and DeepSeek with instructions to find bugs, incorrect advice, and security gaps

The checklists reflect what was actually found, exploited in testing, and fixed — not theoretical recommendations.

## Verified Fixes from Adversarial Review

After submitting these guides to three independent models with adversarial instructions, the following real errors were found and corrected. Each one is listed here because it was a non-obvious mistake that would have caused silent failures or introduced new risks in production.

### Corrected Bugs

**fail2ban backend for sshd (Ubuntu 22/24)** — The original guide said to use `backend = auto` for the sshd jail with `logpath = /var/log/auth.log`. On Ubuntu 22.04 and 24.04, sshd logs exclusively to journald, not to `/var/log/auth.log`. The `auto` backend finds no log file and silently bans nothing. The `systemd` backend must be used for sshd jails on systemd-based distros. Nginx jails remain `backend = auto` (file-based). *Found by Claude Opus 4.7.*

**fail2ban wp-login failregex matching all POSTs** — The original failregex `^<HOST> .* "POST /wp-login.php` matched every POST to wp-login.php, including successful logins. This means the filter would ban your own admin IP after 5 logins. Corrected to match only failed responses: `^<HOST> .* "POST /wp-login\.php[^"]*" (401|403|429) `. *Found by Claude Opus 4.7.*

**OPcache validate_timestamps = 0 with git-pull deploys** — The original security.ini had `opcache.validate_timestamps = 0`, disabling file change detection entirely. On a server that deploys via `git pull` without an explicit `php-fpm reload`, code changes are silently ignored — the old bytecode keeps running until a restart. Corrected to `validate_timestamps = 1`, `revalidate_freq = 2`. *Found by Claude Opus 4.7.*

**X-XSS-Protection header** — The original nginx config included `add_header X-XSS-Protection "1; mode=block"`. This header was removed from all modern browsers (Chrome 78+, Firefox, Safari). It has no effect on current browsers and can trigger cross-site scripting vulnerabilities (UXSS) in legacy Internet Explorer by interfering with inline scripts that were not attacks. Removed; CSP already provides equivalent protection. *Found by ChatGPT 5.5.*

**DOCKER-USER iptables example missing ESTABLISHED/RELATED** — The original example used `iptables -I DOCKER-USER -i eth0 ! -s 127.0.0.1 -j DROP` as a one-liner to block direct container access. This drops return traffic from outbound connections made by containers — breaking DNS resolution, package downloads, and any API calls containers make to the internet. A complete implementation requires allowing `ESTABLISHED,RELATED` traffic first. The simpler and more reliable fix (binding containers to `127.0.0.1` in the ports directive) is now the primary recommendation. *Found by Claude Opus 4.7.*

**Authenticated Origin Pulls: ssl_verify_client on causes complete lockout** — The Cloudflare AOP section recommended `ssl_verify_client on` in nginx without noting that during a Cloudflare outage, partial misconfiguration, or when connecting directly via VPS console, the origin server becomes completely unreachable — nginx rejects all connections without the Cloudflare client certificate. The fix is to document this risk explicitly and ensure an emergency access plan exists (VPS provider console, or a management IP that bypasses nginx). *Found by Claude Opus 4.7.*

### Security Theater Removed

The following items were removed or caveated because they provide negligible security value while adding real operational cost:

**`chattr +i /etc/passwd /etc/shadow /etc/group`** — Making these files immutable sounds protective. In practice, any attacker with root access (a prerequisite for most of these threats) can run `chattr -i` in one command. Meanwhile, the immutable flag breaks every legitimate account management tool: `useradd`, `passwd`, `addgroup`, shadow package updates, and PAM modules all fail. On a Docker server where accounts are rarely touched, this is a source of confusing, hard-to-diagnose breakage. Removed.

**Removing gcc/make from the host** — Recommended as attack surface reduction. On a Docker server, compilation happens inside containers during image builds, not on the host. An attacker who has compromised a container doesn't need host compilers — they can download pre-compiled binaries, compile inside the container, or use pure-PHP exploitation tools. Removing host compilers adds an operational tax (package updates fail, debugging tools break) with no meaningful security benefit in the Docker context. Removed as a recommended step.

**Blacklisting cramfs/squashfs/udf kernel modules** — Blacklisting squashfs breaks snap packages on Ubuntu 22/24 (snap is squashfs-based). Blacklisting udf breaks ISO mounting. These modules are not realistic attack vectors on a VPS running Docker — mounting untrusted filesystem images is not a typical post-exploitation step via a PHP application. Replaced with a targeted caveat: only blacklist these if you are certain snap is not in use and have a specific reason to do so.

### New Controls Added

The following were not in the original guides and were added based on the review synthesis:

- **Docker `read_only: true` + tmpfs** on the application container. Makes the container's overlay filesystem layer immutable; named volumes remain writable. Closes webshell persistence and post-RCE filesystem modification. Called the highest-impact single change by all three models.
- **Container logging limits** (`max-size: 10m, max-file: 3`). Prevents log flooding from filling the host disk and silently disabling fail2ban.
- **MariaDB `--secure-file-priv=NULL`**. Disables `LOAD DATA INFILE` and `SELECT INTO OUTFILE` entirely. Blocks the documented UDF-to-RCE attack path through the database.
- **`phar.readonly = On`**. Prevents PHAR archive creation from PHP, reducing the gadget chain surface for PHAR deserialization attacks.
- **REST API write rate limiting via nginx method map**. Limits `POST/PUT/DELETE/PATCH` to `/wp-json/` per IP without rate-limiting GET requests. Uses `map $request_method` to produce an empty key for read methods — nginx ignores rate limits on empty keys, avoiding the `if-is-evil` anti-pattern.
- **fail2ban wp-login failregex: response-code gating**. Filter updated to match only failed login responses (401/403/429), not all POSTs.

### Round 2 Fixes (DeepSeek + ChatGPT 5.5)

**OPcache contradiction in wordpress guide** — README was updated after PR #4 but `wordpress-server-hardening.md` still recommended `validate_timestamps = 0`. Both models independently flagged it. Fixed to match. *Both models.*

**Cloudflare `set_real_ip_from` missing — critical** — Without `set_real_ip_from` and `real_ip_header CF-Connecting-IP` in nginx, `$remote_addr` is a Cloudflare edge IP shared by millions of users. Rate limiting, fail2ban, and IP-based access controls all target the wrong IP. A single attacker's traffic could trigger rate limits for all visitors. Added as a mandatory step in the Cloudflare guide with the full current IP range list. *ChatGPT 5.5.*

**CVE-2024-6387 (regreSSHion)** — A signal handler race condition in OpenSSH 8.5p1–9.7p1 allows unauthenticated remote root RCE on glibc-based Linux. Public exploit code exists. Ubuntu 22.04 and 24.04 were affected. `MaxAuthTries` and key-only auth do not mitigate it — patching is the only fix. Added to SSH section with version check commands. *DeepSeek.*

**Backup format inconsistency** — The backup section created `.sql` but verified `.sql.gz`, leaving operators with a false integrity check. Fixed to pipe mysqldump directly through gzip, creating `.sql.gz` at dump time. *ChatGPT 5.5.*

**htpasswd `chmod 644`** — World-readable htpasswd files expose bcrypt hashes to all local users and services. Fixed to `chown root:www-data` + `chmod 640`. *ChatGPT 5.5.*

**FFI extension bypass** — PHP's FFI extension (7.4+) allows calling arbitrary C library functions from PHP, bypassing `disable_functions` entirely. Added `ffi.enable = false` to PHP hardening section. Also documented the `chdir` + `ini_set` technique that bypasses `open_basedir`. *DeepSeek.*

**auditd log rotation not configured** — Without `max_log_file` and `max_log_file_action = ROTATE` in `auditd.conf`, `/var/log/audit/audit.log` grows unbounded and auditd eventually stops logging new events. Added rotation config. *DeepSeek.*

**ip6tables for DOCKER-USER** — iptables and ip6tables are separate. A DOCKER-USER rule only in iptables leaves IPv6-based container access unfiltered. Added ip6tables equivalent. *DeepSeek.*

**Country blocking false confidence** — Guide framed country-based wp-login filtering as a meaningful security control. Changed to "Block" → "Managed Challenge" and added explicit note that residential proxy infrastructure bypasses geo-filtering, making it noise reduction only. *ChatGPT 5.5.*

**fail2ban Docker log path clarification** — Added note explaining that if nginx runs inside a container, fail2ban cannot watch `/var/log/nginx/access.log` on the host (container logs go to Docker's log driver). Documented the two solutions: host-level nginx, or log volume mount. *DeepSeek.*

**certbot + mTLS DNS-01 recommendation** — Added note recommending DNS-01 ACME challenge when Authenticated Origin Pulls is enabled, to avoid potential HTTP-01 failure modes when the challenge request bypasses Cloudflare's proxy. *DeepSeek.*

**`read_only: true` container restore procedure** — Added clarification that named volumes remain writable with `read_only: true` containers; restore scripts should target volume paths. *DeepSeek.*

### Round 3 Fixes (Claude Opus 4.7)

**nginx `add_header` inheritance — critical correctness bug** — In nginx, when any `location` block contains an `add_header` directive, it inherits **none** of the `add_header` directives from the parent `server` or `http` block. The wordpress guide's security headers block (HSTS, X-Frame-Options, CSP, etc.) was set at the server level while child location blocks for `/wp-login.php`, `/wp-admin/`, and others had their own `add_header` entries — silently dropping all security headers for those paths. Fixed by adding an explicit warning and documenting the `include snippets/security-headers.conf` pattern. *Claude Opus 4.7.*

**X-XSS-Protection still present in wordpress guide** — The round 1 fix removed this header from the README description and from the production nginx config, but the `wordpress-server-hardening.md` checklist still listed `add_header X-XSS-Protection "1; mode=block" always`. Removed. *Caught during round 3 review.*

**Chankro disable_functions bypass: `mail`, `putenv`, `dl` not blocked** — The original `disable_functions` list blocked execution functions (`exec`, `system`, `shell_exec`, etc.) but left open the Chankro bypass path: `putenv('LD_PRELOAD=/tmp/evil.so')` + `mail()` forks a sendmail subprocess that inherits `LD_PRELOAD` and loads the malicious shared object entirely outside PHP's disable_functions checks. `dl()` loads PHP extensions at runtime, also bypassing disable_functions. All three added to `disable_functions`. WordPress with an SMTP relay plugin does not require any of them. *Claude Opus 4.7.*

**`opcache.restrict_api = ""` is unrestricted — misleading comment** — The PHP documentation states: "If non-empty, the OPcache will check that the current working directory is within the specified directory path." An empty string `""` means no restriction at all — any PHP script from any path can call `opcache_invalidate()` and `opcache_reset()`. The original comment said "Prevent scripts from modifying the opcode cache" but the value did exactly the opposite. Fixed to `opcache.restrict_api = /var/www/html`. *Claude Opus 4.7.*

**WP-Cron `--allow-root` in docker exec** — The server-side cron command used `docker exec WORDPRESS_CONTAINER wp cron event run --due-now --allow-root`. Running WP-CLI as root inside the container means file caches and temp files created by WP-CLI are root-owned, which causes permission errors for subsequent www-data requests. Fixed to `docker exec --user www-data`. *Claude Opus 4.7.*

**"Cloudflare-bypass-via-Cloudflare" attack pattern not documented** — An attacker who discovers the origin IP can route requests through their own Cloudflare account. The origin UFW rules allow all Cloudflare IP ranges, so the requests pass the firewall. The victim's WAF rules, rate limits, and bot protection do not apply to requests routed through the attacker's zone. Critically: Authenticated Origin Pulls does not close this gap — the Cloudflare AOP certificate is issued by Cloudflare's CA and is the same for all accounts. Two correct mitigations documented: (1) a custom `X-Origin-Verify` secret header injected by the victim's CF zone and verified in nginx; (2) Cloudflare Tunnel (`cloudflared`), which requires no inbound ports at all. Added to `cloudflare-hardening.md` Section 1. *Claude Opus 4.7.*

**certbot DNS-01 required in local-to-production checklist** — The Infrastructure Checklist mentioned `certbot renew --dry-run` but did not note that HTTP-01 ACME challenge fails when `ssl_verify_client on` (Authenticated Origin Pulls) is configured — nginx rejects the challenge connection because it requires Cloudflare's client cert. Added DNS-01 instructions with `certbot-dns-cloudflare` plugin to `local-to-production-checklist.md` Section 4. *Claude Opus 4.7.*

**Runtime virtual patching not mentioned** — Plugin CVE disclosure creates a window between public disclosure and the next maintenance window where the plugin can be updated. Patchstack and Wordfence both provide virtual patching (WAF rules that block specific CVE exploit patterns) to cover this window. Added to Plugin Supply Chain Security section. *Claude Opus 4.7.*

**Docker image accumulation fills disk** — Old image layers are not automatically removed after `docker compose pull`. On a VPS with a small disk, this silently fills the disk over weeks, eventually causing MariaDB write failures. Added weekly `docker image prune -f` cron job to Docker Security section of `linux-server-hardening.md`. *Claude Opus 4.7.*

**auditd and AIDE rules target host paths that don't exist for Docker volumes** — The auditd and AIDE configurations monitored `/var/www/html/wp-config.php`, `/var/www/html/wp-content/uploads`, and `/var/www/html/wp-includes` — but when WordPress runs in a Docker container with named volumes, these host paths do not exist (or point to overlay layers that monitoring tools cannot traverse). Added notes explaining how to find the real volume mount path via `docker inspect VOLUME_NAME | grep Mountpoint`. *Claude Opus 4.7.*

**DKIM selector "mailo" example lacks provider context** — `mailo` is Mailgun's default DKIM selector name. The guide used it without noting it is provider-assigned and provider-specific. SendGrid, Brevo, and other providers use different selector names. Added clarifying note. *Claude Opus 4.7.*

## What Was Rejected from Reviews

Not every claim from adversarial review is valid. These were checked and rejected:

- **HTTP/2 continuation frame DoS → SSH brute force escalation chain** (DeepSeek): Framed as a connected attack path. Our setup uses HTTP/1.1 internally; the referenced CVE chain requires specific H2 implementations. Not applicable.
- **CVE-2023-34641 LD_PRELOAD via WP cron** (DeepSeek): Requires local write access to an LD_PRELOAD path. `read_only: true` on the container and `no-new-privileges: true` block this. Not a gap.
- **Dirty Pipe (CVE-2022-0847)** (DeepSeek): Affects kernel 5.8–5.16. Production kernel is 6.x. Not applicable.
- **"docker system prune daily is security theater"** (DeepSeek): Not in these guides — straw man.
- **"use .htaccess to block xmlrpc.php"** (DeepSeek): .htaccess is Apache-specific. These guides use nginx `deny all` location blocks. Not applicable.

**Round 2 rejections:**

- **nginx empty-key rate limit "tüm request'leri aynı bucket'a koyar"** (DeepSeek): False. From nginx documentation: "If the key value is an empty string, the request will not be limited." Empty key zones are ignored per-request, not shared. This is intentional nginx behavior and is how `map`-based selective rate limiting works. Verified against nginx source and documentation.
- **xmlrpc.php 404 returns PHP REQUEST_URI** (DeepSeek): Not applicable. The nginx config uses `location = /xmlrpc.php { deny all; return 404; }` — an nginx-level `return` directive. The request never reaches PHP-FPM. There is no PHP error page and no REQUEST_URI leakage.
- **Cloudflare WAF `ip.src in {IP/32}` is invalid syntax** (DeepSeek): False. Cloudflare's WAF expression language supports CIDR notation in the `in` operator. `ip.src in {1.2.3.4/32}` is valid. A `/32` is simply a single host — the syntax is verbose but correct.
- **Guide removes postfix, breaking abuse notification emails** (DeepSeek): The guide removes `cups`, `avahi`, `bluetooth`, and `ModemManager`. It does not remove postfix or any MTA. This finding attacked a recommendation that does not exist in the guide.
- **Supply chain: require signed commits and image digest pinning** (ChatGPT): For a 1-5 person team on a VPS, protected branches + PR reviews + Dependabot is the appropriate threat model. Signed commits and image digests add significant operational overhead with marginal benefit when the team controls the repository and the deploy key. Noted as a "raise the bar" option for higher threat models, not added as a default requirement.

**Round 3 rejections (Claude Opus 4.7):**

- **Cloudflare `set_real_ip_from` / `real_ip_header` not configured** (Opus): This was flagged as a new finding, but it was already fixed in Round 2 and is documented in `cloudflare-hardening.md` Section 3. Opus likely read cached GitHub content from before the Round 2 commit was pushed. Not a new gap.
- **PHP container `/tmp` mounted noexec** (Opus): Mounting the PHP container's `/tmp` as noexec would partially mitigate Chankro by preventing execution of the compiled `.so` file. However, PHP uses `/tmp` for session handling, upload temp files, and OPcache (depending on config). A noexec mount requires carefully redirecting all temp paths. The correct primary mitigation is disabling `mail` and `putenv` in `disable_functions` (implemented). noexec tmpfs as an additional layer is a valid hardening step for setups that have audited their PHP temp path usage.
- **Backup encryption missing, recommending GPG** (Opus): restic with a passphrase is already documented in the backup section and provides authenticated encryption (AES-256 in CTR mode + HMAC-SHA256). The finding suggested adding a full GPG key management workflow as an alternative. For a 1-5 person team, restic's built-in encryption is the correct recommendation — it is simpler, has built-in deduplication, and avoids GPG key management overhead.
- **Deploy sudoers `docker compose pull/up` allows container escape** (Opus): Valid concern — a malicious image pulled via the deploy pipeline could execute arbitrary code in a container that then escapes via a container CVE. This is a real threat in supply chain attack scenarios. The correct long-term fix is Cloudflare Tunnel (no inbound ports, no deploy SSH key needed) or a dedicated deploy token with only `docker compose up -d` permission (no pull). Noted as a known trade-off; full deploy pipeline redesign is out of scope for this checklist.
- **REST API filter hook `rest_authentication_errors` should be `rest_pre_dispatch`** (Opus): False. `rest_authentication_errors` is the conventional and correct WordPress hook for blocking unauthenticated access to REST API namespaces. The `if (!empty($result)) return $result` pattern correctly integrates with the WordPress auth pipeline. `rest_pre_dispatch` is for intercepting dispatch entirely and would require a different code pattern; it would not improve security here. Rejected.
- **npm `--ignore-scripts` required for CI** (Opus): Valid supply chain control for teams running `npm ci` in production. This stack is PHP/WordPress — npm is only used for frontend build tooling in development. There is no `npm install` in the production container or deploy pipeline for this setup. Applicable to teams with Node.js in the production path; out of scope here.

## Threat Model

These guides assume:
- A single-tenant VPS running Docker Compose workloads
- WordPress as the web application
- Nginx as the reverse proxy
- A VPS from any standard provider (no managed Kubernetes, no WAF appliance)
- A small team (1-5 people) without a dedicated security engineer

If your threat model is significantly higher (financial services, healthcare, government), treat these guides as a floor, not a ceiling.

## What Is Intentionally Not Covered

- **SIEM/Wazuh** — valuable but operationally heavy for a small team; not included
- **Intrusion detection systems (Suricata/Snort)** — overkill for most VPS setups
- **CIS benchmark compliance** — the CIS Ubuntu benchmark goes deeper on some items; these guides are practical not compliance-focused
- **Multi-tenant PHP-FPM isolation** — relevant only if hosting multiple unrelated sites on bare metal; not applicable to single-site Docker setups

## Contributing

Issues and pull requests welcome. If you find something wrong, outdated, or missing — especially if you have verified it against a real attack scenario — please open an issue.

## License

[GNU General Public License v3.0](LICENSE) — derivative works must remain open source under the same terms.
