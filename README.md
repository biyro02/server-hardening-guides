# Server Hardening Guides

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/biyro02/server-hardening-guides)](https://github.com/biyro02/server-hardening-guides/commits/main)
[![Stars](https://img.shields.io/github/stars/biyro02/server-hardening-guides?style=flat)](https://github.com/biyro02/server-hardening-guides/stargazers)
[![Tested](https://img.shields.io/badge/tested-16%20attack%20vectors-brightgreen)](#what-makes-these-different)

Production security checklists for self-hosted web applications — tested against 16 attack vectors on a live WordPress / Docker / Nginx stack, with every control verified before it was written. Covers server hardening, PHP (Laravel, Symfony, CodeIgniter, legacy), and JavaScript frontends (React, Vue, Angular, Next.js).

---

## Guides

**Server & Infrastructure**

| File | Covers |
|------|--------|
| [linux-server-hardening.md](linux-server-hardening.md) | SSH hardening, UFW + Docker firewall bypass fix, fail2ban, kernel sysctl, Docker security (`read_only`, `cap_drop`, tmpfs), encrypted backups (restic, append-only), log rotation |
| [cloudflare-hardening.md](cloudflare-hardening.md) | Origin IP cloaking, CF-only UFW lockdown, SSL Full Strict, WAF rules, rate limiting, Cloudflare-bypass-via-Cloudflare mitigation, Authenticated Origin Pulls, Cloudflare Tunnel |
| [local-to-production-checklist.md](local-to-production-checklist.md) | Env separation, secrets audit, post-deploy verification, rollback, CI/CD security, DNS security (CAA, registrar lock, DNSSEC) |
| [security-audit-automation.md](security-audit-automation.md) | Lynis, rkhunter, AIDE, auditd, CrowdSec + Cloudflare bouncer, WPScan scheduling, automated weekly digest, operational drift checks |
| [incident-response-checklist.md](incident-response-checklist.md) | Evidence collection, isolation, investigation (webshells, persistence, DB backdoors), recovery, credential rotation, IOC reference |
| [disaster-recovery.md](disaster-recovery.md) | Playbooks for 8 scenarios: accidental deletion, DB corruption, failed deploy, full server rebuild, ransomware, domain hijacking, Cloudflare account compromise, lost DB password. |

**Application Security**

| File | Covers |
|------|--------|
| [wordpress-server-hardening.md](wordpress-server-hardening.md) | PHP hardening (`open_basedir`, `disable_functions`, Chankro bypass, FFI, PHAR), nginx rules, REST API lockdown, login protection, Application Passwords, plugin supply chain vetting, SPF/DKIM/DMARC |
| [php-application-hardening.md](php-application-hardening.md) | Universal PHP (type juggling, XXE, SSRF, unserialize, file inclusion), legacy PHP 5.x/7.x with "cannot upgrade" mitigations, Laravel, Symfony, CodeIgniter, Phalcon, Pure PHP — each section self-contained with stack detection |
| [frontend-security.md](frontend-security.md) | Universal JS (CORS, CSP, prototype pollution, localStorage vs httpOnly), jQuery/Pure JS, React, Vue.js, Angular, Next.js/Nuxt.js, build tools (Webpack/Vite), dependency supply chain — skip-navigation for each framework |

---

## Who Is This For

**This is for you if:**
- You self-host on a VPS and run Docker Compose + Nginx
- You build PHP applications (WordPress, Laravel, Symfony, CodeIgniter, or legacy PHP)
- You build JavaScript frontends (React, Vue, Angular, Next.js, or plain jQuery)
- You have no dedicated security engineer
- You want to understand *why* each control exists, not just copy-paste commands

**Also useful if:** you are stuck on an older PHP version or legacy framework and cannot upgrade — both application guides include "if you cannot upgrade" mitigations for legacy stacks.

**Threat model:** single-tenant VPS, Docker Compose workloads, 1–5 person team. PHP and JS guides apply regardless of deployment target.

**Not for:** managed platforms (Heroku, Render, AWS ECS), Kubernetes, or regulated industries with compliance requirements (CIS/SOC 2/PCI-DSS) — treat these as a floor, not a ceiling.

---

## How to Use

These are checklists, not scripts. Read each item and understand the reasoning before applying it.

**Server hardening — work in this order:**

1. `linux-server-hardening.md` — base server
2. `cloudflare-hardening.md` — strongly recommended
3. `local-to-production-checklist.md` — before going live

**Application security — pick what applies to your stack:**

4. `wordpress-server-hardening.md` — WordPress + PHP-FPM + nginx
5. `php-application-hardening.md` — Laravel / Symfony / CodeIgniter / legacy PHP / pure PHP
6. `frontend-security.md` — React / Vue / Angular / Next.js / jQuery

Each section in the PHP and JS guides starts with a stack-detection block so you can skip sections that do not apply to your project.

**Ongoing — set up on day 1, read before you need them:**

7. `security-audit-automation.md`
8. `incident-response-checklist.md`
9. `disaster-recovery.md` — run the backup drill monthly

---

## What Makes These Different

Most hardening guides list controls. These document *mistakes in the controls themselves*. Every item below was found in real hardening advice and silently fails in production:

- **Chankro `disable_functions` bypass** — blocking `exec`, `system`, `shell_exec` is not enough. `putenv('LD_PRELOAD=/tmp/evil.so') + mail()` forks a sendmail subprocess outside PHP's `disable_functions` checks entirely. `mail`, `putenv`, and `dl` must also be blocked.
- **nginx `add_header` inheritance** — any `location` block with its own `add_header` silently drops *all* parent `server`-level headers. Security headers disappear for login pages, admin pages, and PHP endpoints — the highest-risk locations.
- **`opcache.restrict_api = ""`** — PHP documentation: "If non-empty, checks that the current working directory is within the specified path." An empty string means *no restriction at all*, the opposite of what every guide comments it does.
- **fail2ban sshd on Ubuntu 22/24** — sshd logs exclusively to journald, not `/var/log/auth.log`. `backend = auto` finds no log file and silently bans nothing. Zero errors, zero bans.
- **fail2ban wp-login regex** — `^<HOST> .* "POST /wp-login.php` matches every POST including your own successful logins. The filter must gate on response codes (401/403/429) or it bans the admin.
- **Cloudflare-bypass-via-Cloudflare** — an attacker who discovers your origin IP can route requests through their own Cloudflare account. Your UFW rules allow all Cloudflare IPs, so they pass. Your WAF and rate limits do not apply. Authenticated Origin Pulls does not close this — the AOP certificate is issued by Cloudflare's CA and is identical for all accounts.
- **auditd and AIDE watching wrong paths** — both tools watch host filesystem paths. When WordPress runs in a Docker named volume, `/var/www/html` does not exist on the host. Rules targeting it are silently ignored.

- **PHP type juggling auth bypass** — `"0e1234" == "0e5678"` evaluates as `0 == 0` in PHP loose comparison. MD5 and SHA1 produce "magic hashes" beginning with `0e` — any two such hashes compare equal. Password and token verification using `==` instead of `hash_equals()` is bypassable with a known collision string.
- **`REACT_APP_SECRET` bundled into the JS build** — any environment variable prefixed `REACT_APP_` (or `VITE_`, `NEXT_PUBLIC_`, `VUE_APP_`) is compiled into the JavaScript bundle and readable by any user who opens DevTools. These prefixes exist to expose values to the frontend. Using them for secrets is not a misconfiguration — it is working as designed.
- **`getServerSideProps` embedding database objects in page HTML** — Next.js serializes the entire return value of `getServerSideProps` into `__NEXT_DATA__` in the HTML response. Returning a database row without filtering fields sends password hashes, internal IDs, and admin flags to every visitor in plaintext.

These were found by testing against a live setup, running Nikto / WPScan / nmap / custom scripts, adversarial review by ChatGPT, Claude Opus 4.7, and DeepSeek, and code review of real PHP and JS application patterns. Corrections are in the [commit history](https://github.com/biyro02/server-hardening-guides/commits/main). Findings that are valid for higher threat models or different stacks are tracked as [open issues](https://github.com/biyro02/server-hardening-guides/issues).

---

## Out of Scope

- **SIEM / Wazuh** — operationally heavy; not appropriate as a default for small teams
- **Suricata / Snort** — overkill for most single-site VPS setups
- **CIS benchmark compliance** — CIS Ubuntu goes deeper; these guides are practical, not compliance-focused
- **Multi-tenant PHP-FPM isolation** — only relevant for bare-metal multi-site hosting, not single-site Docker

---

## Contributing

Issues and pull requests welcome. If you find something wrong, outdated, or missing — especially if you have verified it against a real attack — open an issue.

## License

[GNU General Public License v3.0](LICENSE) — derivative works must remain open source under the same terms.
