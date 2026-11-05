# White-Box Audit Mode

**Read the running configuration of an existing server and compare it to the checklists**

> The other guides tell you how to configure a server. This one tells you how to prove what a server is *actually* running, with read-only commands, and how to turn the gaps into findings. Use it when an external (black-box) assessment marks [linux-server-hardening.md](linux-server-hardening.md) or [security-audit-automation.md](security-audit-automation.md) as "blocked: requires server access". The collector script [scripts/collect-config.sh](scripts/collect-config.sh) implements every check below.

---

## Table of Contents

1. [Scope and Safety](#1-scope-and-safety)
2. [Running the Collector](#2-running-the-collector)
3. [What to Collect and Why](#3-what-to-collect-and-why)
4. [Tool-Assisted Checks](#4-tool-assisted-checks)
5. [TLS Baseline](#5-tls-baseline)
6. [Turning Output into Findings](#6-turning-output-into-findings)

---

## 1. Scope and Safety

> A white-box audit runs on production with elevated privileges. The audit itself must not become the incident. Every rule below exists because an audit step has, at some point, changed or leaked the thing it was meant to inspect.

- [ ] **Get written authorisation that names the hosts, the account, and the time window.** The rules of engagement in [assessment-methodology.md](assessment-methodology.md#1-rules-of-engagement) apply unchanged. Read access to a server is not permission to read its databases.

- [ ] **Run read-only commands only.** Allowed: commands that print state (`sshd -T`, `nginx -T`, `php -i`, `php-fpm -tt`, `ss`, `ufw status`, `iptables -S`, `docker inspect`, `SHOW GRANTS`, `sysctl -n`). Not allowed: `reload`, `restart`, `apt install`, `ufw allow`, `docker run` against production images, editing any file, or "just fixing it while I am here". Fixes go through the normal change process after the report.

  > **Known side effects of "read-only" commands.** `nginx -T` and `php-fpm -tt` parse the configuration exactly like a reload does, which opens the configured log files for append and can create them if they are missing. `docker exec` creates an exec instance that appears in `docker events`. MySQL `SHOW` and `SELECT` statements appear in the general query log if it is enabled. If even these are not acceptable, run the collector with `AUDIT_NO_CONFIG_TEST=1`, which reads the config files with `cat` instead. You lose the merged view of `include` files in exchange.

- [ ] **Use a dedicated, time-limited audit account with sudo.** Most of the useful output (`sshd -T`, `iptables`, the Docker socket, MySQL socket authentication) requires root. Do not reuse a deploy account. Remove the account when the window closes.

  ```bash
  # Create the account and allow ONLY the reviewed, root-owned collector
  adduser --disabled-password --gecos "" auditor
  install -o root -g root -m 0755 collect-config.sh /usr/local/sbin/collect-config.sh
  sha256sum /usr/local/sbin/collect-config.sh   # record this in the report
  echo 'auditor ALL=(root) NOPASSWD: /usr/local/sbin/collect-config.sh' > /etc/sudoers.d/90-auditor
  chmod 0440 /etc/sudoers.d/90-auditor && visudo -c
  ```

  > **Why a root-owned copy:** if the auditor account can write to the script it runs under sudo, it can run anything as root. The sudoers rule is only as narrow as the file permissions behind it.

  > **Options under sudo:** `env_reset` drops the `AUDIT_*` variables, so with the rule above the collector always runs with defaults. To allow them, add `Defaults!/usr/local/sbin/collect-config.sh env_keep += "AUDIT_TIMEOUT AUDIT_ALLOWED_PORTS AUDIT_NO_CONFIG_TEST AUDIT_SKIP_DOCKER AUDIT_SKIP_MYSQL"` to the same sudoers file.

- [ ] **Never print secrets.** Config dumps contain them: `php-fpm -tt` prints every `env[...]` line of every pool, `php -i` prints the whole environment, `nginx -T` prints `proxy_set_header Authorization` values, and `docker inspect` prints every container environment variable. The collector redacts values of keys that match `pass` (including `password`, `passwd`, `DB_PASS`), `pwd`, `_pw`, `secret`, `token`, `auth`, `api_key`, `access_key`, `private_key`, `app_key`, `*_key`, `salt`, `credential`, DSN passwords (`scheme://user:PASS@host`), `Authorization` / `Cookie` header values, MariaDB `USING '...'` hashes, and PEM private key lines. It collects container environment variables as **names only**, and keeps only the names in the Environment and PHP Variables sections of `php -i`.

  > Redaction is pattern-based and best effort. Values that start with `/` are kept on purpose (so `ssl_certificate_key /etc/...` survives), which means a secret that starts with a slash would leak. Grep the output before it leaves the host: `grep -rniE 'pass|secret|token|key' audit-*/ | grep -v REDACTED | less`.

- [ ] **Keep output local until reviewed.** The collector writes only inside its output directory, with `umask 077`, and makes no network calls. Copy the directory to the auditor workstation over SSH, verify it against `MANIFEST.sha256`, then delete it from the server. Do not paste raw output into third-party services, ticket systems, or AI tools before the redaction review; see [assessment-methodology.md](assessment-methodology.md#2-data-handling-during-testing).

---

## 2. Running the Collector

- [ ] **Review the script, then run it once per host.**

  ```bash
  sudo /usr/local/sbin/collect-config.sh /root/audit-$(hostname -s)-$(date +%Y%m%d)
  ```

  Options are environment variables: `AUDIT_TIMEOUT` (per-command seconds, default 30), `AUDIT_ALLOWED_PORTS` (ports allowed on all interfaces, default `80 443`, SSH ports are added from `sshd -T`), `AUDIT_NO_CONFIG_TEST=1`, `AUDIT_SKIP_DOCKER=1`, `AUDIT_SKIP_MYSQL=1`.

- [ ] **Read `SUMMARY.txt` first, then the evidence files.** Lines start with `FAIL` (clear violation of a checklist item), `WARN` (needs a human decision), or `INFO` (context). The layout:

  ```
  audit-web01-20261104/
    SUMMARY.txt              FAIL / WARN / INFO, sorted
    MANIFEST.sha256          integrity of every collected file
    system/  ssh/  firewall/  network/  updates/  fail2ban/
    php/                     host php -i, php-fpm -i, php-fpm -tt per binary
    nginx/                   host nginx -V and nginx -T
    mysql/host/              variables, users (no hashes), grants
    docker/<container>/      inspect (selected fields), env-names, roles,
                             and php / nginx / mysql output from inside it
  ```

- [ ] **Treat the summary as a triage list, not as the report.** The checks are deliberately simple pattern matches. A `WARN` for "runs as root" on an image whose entrypoint drops privileges is a false positive; a clean summary does not mean a clean server. Section 3 tells you what to read by hand.

---

## 3. What to Collect and Why

Each item maps to the checklist it verifies. The "config says" result is only the first half: for anything that faces the network, confirm it live from outside as well (section 5 for TLS, [local-to-production-checklist.md](local-to-production-checklist.md#12-security-scan-commands) for ports).

### PHP: effective configuration per SAPI

Verifies [wordpress-server-hardening.md section 3](wordpress-server-hardening.md#3-php-hardening) and [php-application-hardening.md section 1](php-application-hardening.md#1-universal-php-security).

- [ ] **Collect the FPM configuration, not just the CLI one.** `php -i` describes the **CLI** SAPI. On Ubuntu packages the CLI and FPM read different files (`/etc/php/8.3/cli/php.ini` and `/etc/php/8.3/fpm/php.ini`, each with its own `conf.d/`). A server can show `display_errors => Off` in `php -i` and still print stack traces to every visitor from FPM.

  ```bash
  # By hand these print secrets unredacted (environment, env[...]); prefer the collector output
  php --ini                      # which files the CLI loads
  php-fpm8.3 -i                  # FPM SAPI: php.ini + conf.d as FPM loads them
  php-fpm8.3 -tt 2>&1            # FPM pool config, including php_value / php_admin_value
  ```

  The effective value for a request is `php-fpm -i` **overridden by** the pool's `php_value[...]` / `php_admin_value[...]`, which only `-tt` (test twice: test and dump) shows. Check every pool: one site can be hardened and its neighbour not. In containers run the same commands with `docker exec`. Official `php:*-fpm` images share one `conf.d` between CLI and FPM and ship **no `php.ini`** by default (`Loaded Configuration File => (none)`), which means PHP's built-in defaults: `display_errors=1`, `expose_php=On`, empty `disable_functions`.

  > **Why this matters:** `-tt` prints `env[DB_PASSWORD] = ...` for every pool, and `-i` prints the environment of the process. Never save or share their raw output; use the collector, which redacts it.

- [ ] **Do not drop a temporary `phpinfo()` endpoint into the webroot to "see the real values".** It is a write to production, it exposes the full configuration and environment to anyone who finds it before you delete it, and scanners request `phpinfo.php` and `info.php` constantly. The only thing it adds over `php-fpm -i` plus `-tt` is runtime `ini_set()` calls and `.user.ini` files: grep the code for those instead (`grep -rn "ini_set\|\.user\.ini" /var/www`).

- [ ] **Check these directives against the checklist** (the collector flags them; FAIL for FPM, WARN when only the CLI was found): `expose_php`, `allow_url_include`, `display_errors`, `disable_functions` (empty, or missing `putenv`, `mail`, `dl`, the Chankro bypass trio), `allow_url_fopen`, `open_basedir`, `session.cookie_httponly`, `session.use_strict_mode`, `phar.readonly`, `ffi.enable`, and `opcache.restrict_api` (empty means unrestricted).

### nginx: the merged configuration

Verifies [wordpress-server-hardening.md section 2](wordpress-server-hardening.md#2-nginx-configuration) and section 5 below.

- [ ] **Dump the merged configuration with `nginx -T`.** It prints every included file, prefixed with `# configuration file <path>:`, which is the only reliable view: `sites-enabled`, `conf.d`, snippets, and certbot's `options-ssl-nginx.conf` all contribute.

  ```bash
  nginx -V 2>&1 | head -1        # version decides several defaults
  nginx -T 2>/dev/null | less    # raw output can hold secrets: do not save it unredacted
  ```

- [ ] **Look for the `add_header` inheritance trap.** A `location` (or `if`, or `server`) block that contains any `add_header` inherits **none** from its parent. The collector walks the block structure and reports each block that defines its own headers and silently drops the parent's, with the dropped header names:

  ```
  FAIL [nginx] host nginx: add_header inheritance: /etc/nginx/sites-enabled/app (dump line 88):
       "location = /login" has its own add_header and drops: content-security-policy x-frame-options
  ```

  Fix with a shared `include snippets/security-headers.conf;` in each such block, or on nginx 1.29.3 and later with `add_header_inherit merge;` at the `http` level. The collector does not report blocks covered by `add_header_inherit merge`.

- [ ] **Check `server_tokens`.** Absent means `on`. Only an explicit `server_tokens off;` hides the version.

- [ ] **Check `autoindex on`.** Any occurrence is a directory listing somewhere.

- [ ] **Check `ssl_protocols` everywhere it appears.** Ubuntu's packaged `/etc/nginx/nginx.conf` ships `ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;` in the `http` block, and server blocks that do not override it inherit it. When `ssl_protocols` is absent, the default is `TLSv1.2 TLSv1.3` only from nginx 1.23.4; older versions (Ubuntu 22.04 ships 1.18) default to including TLSv1 and TLSv1.1.

  > **Config says is not the same as runtime does.** Ubuntu's OpenSSL runs at security level 2, which refuses TLS 1.0 and 1.1 even when nginx lists them. A container built on another base image does not have that patch. Always confirm with the live tests in section 5 before rating.

### SSH: effective daemon configuration

Verifies [linux-server-hardening.md section 2](linux-server-hardening.md#2-ssh-hardening).

- [ ] **Use `sshd -T`, not `cat sshd_config`.** It prints the effective value of every option after defaults and `sshd_config.d/*.conf` drop-ins are applied. A drop-in from a cloud image (`50-cloud-init.conf` setting `PasswordAuthentication yes`) beats the main file because the first value wins.

  ```bash
  sshd -T | grep -E '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|usepam|permitemptypasswords|maxauthtries|x11forwarding|allowtcpforwarding|port) '
  sshd -T -C user=deploy,host=x,addr=203.0.113.10   # evaluate Match blocks for a given connection
  ```

  FAIL on `permitrootlogin yes`, `passwordauthentication yes`, `permitemptypasswords yes`. Also note `kbdinteractiveauthentication yes` with `usepam yes`, which can still allow password login through PAM. On Ubuntu 24.04 `sshd -T` may need `/run/sshd` to exist when SSH is socket-activated; the listening port then comes from `ss`, not from `sshd -T`.

- [ ] **List authorized keys by fingerprint.** The collector records `ssh-keygen -lf` output for every `authorized_keys` file, never the keys themselves. Every fingerprint must belong to a named person or system.

### Firewall and listening sockets

Verifies [linux-server-hardening.md section 3](linux-server-hardening.md#3-firewall-ufw--docker).

- [ ] **Collect all three views, because each one lies in a different way.**

  ```bash
  ufw status verbose               # what the admin intended
  iptables -S DOCKER-USER          # whether Docker-published ports are filtered at all
  ip6tables -S DOCKER-USER
  ss -tlnp                         # what is actually listening
  ```

  A port published by Docker bypasses UFW. If `DOCKER-USER` contains only `-j RETURN`, every container port published on `0.0.0.0` is reachable from the internet whatever `ufw status` says. And if the Docker daemon runs with `"userland-proxy": false`, published ports do not appear in `ss` at all, so the Docker check below is the only place you see them.

- [ ] **Flag anything on `0.0.0.0`, `[::]`, or `*` other than SSH, 80, and 443.** Then confirm from outside with `nmap -Pn -p- HOST`. A database or Redis port in this list is the most common critical finding on small Docker hosts.

### Docker: per-container runtime settings

Verifies [linux-server-hardening.md section 6](linux-server-hardening.md#6-docker-security) and [local-to-production-checklist.md section 6](local-to-production-checklist.md#6-docker-deployment-checklist).

- [ ] **Inspect running containers, not the compose file.** The compose file in the repository is what someone meant to deploy; `docker inspect` is what is running, including containers started by hand months ago.

  ```bash
  docker inspect --format '{{.Name}} priv={{.HostConfig.Privileged}} ro={{.HostConfig.ReadonlyRootfs}} user={{.Config.User}} capadd={{.HostConfig.CapAdd}} secopt={{.HostConfig.SecurityOpt}} pid={{.HostConfig.PidMode}} net={{.HostConfig.NetworkMode}}' $(docker ps -q)
  docker inspect --format '{{.Name}} {{range $p, $b := .NetworkSettings.Ports}}{{range $b}}{{$p}}={{.HostIp}}:{{.HostPort}} {{end}}{{end}}' $(docker ps -q)
  docker inspect --format '{{.Name}} {{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' $(docker ps -q) | grep docker.sock
  ```

  FAIL: `Privileged=true`, `CapAdd` containing `ALL` / `SYS_ADMIN` / `SYS_PTRACE` / `SYS_MODULE` / `NET_ADMIN` / `DAC_READ_SEARCH`, `seccomp=unconfined`, `pid: host`, a mounted `docker.sock`, a port published on `0.0.0.0` / `::` / empty HostIp other than 80 and 443. WARN: no `no-new-privileges`, writable root filesystem, empty `User` (root), `network_mode: host`.

  > Do not dump `{{.Config.Env}}` with values. It holds the database password in almost every compose stack. The collector stores variable names only.

- [ ] **Run the PHP, nginx, and MySQL checks inside each container that has them.** The collector detects `nginx`, `php`, `php-fpm*`, `mysqld`, and `mariadbd` binaries inside each running container and repeats the host checks with `docker exec`. Containers without a shell (distroless) are skipped and listed as INFO.

### MySQL / MariaDB: privileges and dangerous settings

Verifies the database items in [linux-server-hardening.md section 3](linux-server-hardening.md#3-firewall-ufw--docker) (exposure) and least privilege for the application user.

- [ ] **Read grants and settings with SHOW and SELECT only.** Do not select `authentication_string` itself; compute whether it is empty.

  ```sql
  SHOW GLOBAL VARIABLES WHERE Variable_name IN
    ('bind_address','local_infile','secure_file_priv','skip_name_resolve','require_secure_transport','have_ssl','tls_version');
  SELECT user, host, plugin,
         IF(plugin IN ('unix_socket','auth_socket'), 'socket',
            IF(authentication_string = '', 'EMPTY', 'set')) AS pw
    FROM mysql.user;
  SHOW GRANTS FOR 'app'@'%';
  ```

  On the host the collector authenticates through the root socket (or `/etc/mysql/debian.cnf` when readable). Inside a container it reads `MYSQL_ROOT_PASSWORD` / `MARIADB_ROOT_PASSWORD` (or the `*_FILE` variant) from the container's own environment and passes it as `MYSQL_PWD` inside the container, so the password never reaches the audit host.

- [ ] **Flag these.** FAIL: an application user with `ALL PRIVILEGES ON *.*`, or `SUPER` or `FILE` on `*.*` (FILE plus an empty `secure_file_priv` reads any file mysqld can read and writes webshells into a webroot); an anonymous user (`''@'host'`); a user with an empty password; `root@'%'`. WARN: `ALL PRIVILEGES` on the application schema (DDL rights turn SQL injection into `DROP TABLE`), any user at host `%`, `local_infile=ON`, empty `secure_file_priv`, and on a host install `bind_address` of `*`, `0.0.0.0`, or `::`.

### Kernel, updates, and fail2ban

Verifies [linux-server-hardening.md sections 4, 5, and 7](linux-server-hardening.md#5-kernel-hardening).

- [ ] **Compare sysctl values with `sysctl -n KEY`**, one key at a time, against the list in [section 5](linux-server-hardening.md#5-kernel-hardening). Read the running value, not `/etc/sysctl.d/`: a file that was never applied, or is overridden by a later file, is a common drift. Containers share the host kernel, so this is a host-only check.

- [ ] **Prove that unattended-upgrades actually runs.**

  ```bash
  apt-config dump APT::Periodic | grep Unattended-Upgrade    # must be "1"
  systemctl is-enabled apt-daily-upgrade.timer unattended-upgrades.service
  tail -n 60 /var/log/unattended-upgrades/unattended-upgrades.log
  ls /var/run/reboot-required 2>/dev/null                    # patched but not running
  ```

  An installed package with `APT::Periodic::Unattended-Upgrade "0"` does nothing. A log that has not been written for weeks means the timer is not firing. See [section 7](linux-server-hardening.md#7-system-updates).

- [ ] **Check the fail2ban backend for sshd, not just that the service is up.**

  ```bash
  fail2ban-client -d | grep "'add', 'sshd'"     # expect ['add', 'sshd', 'systemd']
  fail2ban-client status sshd                    # "Total failed" never rising = jail is blind
  ```

  Where rsyslog is not installed (minimal and container-style images, Debian 12 and later), sshd logs only to journald, and a jail with `backend = auto` reads no file and bans nothing, with no error. Standard Ubuntu server installs still run rsyslog and write `/var/log/auth.log`, so a file backend works there until rsyslog is removed; `backend = systemd` is the robust choice either way. The collector reports FAIL only when the backend is not `systemd` and `/var/log/auth.log` is missing or stale, otherwise WARN. See [section 4](linux-server-hardening.md#4-fail2ban).

---

## 4. Tool-Assisted Checks

> The collector covers the items in this repo. These tools go wider. Run them on a copy of the collected output on the auditor workstation where possible, so the server only executes the read-only collector.

- [ ] **gixy for nginx configuration analysis.** The original Yandex `gixy` is no longer maintained (no commits since 2024). Two forks describe themselves as actively maintained as of November 2026: `gixy-ng` (GetPageSpeed) and `Gixy-Next` (a fork of gixy-ng). Both run on current Python and add checks the original never had, such as Let's Encrypt OCSP stapling (the original already has `add_header_redefinition`). Pick one, pin its version, and run it offline against the dump:

  ```bash
  pipx install gixy-next          # or a pinned version: pipx install 'gixy-next==X.Y.Z'
  grep -v '^nginx: ' audit-web01/nginx/host-nginx-T.txt > nginx-dump.conf
  gixy nginx-dump.conf
  ```

  > The `grep -v` strips the `nginx: syntax is ok` lines that `nginx -T` writes to stderr, which the collector captures in the same file.

- [ ] **docker-bench-security for the CIS Docker Benchmark.** Still the standard host-side checker, but low activity: the last tagged release is v1.6.1 (December 2023, CIS Docker Benchmark 1.6.0) and newer Docker Engine features are not covered. Run it from a reviewed clone. It writes its own log, so point that log at the audit output directory.

  ```bash
  git clone --depth 1 https://github.com/docker/docker-bench-security.git
  cd docker-bench-security && sudo sh docker-bench-security.sh -l /root/audit-web01/docker-bench.log
  ```

- [ ] **Trivy for images, misconfiguration, and dependency lockfiles.**

  ```bash
  # Vulnerabilities and embedded secrets in each running image (pin by digest from docker/images.txt)
  trivy image --scanners vuln,secret --severity HIGH,CRITICAL --ignore-unfixed IMAGE@sha256:DIGEST
  # Misconfiguration in Dockerfiles and IaC in the repository
  trivy config ./
  # composer.lock, package-lock.json, and other lockfiles in a source tree
  trivy fs --scanners vuln ./
  ```

  Trivy downloads its vulnerability database from a public registry on first run, so run it on the auditor workstation or a CI runner, not on the audited server. **Pin and verify the Trivy binary.** In March 2026 the project's release credentials were abused: binary v0.69.4 and several Docker Hub image tags were malicious, and most `trivy-action` tags were repointed (CVE-2026-33634, GHSA-69fq-xp46-6x23). Install a current release (v0.76.1 at the time of writing), verify its checksum and signature, and pin CI actions to a commit SHA. Use [local-to-production-checklist.md section 2](local-to-production-checklist.md#2-pre-deploy-dependency-audit) for how to act on dependency results.

- [ ] **Lynis for the broad host audit.** Already covered in [security-audit-automation.md section 1](security-audit-automation.md#1-lynis--system-audit). In a white-box audit, run `lynis audit system` once, record the hardening index, and copy `/var/log/lynis-report.dat` into the audit directory. Note that Lynis writes its own log files under `/var/log`.

- [ ] **testssl.sh for TLS.** See section 5. It runs from the auditor workstation against the public endpoint and, separately, against the origin IP.

---

## 5. TLS Baseline

> A production assessment found TLS 1.0 and 1.1 enabled on a public endpoint. The repo had SSH cipher guidance but no web TLS baseline. This section is that baseline.

- [ ] **Use the "intermediate" profile from the TLSRef (formerly Mozilla) configuration guidelines.** The Mozilla SSL Configuration Generator moved in 2026 to a community working group: `ssl-config.mozilla.org` now redirects to [configurator.tlsref.org](https://configurator.tlsref.org/), and the current guideline is **version 6.0**. Intermediate is the right default for any public web server; "modern" (TLS 1.3 only) drops some older clients that still appear in healthcare, enterprise, and embedded traffic.

  ```nginx
  # TLSRef guideline 6.0, intermediate profile, nginx >= 1.25.1
  http {
      server {
          listen 443 ssl;
          listen [::]:443 ssl;
          http2 on;
          ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
          ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

          # 2 years; see the HSTS item below before adding preload
          add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
      }

      ssl_protocols TLSv1.2 TLSv1.3;
      ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1:secp384r1;   # drop X25519MLKEM768 if OpenSSL < 3.5
      ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
      ssl_prefer_server_ciphers off;

      ssl_session_timeout 1d;
      ssl_session_cache shared:MozSSL:10m;   # about 40000 sessions
      # ssl_session_tickets off;   # only needed on nginx < 1.23.2 (Ubuntu 22.04 ships 1.18)
  }
  ```

  Notes on the values:
  - **`ssl_ciphers` only applies to TLS 1.2.** TLS 1.3 suites (`TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`) are OpenSSL defaults and need no directive.
  - **Guideline 5.8 removed the DHE suites** from intermediate (6.0 then removed the "old" profile), so `ssl_dhparam` is no longer needed. If an older config still lists `DHE-RSA-*`, it is following guideline 5.7 or earlier.
  - **`X25519MLKEM768`** is the hybrid post-quantum key exchange. It needs OpenSSL 3.5 or later; Ubuntu 24.04 ships 3.0, so the generator drops it there and you should too.
  - **`ssl_prefer_server_ciphers off`** is correct when every enabled cipher is strong: it lets mobile clients without AES hardware choose ChaCha20.
  - **Session tickets** are fine on nginx 1.23.2 and later, which rotates ticket keys automatically when a shared session cache is configured. On older nginx, set `ssl_session_tickets off;` or tickets reuse one key until restart and break forward secrecy.

- [ ] **Remove OCSP stapling for Let's Encrypt certificates, and understand why.** Let's Encrypt removed OCSP URLs from new certificates on 7 May 2025 and turned its OCSP responders off on 6 August 2025. The consequence: `ssl_stapling on;` with a Let's Encrypt certificate does nothing, nginx logs `"ssl_stapling" ignored, no OCSP responder URL in the certificate`, Must-Staple certificates can no longer be issued, and revocation now reaches browsers through CRLs aggregated by the browser vendors. Check certbot's shared `/etc/letsencrypt/options-ssl-nginx.conf` too. Keep stapling only for certificates from a CA that still runs OCSP. A missing stapled response on a Let's Encrypt site is **not** a finding; a scanner that reports it is out of date.

- [ ] **Set HSTS deliberately.** `max-age=63072000` (2 years) is the guideline value. Two parts need care:
  - **`includeSubDomains`** applies the policy to every subdomain, including internal tools, mail autodiscovery, and legacy hosts that may not serve valid HTTPS. Inventory the subdomains (see [local-to-production-checklist.md section 11](local-to-production-checklist.md#11-dns-security)) before enabling it. Roll out with `max-age=300` first, then raise it.
  - **`preload`** is a request to be hard-coded into browsers. It only takes effect after submission to the preload list, it requires `includeSubDomains` and a max-age of at least one year, and removal takes months to reach users. Add it only when you intend to submit. Several existing guides add `preload` by default; treat that as a decision to review, not as the baseline.

- [ ] **Behind Cloudflare, configure two TLS endpoints.** Visitors negotiate TLS with Cloudflare's edge, not with your nginx. Cloudflare's documented default **Minimum TLS Version is TLS 1.0**, so a zone nobody configured accepts TLS 1.0 and 1.1 however well the origin is hardened. This is the most likely cause of a "TLS 1.0 enabled" finding on a Cloudflare-fronted site.
  - Edge: SSL/TLS, Edge Certificates, **Minimum TLS Version: TLS 1.2**, and TLS 1.3 on (zone setting `min_tls_version`). See [cloudflare-hardening.md section 4](cloudflare-hardening.md#4-ssltls-configuration).
  - Origin: the nginx baseline above, plus SSL mode **Full (strict)** so Cloudflare validates the origin certificate. The origin baseline still matters for anyone who reaches the origin IP directly.

- [ ] **Verify live, at the edge and at the origin.**

  ```bash
  # Full protocol, cipher, header, and vulnerability check (testssl.sh 3.2.x)
  ./testssl.sh --protocols --server-defaults --server-preference --headers --vulnerable \
    --jsonfile-pretty tls-edge.json https://example.com

  # Same hostname, but connect to the origin IP directly (SNI still example.com)
  ./testssl.sh --protocols --server-defaults --ip ORIGIN_IP https://example.com

  # Quick check: TLS 1.1 and 1.0 must FAIL, TLS 1.2 must succeed
  openssl s_client -connect example.com:443 -servername example.com -tls1_1 -cipher 'DEFAULT:@SECLEVEL=0' </dev/null
  openssl s_client -connect example.com:443 -servername example.com -tls1   -cipher 'DEFAULT:@SECLEVEL=0' </dev/null
  openssl s_client -connect example.com:443 -servername example.com -tls1_2 </dev/null | grep -E 'Protocol|Cipher'
  ```

  > **Why `-cipher 'DEFAULT:@SECLEVEL=0'`:** OpenSSL 3 on Ubuntu 22.04 and later refuses TLS 1.0 and 1.1 on the **client** side. Without lowering the client security level, the handshake fails locally (`no protocols available`) and you conclude the server is safe when you never asked it. With the flag, a hardened server answers with an alert such as `tlsv1 alert protocol version` or `handshake failure`; a vulnerable one completes the handshake and prints `Protocol  : TLSv1.1`. testssl.sh does its own protocol probing and is not affected.

---

## 6. Turning Output into Findings

> The collector produces observations. A finding is an observation plus a category, a severity with a written rationale, evidence, and a fix. [assessment-methodology.md](assessment-methodology.md) defines the category list, the severity rubric, and the report template; this section shows how white-box output feeds into them.

- [ ] **Assign exactly one category** from [assessment-methodology.md section 4](assessment-methodology.md#4-finding-categories). If a finding fits two, pick the one that describes the fix. Most white-box output lands in one of three:
  - **Misconfiguration:** a setting is wrong; versions are fine (TLS 1.0 enabled, `display_errors On`, `server_tokens` on, writable root filesystem, privileged container or `docker.sock` mounted in a web container).
  - **Access control and secrets:** someone can reach data or actions they should not (database port on `0.0.0.0`, application user with `FILE` or `ALL ON *.*`, empty MySQL password, password SSH login).
  - **Outdated or EOL component:** a runtime, package, or image is past support or has known CVEs (PHP below 8.2, unpatched `openssh-server`, pending security updates, image CVEs from Trivy).
  - Anything else uses the remaining two categories: **Detection/response gap** (a fail2ban jail that cannot see its logs, no backup evidence) or **Code-level vulnerability** (a defect found while reading application code).

- [ ] **Rate severity with the rubric, not with the collector's FAIL / WARN label.** FAIL means "violates a checklist item", not "High". Use [assessment-methodology.md section 5](assessment-methodology.md#5-severity-rubric). Typical starting points before adjustment:

  | Observation | Category | Starting severity |
  |---|---|---|
  | Database or cache port reachable from the internet (confirmed with nmap) | Access control and secrets | Critical if unauthenticated, High otherwise |
  | MySQL user with empty password, network reachable | Access control and secrets | Critical |
  | Privileged container, `docker.sock` mounted, or `SYS_ADMIN` added | Misconfiguration | High |
  | Application DB user with `FILE`, `SUPER`, or `ALL ON *.*` | Access control and secrets | High |
  | `allow_url_include = On` in FPM | Misconfiguration | High |
  | TLS 1.0 / 1.1 accepted (confirmed live) | Misconfiguration | Medium or High, see methodology worked example |
  | `PasswordAuthentication yes` on internet-facing SSH | Access control and secrets | Medium (High with no fail2ban or `PermitRootLogin yes`) |
  | `display_errors On` in FPM | Misconfiguration | Medium |
  | `add_header` inheritance drops CSP / frame headers on login or admin paths | Misconfiguration | Medium |
  | Unattended security updates disabled | Misconfiguration | Medium |
  | PHP past upstream security support | Outdated or EOL component | High (policy), lower only with documented distro backports |
  | `disable_functions` empty or missing the Chankro trio | Misconfiguration | Low (defence in depth) |
  | `server_tokens` on, `expose_php = On` | Misconfiguration | Info or Low |
  | sysctl value differs from the checklist | Misconfiguration | Low or Info |

- [ ] **Mark every finding as "config only" or "confirmed live".** A config-only TLS or port finding may be neutralised by something the collector cannot see (Ubuntu's OpenSSL security level, a cloud firewall, a Cloudflare edge setting). Confirm network-facing findings from outside before rating them above Medium, and say in the finding which you did.

- [ ] **Cite the evidence by file and line, redacted.** Example: `docker/app/php-fpm-i.txt: display_errors => On => On` or `nginx/host-nginx-T.txt line 88`. Include the collector's `MANIFEST.sha256` hash of the file so the evidence can be checked later, and the script's own SHA-256 recorded in section 1.

- [ ] **Map back to the checklist.** For each FAIL, link the exact checklist item it violates (the section links in section 3 of this guide). In the report's checklist coverage table, the guides that were "externally blocked" can now be marked as verified, with the white-box date and host list.

- [ ] **Re-run the collector after remediation** with a new output directory and diff the two `SUMMARY.txt` files. A finding is closed when its line is gone **and** the live check (where one applies) passes.

---

*Last reviewed: 2026-11 | Applies to: Ubuntu 22.04/24.04, nginx, PHP-FPM 8.x, MySQL 8 / MariaDB 10.6+, Docker Engine, Cloudflare-fronted origins*
