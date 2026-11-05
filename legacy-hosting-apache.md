# Legacy Hosting Hardening: Apache, .htaccess, and Shared Hosting

**Security checklist for PHP and WordPress sites on Apache (mod_php, PHP-FPM via proxy_fcgi, suPHP, LSAPI) and on cPanel/WHM, CloudLinux, or Plesk accounts where you may not have root**

> The rest of this repo assumes Nginx + PHP-FPM + Docker on a VPS you control. A large share of real PHP sites, especially older WordPress installs on PHP 7.x, run on Apache with per-directory `.htaccess` files, often on a shared hosting account. This guide gives the Apache equivalents of the Nginx controls in [wordpress-server-hardening.md](wordpress-server-hardening.md), covers the risks that only exist on Apache (mod_php shared identity, `.htaccess` and `.user.ini` overrides), and gives a no-root playbook for panel users. Application-level PHP issues are not repeated here: see [php-application-hardening.md](php-application-hardening.md), in particular [Legacy PHP](php-application-hardening.md#2-legacy-php-5x-and-early-7x).

> **Two kinds of reader.** Items marked **(root)** need access to the main Apache config (`/etc/apache2/`, `/etc/httpd/`, or the panel's include files). Items marked **(.htaccess)** work from your own document root on a shared account, provided the host's `AllowOverride` permits them. Unmarked items apply to both.

---

## Table of Contents

1. [Stack Detection](#1-stack-detection)
2. [Apache Hardening (Nginx Equivalents)](#2-apache-hardening-nginx-equivalents)
3. [mod_php Risks and PHP Handler Choice](#3-mod_php-risks-and-php-handler-choice)
4. [.htaccess and .user.ini as an Attack Surface](#4-htaccess-and-userini-as-an-attack-surface)
5. [Shared Hosting and No-Root Playbook](#5-shared-hosting-and-no-root-playbook)
6. [Audit Commands](#6-audit-commands)
7. [Common Mistakes (Silent Failures)](#7-common-mistakes-silent-failures)

---

## 1. Stack Detection

> Every control below depends on three facts: which PHP handler runs your code, which Apache version and MPM you have, and whether a control panel rewrites your config. Find these out first. Advice for mod_php is wrong under PHP-FPM and the other way around.

- [ ] **Identify Apache version, MPM, and loaded modules (root).**

  ```bash
  # Debian/Ubuntu use apache2ctl; RHEL/Alma/CloudLinux use apachectl or httpd
  apachectl -V | grep -Ei 'version|mpm'
  apachectl -M 2>/dev/null | grep -Ei 'mpm_|php|proxy_fcgi|fcgid|suphp|lsapi|ruid2|itk|security|evasive|reqtimeout|headers|status|info'
  ```

  > How to read the module list:
  > - `php_module` / `php7_module` / `php5_module`: **mod_php** (PHP runs inside Apache, as the Apache user). Requires `mpm_prefork`.
  > - `proxy_fcgi_module` plus a running `php-fpm` master: **PHP-FPM via proxy_fcgi**.
  > - `fcgid_module`: **mod_fcgid** (often PHP-CGI, sometimes with suEXEC).
  > - `suphp_module`: **suPHP** (each request runs PHP-CGI as the file owner; slow, legacy).
  > - `lsapi_module`: **mod_lsapi** (CloudLinux LiteSpeed SAPI; runs as the account user).
  > - `ruid2_module` / `mpm_itk_module`: Apache itself switches UID per vhost.

  > **Apache 2.2 is end of life** and gets no security fixes. If `apachectl -V` shows 2.2.x, nothing in this guide makes the server safe; plan a migration. For 2.4, check the current release at [httpd.apache.org](https://httpd.apache.org/security/vulnerabilities_24.html) (2.4.68, June 2026, was the latest at time of writing) and compare it with your distro's backported package, not just the version string.

- [ ] **Confirm which user PHP actually runs as (root).**

  ```bash
  ps -eo user,group,comm,args | grep -Ei 'php-fpm|php-cgi|lsphp|httpd|apache2' | grep -v grep
  # php-fpm pool lines show "php-fpm: pool NAME" with the pool user in column 1
  ```

  > If every PHP process runs as `www-data`, `apache`, or `nobody`, all sites on the server share one identity. See [Section 3](#3-mod_php-risks-and-php-handler-choice).

- [ ] **Detect the control panel (root or SSH).**

  ```bash
  cat /usr/local/cpanel/version 2>/dev/null && echo "cPanel/WHM"
  cat /usr/local/psa/version 2>/dev/null && echo "Plesk"
  cat /etc/redhat-release 2>/dev/null          # "CloudLinux" appears here on CloudLinux
  ls -d /usr/share/cagefs 2>/dev/null && echo "CageFS present"
  ```

  > Panels regenerate `httpd.conf` and vhost files. Edits made directly in those files are lost on the next rebuild. Use the panel's include mechanism (cPanel: `/etc/apache2/conf.d/includes/` and per-vhost `userdata` includes; Plesk: per-domain "Additional Apache directives" or `vhost.conf`) so changes survive.

- [ ] **No root: detect the handler from your own account.**

  ```bash
  # Over SSH, as your account user
  php -v                                  # CLI version, may differ from the web version
  grep -n -A3 'cPanel-generated handler' ~/public_html/.htaccess
  # e.g. "AddHandler application/x-httpd-ea-php81 .php" = cPanel MultiPHP, PHP 8.1
  curl -sI https://example.com/ | grep -Ei '^(server|x-powered-by|x-litespeed)'
  ```

  > **The CLI is not the web SAPI.** `php -i` over SSH reads the CLI `php.ini`, which on panel servers is often a different binary and a different ini file than the one serving your site. Use it for version hints only, never as proof of web settings.

- [ ] **If you need web-SAPI facts, use a short-lived, unguessable check script. Never leave `phpinfo()` in the webroot.**

  ```bash
  NAME="chk-$(openssl rand -hex 12).php"
  cat > ~/public_html/"$NAME" <<'EOF'
  <?php
  header('Content-Type: text/plain');
  foreach (['disable_functions','open_basedir','allow_url_include','expose_php',
            'user_ini.filename','auto_prepend_file','display_errors'] as $k) {
      echo $k, ' = ', var_export(ini_get($k), true), "\n";
  }
  // get_current_user() and getmyuid() return the script file's OWNER, not the process user
  $u = function_exists('posix_geteuid') ? (posix_getpwuid(posix_geteuid())['name'] ?? posix_geteuid()) : 'unknown (no posix ext)';
  echo 'SAPI = ', PHP_SAPI, "\nVERSION = ", PHP_VERSION, "\nPROCESS USER = ", $u, "\n";
  EOF
  curl -s "https://example.com/$NAME"; rm -f ~/public_html/"$NAME"
  ```

  > **Why this matters:** A forgotten `phpinfo.php` or `info.php` discloses the full environment, including paths, loaded modules, and often secrets passed as environment variables. Scanners request these filenames constantly. The script above prints only named settings and is deleted in the same command. `PHP_SAPI` returns `apache2handler` for mod_php, `fpm-fcgi` for PHP-FPM, `cgi-fcgi` for CGI/fcgid/suPHP, and `litespeed` for LSAPI.

---

## 2. Apache Hardening (Nginx Equivalents)

> Each item maps to a control in [wordpress-server-hardening.md Section 2](wordpress-server-hardening.md#2-nginx-configuration). Server-wide directives (version tokens, TRACE, timeouts, modules) are root-only. Path blocking and headers can usually be done in `.htaccess`.

- [ ] **Hide version information (root).** `ServerTokens` defaults to `Full`, which sends Apache version, OS, and module versions (including PHP under mod_php) in every `Server:` header.

  ```apache
  ServerTokens Prod
  ServerSignature Off
  ```

  > `ServerTokens` is only valid in server config, not in a vhost or `.htaccess`. Pair with `expose_php = Off` (see [wordpress-server-hardening.md Section 3](wordpress-server-hardening.md#3-php-hardening)). On shared hosting you cannot change it; it is a disclosure issue, not a vulnerability, so do not spend time fighting it.

- [ ] **Disable TRACE (root).** The default is `TraceEnable on`. `off` makes the core and `mod_proxy` answer `405`.

  ```apache
  TraceEnable Off
  ```

- [ ] **Turn off directory listings and SSI.** Set this at the `<Directory>` for your document root (root), or at the top of your `.htaccess` (.htaccess, requires `AllowOverride Options`).

  ```apache
  Options -Indexes -Includes -ExecCGI
  ```

  > Mixing `+`/`-` and bare options in one `Options` line is a syntax error in 2.4. Use all prefixed or none.

- [ ] **Prefer `SymLinksIfOwnerMatch` over `FollowSymLinks`, and do not treat either as a security boundary (root).**

  ```apache
  <Directory /home/*/public_html>
      Options -Indexes -Includes +SymLinksIfOwnerMatch
      AllowOverride AuthConfig FileInfo Indexes Limit
  </Directory>
  ```

  > **Why this matters:** On shared hosting the classic cross-account read is a symlink: user A creates `public_html/x.txt -> /home/B/public_html/wp-config.php` and requests it over HTTP. Apache reads it as the web server user. `SymLinksIfOwnerMatch` checks that link and target owner match, but the Apache docs state that symlink testing "is subject to race conditions that make it circumventable": the attacker swaps the link between the check and the open. Real protection is kernel or filesystem level: CloudLinux SecureLinks (cPanel's recommended option), KernelCare symlink protection, or per-account PHP identities with home directories at `0710`/`0750` (group = web server group) so other accounts cannot traverse into them. `0711` is not enough: anyone can open a known path such as `public_html/wp-config.php` if the file itself is world-readable. The cPanel "Bluehost" `SymlinkProtect` patch exists but cPanel describes it as weaker and slower than kernel options.

- [ ] **Scope `AllowOverride` narrowly (root).** The 2.4 default is `None` (no `.htaccess` processing). Panels usually set `All` so customers can use WordPress permalinks.

  ```apache
  # Enough for WordPress permalinks, auth, and caching headers; no Options, no php_value
  AllowOverride AuthConfig FileInfo Indexes Limit
  # Or allow only specific directives:
  AllowOverride None
  AllowOverrideList Redirect RedirectMatch RewriteEngine RewriteRule RewriteCond RewriteBase
  ```

  > **Know the trade-off:** `FileInfo` still permits `AddType`, `AddHandler`, `SetHandler`, `RewriteRule`, and `Header`. That is exactly what an attacker uses to re-enable PHP in an uploads folder ([Section 4](#4-htaccess-and-userini-as-an-attack-surface)). On a single-site server you control, the strongest option is `AllowOverride None` with WordPress rewrite rules moved into the vhost, which also removes the per-request `.htaccess` lookup cost.

- [ ] **Block PHP execution in upload and cache directories.** This is the most important Apache control for WordPress. Use `Require all denied`, which works under every handler.

  ```apache
  # root: in the vhost
  <Directory "/var/www/example.com/wp-content/uploads">
      <FilesMatch "\.(?i:ph(p[0-9]*|tml|ar|ps|t)|cgi|pl|py|sh|shtml)$">
          Require all denied
      </FilesMatch>
      Options -ExecCGI -Includes -Indexes
      AllowOverride None
  </Directory>
  ```

  ```apache
  # .htaccess: wp-content/uploads/.htaccess
  <FilesMatch "\.(?i:ph(p[0-9]*|tml|ar|ps|t)|cgi|pl|py|sh|shtml)$">
      Require all denied
  </FilesMatch>
  ```

  > **`php_admin_flag engine off` caveat:** it only works under mod_php. With PHP-FPM, fcgid, suPHP, or LSAPI the `php_*` directives belong to a module that is not loaded: in the main config Apache refuses to start ("Invalid command"), and in `.htaccess` every request in that folder returns `500`. `php_admin_*` is never allowed in `.htaccess`, even under mod_php. Many guides still recommend it. `Require all denied` is handler-independent.

  > **`AllowOverride None` on the uploads directory is what makes this durable (root).** The `.htaccess` version can be deleted or replaced by anyone who can write to `uploads/`, which is the PHP user. If you can only use `.htaccess`, monitor that file ([Section 4](#4-htaccess-and-userini-as-an-attack-surface)).

- [ ] **Deny dotfiles, VCS directories, backups, and environment files.** `<FilesMatch>` only sees the final path component, so it does not protect `/.git/config` (basename `config`). Match on the URL path instead.

  ```apache
  # Any path segment starting with a dot, except ACME challenges
  RedirectMatch 404 "/\.(?!well-known/)"

  # Backups, dumps, editor leftovers, logs
  <FilesMatch "(?i)(\.(bak|backup|old|orig|save|swp|sql|sql\.gz|tar|tar\.gz|tgz|zip|7z|log|ini|env)|~)$">
      Require all denied
  </FilesMatch>

  # WordPress specifics
  <Files "wp-config.php">
      Require all denied
  </Files>
  RedirectMatch 404 "^/wp-content/debug\.log$"
  RedirectMatch 404 "^/wp-admin/(install|upgrade)\.php$"
  ```

  > Apache ships `<Files ".ht*"> Require all denied`, which covers `.htaccess` and `.htpasswd` only. `.user.ini`, `.env`, and `.git/` are not covered unless you add the rule above. Test that `/.well-known/acme-challenge/` still works before your next certificate renewal. Blocking `wp-admin/upgrade.php` also blocks the browser database-upgrade step after a core update; run `wp core update-db` instead, or lift the rule during the update.

- [ ] **Block `xmlrpc.php`** unless a specific client needs it (Jetpack and some mobile apps do). Reasons are in [wordpress-server-hardening.md Section 2](wordpress-server-hardening.md#2-nginx-configuration).

  ```apache
  RedirectMatch 404 "^/xmlrpc\.php$"
  ```

- [ ] **Set security headers with `Header always set`, not plain `Header set`.**

  ```apache
  <IfModule !mod_headers.c>
      # Fail loudly: if mod_headers is missing you want a startup error, not silent no-op
      Error "mod_headers is required for security headers"
  </IfModule>
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-Frame-Options "SAMEORIGIN"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
  # Headers PHP may also emit: remove from the default table, set in the always table
  Header onsuccess unset X-Frame-Options
  Header unset X-Powered-By
  Header always unset X-Powered-By
  ```

  > **Why this matters:** This is the Apache counterpart of the nginx `add_header` inheritance trap. mod_headers keeps two tables. `onsuccess` (the default when you write `Header set`) only reaches locally generated `2xx` responses. Redirects, `401`/`403`/`404`, and `500` pages only carry headers from the `always` table. Worse, `mod_proxy_fcgi` and CGI put backend (PHP) headers into the `always` table, so `Header set X` plus a PHP-emitted `X` produces the header twice with two values, and `Header unset X-Powered-By` without `always` does not remove what PHP sent. The Apache docs recommend exactly the `onsuccess unset` plus `always set` pattern above. The `Error` directive needs Apache 2.4.9 or later; on shared hosting leave it out and verify with curl instead.

  > **Verify, do not assume:** `curl -sI https://example.com/does-not-exist` and `curl -sI https://example.com/wp-login.php` must both show the headers, and none may appear twice. Check behaviour of subdirectory `.htaccess` files that define their own `Header` lines too; merge behaviour is easy to get wrong and differs from nginx.

  > Add a Content-Security-Policy only after testing; see [frontend-security.md](frontend-security.md).

- [ ] **Keep mod_reqtimeout enabled for slowloris resistance (root).** It is on by default in current 2.4 with `RequestReadTimeout handshake=0 header=20-40,MinRate=500 body=20,MinRate=500`. Make it explicit and tighten the TLS handshake (the `handshake` stage exists from 2.4.39).

  ```apache
  <IfModule reqtimeout_module>
      RequestReadTimeout handshake=5 header=10-30,MinRate=500 body=20,MinRate=500
  </IfModule>
  ```

  > Also prefer `mpm_event` over `mpm_prefork` (prefork ties up a whole process per slow connection), and keep `Timeout` well below the 2.4 default of 60 only if your uploads allow it. mod_php forces prefork, which is one more reason to leave it ([Section 3](#3-mod_php-risks-and-php-handler-choice)).

- [ ] **Run ModSecurity with OWASP CRS v4, starting in detection mode (root, or panel toggle).**

  ```apache
  # modsecurity.conf
  # Switch to On after reviewing logs for 1-2 weeks.
  # Apache config has no trailing comments: a "# ..." after a directive is a startup error.
  SecRuleEngine DetectionOnly
  SecAuditEngine RelevantOnly
  SecAuditLogParts ABIJDEFHZ
  ```

  > Parts `I` and `C` record request bodies, so the audit log will contain submitted passwords and tokens. Keep it root-readable only, rotate it, and do not ship it to a shared log platform unredacted.

  ```apache
  # crs-setup.conf (CRS v4 variable names)
  SecAction "id:900000,phase:1,pass,nolog,t:none,\
      setvar:tx.blocking_paranoia_level=1"
  SecAction "id:900110,phase:1,pass,nolog,t:none,\
      setvar:tx.inbound_anomaly_score_threshold=5,\
      setvar:tx.outbound_anomaly_score_threshold=4"
  ```

  > **Version check:** at time of writing the latest CRS release is v4.30.0 and the long-term-support line is v4.25.x (v4.25.2). CRS 3.3.x support ends in Q3 2026. Confirm the current release at [github.com/coreruleset/coreruleset/releases](https://github.com/coreruleset/coreruleset/releases) before installing. In v4 the v3 variable `tx.paranoia_level` became `tx.blocking_paranoia_level`, and application exclusions (WordPress, Drupal, Nextcloud) moved out of core into separate plugins: install the WordPress rule exclusions plugin, or PL1 will block normal admin editing.

  > **Paranoia levels:** PL1 is the right default. PL2 is reasonable after tuning. PL3 and PL4 generate many false positives on WordPress and are for teams with time to write exclusions. Write exclusions by rule ID and parameter (`ctl:ruleRemoveTargetById`), never by turning off the engine for `/wp-admin/`.

  > **Panels:** cPanel and Plesk ship their own ModSecurity vendor rule sets (often Comodo/Imunify or Atomicorp rather than CRS). A per-domain "ModSecurity off" toggle in the panel is a common quick fix for a false positive. Find the rule ID in the log instead and ask the host to exclude it.

- [ ] **Treat mod_evasive as a weak signal, not rate limiting.** Apache has no built-in equivalent of nginx `limit_req`.

  > Known caveats: the hit counters are per child process, so under prefork or event the effective threshold scales with the number of children and is inconsistent; behind Cloudflare or a reverse proxy every request appears to come from the proxy unless `mod_remoteip` is configured first, so you will block the proxy; and the module has seen little maintenance for years. For login brute-force use fail2ban on response codes (see the regex warning in [README](README.md#what-makes-these-different)), CRS, or rate limiting at Cloudflare ([cloudflare-hardening.md](cloudflare-hardening.md)).

- [ ] **Configure TLS to the repo baseline (root).** Use `SSLProtocol -all +TLSv1.2 +TLSv1.3`, `SSLHonorCipherOrder off` with a modern cipher list, `SSLSessionTickets off` unless you rotate keys, and OCSP stapling. The full baseline and verification steps are in [whitebox-audit.md](whitebox-audit.md). On shared hosting, TLS is the host's; verify it with `testssl.sh` ([Section 6](#6-audit-commands)) and move if it fails.

- [ ] **Lock down mod_status and mod_info (root).** `/server-status` shows every client IP and requested URL (including tokens in query strings); `/server-info` dumps the full configuration.

  ```apache
  <Location "/server-status">
      SetHandler server-status
      Require ip 127.0.0.1 ::1
  </Location>
  ExtendedStatus Off
  # mod_info: disable unless actively debugging
  # a2dismod info   |  comment out LoadModule info_module
  ```

  > **Reverse proxy trap:** if Varnish, nginx, or a panel proxy sits in front of Apache on the same host, every public request arrives from `127.0.0.1`, so `Require local` or `Require ip 127.0.0.1` makes `/server-status` public. Check with `curl -s -o /dev/null -w '%{http_code}\n' https://example.com/server-status` from outside.

---

## 3. mod_php Risks and PHP Handler Choice

- [ ] **Move off mod_php to PHP-FPM with one pool per site and one Unix user per pool (root).**

  > **Why this matters:** mod_php runs PHP inside every Apache process as the Apache user. Every site on the server shares that identity, so code execution in one WordPress install can read every other site's `wp-config.php`, sessions, and uploads, and write to anything the Apache user owns. `open_basedir` is the only separation, and it has known bypasses (see [wordpress-server-hardening.md Section 3](wordpress-server-hardening.md#3-php-hardening)). mod_php also forces `mpm_prefork`. cPanel no longer supports its DSO (mod_php) handler on PHP 8.0 and later.

  ```ini
  ; /etc/php/8.3/fpm/pool.d/example.conf
  [example]
  user = example
  group = example
  listen = /run/php/example.sock
  listen.owner = www-data
  listen.group = www-data
  listen.mode = 0660
  php_admin_value[open_basedir] = /home/example/public_html:/home/example/tmp
  php_admin_value[disable_functions] = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,mail,putenv,dl
  php_admin_value[upload_tmp_dir] = /home/example/tmp
  php_admin_value[session.save_path] = /home/example/tmp
  php_admin_flag[allow_url_include] = off
  ```

  ```apache
  <VirtualHost *:443>
      ServerName example.com
      DocumentRoot /home/example/public_html
      <FilesMatch "\.php$">
          SetHandler "proxy:unix:/run/php/example.sock|fcgi://localhost"
      </FilesMatch>
  </VirtualHost>
  ```

  > Set home directories to `0710` or `0750` with group `www-data` (or the panel's equivalent) so Apache can traverse to static files but other pool users cannot read each other's trees.

- [ ] **Use the anchored `\.php$` match, never `AddHandler ... .php`.** `AddHandler` and `AddType` match an extension anywhere in the filename, so `shell.php.jpg` is executed as PHP. This is a common path to RCE on hosts whose upload filter only checks the last extension.

  ```bash
  # root: find extension-anywhere handlers
  grep -RniE 'AddHandler|AddType' /etc/apache2 /etc/httpd 2>/dev/null | grep -i php
  ```

- [ ] **Under mod_php, put every security setting in `php_admin_value` / `php_admin_flag`, never `php_value` (root).**

  > `php_value` and `php_flag` can be set from `.htaccess` (with `AllowOverride Options` or `All`) and can be changed again by any `.htaccess` lower in the tree or by `ini_set()`. `php_admin_*` is only accepted in the main config and vhosts, and cannot be overridden by `.htaccess` or `ini_set()`. Anything an attacker would want to loosen (`open_basedir`, `disable_functions`, `allow_url_include`, `auto_prepend_file`, `upload_tmp_dir`) belongs in `php_admin_*`. Note that `disable_functions` is `PHP_INI_SYSTEM` and is ignored when set with `php_value`.

- [ ] **Under PHP-FPM, CGI, and LSAPI, control `.user.ini` (root).**

  > `.user.ini` files are processed by the CGI/FastCGI SAPIs (which includes PHP-FPM) and are the FPM equivalent of `php_value` in `.htaccess`. PHP looks for them in the script's directory and each parent up to the document root, and re-reads them every `user_ini.cache_ttl` seconds (default 300). Any `PHP_INI_PERDIR` or `PHP_INI_USER` setting can be changed there, including `auto_prepend_file`, `auto_append_file`, `display_errors`, and `include_path` (`allow_url_fopen` and `disable_functions` are `PHP_INI_SYSTEM` and cannot be changed there). If your sites do not need it, disable the mechanism per pool:

  ```ini
  php_admin_value[user_ini.filename] =
  ```

  > Settings fixed with `php_admin_value` in the pool should win over `.user.ini`; verify this on your PHP version with the check script from [Section 1](#1-stack-detection) by placing a test `.user.ini` that tries to change one of them. On cPanel, `.user.ini` is also how the MultiPHP INI Editor stores per-directory values, so disabling it there will break panel-managed settings.

---

## 4. .htaccess and .user.ini as an Attack Surface

> The PHP user can write to `wp-content/uploads/` and often to the whole document root. If that user can also write a `.htaccess` or `.user.ini`, a file upload bug becomes code execution and survives a plugin cleanup.

- [ ] **Understand the three persistence patterns.**

  ```apache
  # 1. Re-enable PHP for an innocent extension (dropped into uploads/)
  AddType application/x-httpd-php .jpg
  AddHandler application/x-httpd-php .png
  <FilesMatch "\.gif$">
      SetHandler application/x-httpd-php
  </FilesMatch>
  # On FPM the attacker copies your proxy handler line instead:
  # SetHandler "proxy:unix:/run/php/example.sock|fcgi://localhost"
  ```

  ```ini
  ; 2. .user.ini (FPM/CGI) or php_value in .htaccess (mod_php):
  ;    runs the attacker's file before every PHP request in the tree
  auto_prepend_file = /home/example/public_html/wp-content/uploads/2021/03/thumb.png
  ```

  ```apache
  # 3. .htaccess redirect / SEO spam: send search-engine or mobile visitors elsewhere
  RewriteCond %{HTTP_USER_AGENT} (google|bing) [NC]
  RewriteRule ^(.*)$ https://attacker.example/$1 [R=302,L]
  ```

  > **Why this matters:** The prepend file can have any extension; PHP includes it by path regardless of name, so blocking `.php` in uploads does not stop it. Removing the original webshell does not remove the backdoor while `auto_prepend_file` still points at a copy. Because `.user.ini` is cached for up to 5 minutes, deleting it does not take effect immediately, which confuses incident responders.

- [ ] **Hunt for these files and directives regularly.**

  ```bash
  ROOT=/home/example/public_html     # or ~/public_html on shared hosting

  # Recently changed override files (last 14 days)
  find "$ROOT" \( -name '.htaccess' -o -name '.user.ini' -o -name 'php.ini' \) -mtime -14 -ls

  # Any override file below uploads or cache is suspicious by default
  find "$ROOT/wp-content" \( -name '.htaccess' -o -name '.user.ini' -o -name 'php.ini' \) \
       -not -path '*/wp-content/uploads/.htaccess' -ls

  # Prepend/append and handler tricks
  grep -RInE --include='.htaccess' --include='.user.ini' --include='php.ini' \
       'auto_(prepend|append)_file|AddHandler|AddType|SetHandler|ForceType|php_value|php_flag|x-httpd-php|proxy:unix' "$ROOT"

  # Rewrite-based redirects to external hosts
  grep -RInE --include='.htaccess' 'RewriteRule .*https?://' "$ROOT"

  # PHP code hiding in image-named files
  grep -RalE --include='*.jpg' --include='*.jpeg' --include='*.png' --include='*.gif' \
       --include='*.ico' --include='*.svg' --include='*.txt' '<\?php|eval\(|base64_decode\(' "$ROOT/wp-content/uploads"
  ```

  > Expected hits: the cPanel MultiPHP block (`# php -- BEGIN cPanel-generated handler, do not edit`) at the document root, WordPress's `# BEGIN WordPress` block, and caching or security plugin blocks. Attackers copy these comment markers, so read every line inside them. Compare against a known-good copy kept in version control or your backup.

- [ ] **Make the root `.htaccess` and `.user.ini` read-only to the PHP user where the stack allows it.** If PHP runs as a separate user from the file owner (FPM pools, or mod_php), set them `0644` owned by the deploy user. If PHP runs as the file owner (suPHP, LSAPI, cPanel PHP-FPM), permissions alone cannot protect them; rely on the hunting commands above, file integrity monitoring ([security-audit-automation.md](security-audit-automation.md)), and the host's malware scanner.

- [ ] **If you find any of these, treat it as a compromise, not a cleanup.** Follow [incident-response-checklist.md](incident-response-checklist.md): preserve evidence, rotate database and admin credentials and WordPress salts, and look for database backdoors before deleting files.

---

## 5. Shared Hosting and No-Root Playbook

> On a shared account you control the application, your files, and whatever the panel exposes. You do not control the kernel, Apache build, other tenants, the firewall, or TLS termination. Harden what you can, verify what you cannot, and know when to leave.

**What you can still control**

- [ ] **Pick a supported PHP version in the panel selector** (cPanel MultiPHP Manager, CloudLinux PHP Selector, Plesk PHP settings). PHP 7.4 has been end of life since November 2022, 8.1 since 31 December 2025, and 8.2 reaches end of life on 31 December 2026. See [php-version-upgrade-path.md](php-version-upgrade-path.md) for the upgrade order and compatibility checks.

  > **EOL builds offered by panels:** CloudLinux `alt-php` and its hardened PHP builds (and TuxCare PHP ELS) backport security fixes to versions that are end of life upstream, so `alt-php74` on CloudLinux is not the same risk as a stock 7.4 binary. They patch the interpreter only: your application code, WordPress plugins, and Composer libraries that dropped support for old PHP do not get fixes. The exact list of patched branches changes; confirm it in the CloudLinux documentation for your account. Treat a hardened EOL build as a bridge with a deadline, not a destination.

- [ ] **Set PHP directives in the MultiPHP INI Editor / PHP Selector options** rather than in `.htaccess`. Apply the settings from [wordpress-server-hardening.md Section 3](wordpress-server-hardening.md#3-php-hardening) that the panel exposes: `expose_php = Off`, `display_errors = Off`, `allow_url_include = Off`, session cookie flags, sane upload limits. `disable_functions` and `open_basedir` are often host-controlled; ask support what they enforce.

- [ ] **Disable unused PHP extensions** in the CloudLinux PHP Selector (for example `ffi`, `phar` if unused, `imap`, `xmlrpc`, `soap`, `pdo_sqlite`). Fewer extensions mean less attack surface for deserialization and parser bugs.

- [ ] **Keep ModSecurity enabled for every domain.** If it blocks something, collect the rule ID from the panel's ModSecurity log or the error page and ask support for a targeted exclusion.

- [ ] **Set file permissions for the handler you actually have.**

  ```bash
  cd ~/public_html
  find . -type d -exec chmod 755 {} +
  find . -type f -exec chmod 644 {} +
  chmod 600 wp-config.php        # or 400; works when PHP runs as your user
  ```

  > This works only when PHP runs as your account user (suPHP, LSAPI, cPanel PHP-FPM, Plesk FPM or FastCGI). Under mod_php the Apache user must read `wp-config.php`, so it ends up `0644` and readable by every other tenant's PHP. If the check script in [Section 1](#1-stack-detection) shows `SAPI = apache2handler` on a shared server, your database password is effectively shared with the whole box: move hosts. suPHP refuses to run files that are group- or world-writable, so `777` produces `500` errors there rather than working.

- [ ] **Move `wp-config.php` one level above the document root** where your layout allows it (WordPress looks one directory up automatically), and keep backups, SQL dumps, and `.env` files out of `public_html` entirely.

- [ ] **Use SSH keys, not passwords, and disable FTP.** Import an Ed25519 key in the panel's SSH Access page, then delete unused FTP accounts and prefer SFTP. If the host offers only plain FTP, that is a reason to leave.

- [ ] **Enable two-factor authentication on the panel login** (cPanel "Two-Factor Authentication", Plesk "Google Authenticator" extension) and on the hosting provider's billing account, which can usually reset the panel password.

- [ ] **Use the host's isolation and malware tools if offered.** CloudLinux CageFS gives each account a virtualized filesystem so it cannot see other users or most system files; LVE limits cap one account's CPU and memory; Imunify360 adds malware scanning, a WAF rule set, and proactive PHP defense. Confirm with support that CageFS is enabled for your account, not just installed on the server.

- [ ] **Keep backups off-account.** A backup in the same account is deleted or encrypted along with the site. Use the panel's remote destination (S3-compatible, SFTP) or pull from outside with your own key, and test restores per [disaster-recovery.md](disaster-recovery.md).

- [ ] **Apply the application-level controls**, which do not need root: WordPress configuration, REST lockdown, login protection, and plugin vetting in [wordpress-server-hardening.md](wordpress-server-hardening.md), and the code-level fixes in [php-application-hardening.md](php-application-hardening.md).

**What you cannot control**

- Kernel version and patches, and therefore privilege escalation from another tenant.
- Network firewall, SSH daemon settings, and fail2ban configuration.
- Apache version, MPM, loaded modules, `AllowOverride`, and server-wide headers.
- TLS protocol and cipher configuration on shared IPs.
- Which handler other tenants use, and whether symlink protection is in place.

**When to move off shared hosting**

- [ ] **Migrate to a VPS or managed container platform when any of these is true:**
  - The check script shows `SAPI = apache2handler` (mod_php) or a `PROCESS USER` that is not your account.
  - The only PHP versions offered are end of life and not hardened or backported builds.
  - TLS 1.0/1.1 is still accepted or the certificate cannot be renewed automatically.
  - You need firewall rules, origin lockdown to Cloudflare IPs ([cloudflare-hardening.md](cloudflare-hardening.md)), or log access for incident response that the host will not give you.
  - The site processes payments or health or other regulated data.
  - You have been compromised and cannot rule out lateral movement from another account.

---

## 6. Audit Commands

```bash
# --- Server (root) ---
apachectl -t                                   # syntax check, run before every reload
apachectl -S                                   # vhost map: which vhost answers which name/port, default vhost
apachectl -M | sort                            # loaded modules; look for php/info/status/dav/autoindex/userdir
apachectl -t -D DUMP_INCLUDES                  # every included config file, in order
apachectl -t -D DUMP_RUN_CFG                   # user/group, ServerRoot, PidFile, Mutex
grep -RniE 'AllowOverride|Options|ServerTokens|TraceEnable|php_value|php_flag' \
     /etc/apache2 /etc/httpd 2>/dev/null

# --- Response headers on success AND error pages ---
for p in / /wp-login.php /does-not-exist-$RANDOM; do
  echo "== $p"; curl -sk -o /dev/null -D - "https://example.com$p" \
    | grep -iE '^(HTTP/|server|x-powered-by|strict-transport|x-content-type|x-frame|referrer-policy|permissions-policy)'
done
# A header present on / but missing on the 404 = Header without "always".
# A header listed twice = PHP and Apache both set it.

# --- Blocked paths: expect 403 or 404, never 200 ---
for p in /.git/config /.env /.user.ini /.htaccess /wp-config.php /wp-config.php.bak \
         /xmlrpc.php /wp-content/debug.log /server-status /server-info /phpinfo.php /info.php \
         /wp-admin/install.php /backup.zip /db.sql; do
  printf '%-28s %s\n' "$p" "$(curl -sk -o /dev/null -w '%{http_code}' "https://example.com$p")"
done

# --- PHP execution in uploads: drop a harmless, randomly named test file, request it, delete it ---
T="zz-exec-$(openssl rand -hex 8)"; U=~/public_html/wp-content/uploads
echo '<?php echo "EXECUTED";' > "$U/$T.php"; cp "$U/$T.php" "$U/$T.php.jpg"
curl -sk "https://example.com/wp-content/uploads/$T.php"       # expect 403/404
curl -sk "https://example.com/wp-content/uploads/$T.php.jpg"   # must NOT print EXECUTED
rm -f "$U/$T.php" "$U/$T.php.jpg"

# --- TRACE ---
curl -sk -X TRACE -o /dev/null -w '%{http_code}\n' https://example.com/    # expect 405

# --- Directory listing ---
curl -sk https://example.com/wp-content/uploads/ | grep -i 'Index of' && echo "LISTING ENABLED"

# --- TLS (https://testssl.sh) ---
./testssl.sh --severity MEDIUM --quiet https://example.com
```

> Run the header, path, and upload checks after every panel change, PHP version switch, or plugin that edits `.htaccess` (caching and security plugins rewrite it often). Feed the path list into the weekly digest from [security-audit-automation.md](security-audit-automation.md).

---

## 7. Common Mistakes (Silent Failures)

- [ ] **`<IfModule mod_headers.c>` around security headers.** If the module is not loaded, the block is skipped with no error and the site serves no headers. Prefer a hard failure (`<IfModule !mod_headers.c> Error ... </IfModule>` on 2.4.9+) in config you own, and verify with curl in `.htaccess`.

- [ ] **`Header set` instead of `Header always set`.** Headers disappear from redirects and error pages, and `Header unset` does not remove PHP-emitted headers under proxy_fcgi. See [Section 2](#2-apache-hardening-nginx-equivalents).

- [ ] **`php_admin_flag engine off` under PHP-FPM.** Either Apache fails to start, or every request in the folder returns `500`, and someone "fixes" it by deleting the block, leaving uploads executable.

- [ ] **`<FilesMatch "^\.">` to protect `.git`.** It matches the file name only, so `/.git/config`, `/.git/HEAD`, and `/.svn/entries` are still served. Use the `RedirectMatch 404 "/\.(?!well-known/)"` pattern.

- [ ] **`AddHandler application/x-httpd-php .php`.** It also matches `image.php.jpg`. Use `<FilesMatch "\.php$">` with `SetHandler`.

- [ ] **`php_value` for security settings.** Overridable by any lower `.htaccess` and by `ini_set()`; `disable_functions` set this way is ignored entirely. Use `php_admin_value` in the vhost or FPM pool.

- [ ] **Hardening `php.ini` while PHP-FPM reads a different file.** Panels run several PHP builds side by side (`/opt/cpanel/ea-php81/root/etc/php.ini`, `/opt/alt/php74/etc/php.ini`, `/opt/plesk/php/8.2/etc/php.ini`). Confirm with the check script in [Section 1](#1-stack-detection), not with `php -i` over SSH.

- [ ] **`Require local` on `/server-status` behind a local reverse proxy.** Every public request is local. Use `mod_remoteip` with `RemoteIPInternalProxy`, or protect the location with authentication.

- [ ] **mod_evasive behind Cloudflare without `mod_remoteip`.** It sees only Cloudflare addresses and either blocks Cloudflare (outage) or never triggers.

- [ ] **`SymLinksIfOwnerMatch` treated as tenant isolation.** The Apache docs call it circumventable via race conditions. Isolation comes from separate PHP users, restrictive home directory permissions, and kernel-level symlink protection.

- [ ] **ModSecurity installed but `SecRuleEngine DetectionOnly` forever,** or turned off per domain after the first false positive. Check `SecRuleEngine` in the active config and the panel's per-domain toggles.

- [ ] **Panel rebuild wiping manual edits.** Directly edited `httpd.conf` or vhost files on cPanel or Plesk are regenerated on the next rebuild or update. Use the panel's include files and re-run the [Section 6](#6-audit-commands) checks after panel updates.

- [ ] **Deleting `.user.ini` and assuming the prepend is gone.** PHP caches it for `user_ini.cache_ttl` (300 seconds by default), and the attacker may have planted copies in parent directories. Re-run the hunt in [Section 4](#4-htaccess-and-userini-as-an-attack-surface) after cleanup and reload PHP-FPM if you have root.

- [ ] **Leaving a diagnostic `phpinfo()` file "just for a minute".** Scanners find `info.php`, `phpinfo.php`, and `test.php` within hours. Use a random name and delete it in the same command.

---

*Last reviewed: 2026-11 | Applies to: Apache HTTP Server 2.4 (mod_php, PHP-FPM via proxy_fcgi, mod_fcgid, suPHP, mod_lsapi), PHP 7.x and 8.x, cPanel/WHM with EasyApache 4, CloudLinux (CageFS, alt-php), Plesk, ModSecurity v2 with OWASP CRS v4*
