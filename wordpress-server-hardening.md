# WordPress Server Hardening Checklist

**Security checklist for self-hosted WordPress on Docker/VPS**

> This checklist covers hardening a self-hosted WordPress installation served by Nginx, running in Docker on a Linux VPS. It addresses both the WordPress application layer and the infrastructure around it. Start with this after completing your base Linux server hardening.

---

## Table of Contents

1. [WordPress Configuration](#1-wordpress-configuration)
2. [Nginx Configuration](#2-nginx-configuration)
3. [PHP Hardening](#3-php-hardening)
4. [WordPress REST API](#4-wordpress-rest-api)
5. [Login Security](#5-login-security)
6. [File Permissions](#6-file-permissions)
7. [Plugin Supply Chain Security](#7-plugin-supply-chain-security)
8. [WP-Admin Access Strategy](#8-wp-admin-access-strategy)
9. [WordPress Salts](#9-wordpress-salts)
10. [Version Disclosure](#10-version-disclosure)
11. [Email Security (SPF / DKIM / DMARC)](#11-email-security-spf--dkim--dmarc)
12. [Backup](#12-backup)
13. [Red Flags to Check](#13-red-flags-to-check)
14. [Regular Audit Commands](#14-regular-audit-commands)

---

## 1. WordPress Configuration

> Most WordPress security options are set in `wp-config.php`. In a Docker setup, inject these via environment variables or a mounted config file — never hardcode secrets.

- [ ] **Disable file editing from the admin panel.** This prevents an attacker who gains admin access from using the built-in editor to inject PHP backdoors.

  ```php
  define('DISALLOW_FILE_EDIT', true);
  ```

- [ ] **Disable file modification entirely** (stronger — prevents plugin/theme installation from the admin too).

  ```php
  define('DISALLOW_FILE_MODS', true);
  ```

- [ ] **Enable automatic minor core updates** (security patches) while leaving major updates manual.

  ```php
  define('WP_AUTO_UPDATE_CORE', 'minor');
  ```

- [ ] **Force SSL for the admin panel.** Without this, admin credentials can be sent over HTTP.

  ```php
  define('FORCE_SSL_ADMIN', true);
  ```

- [ ] **Disable WP_DEBUG in production.** Debug mode outputs error messages and stack traces to the browser, leaking file paths and database structure.

  ```php
  define('WP_DEBUG', false);
  define('WP_DEBUG_LOG', false);
  define('WP_DEBUG_DISPLAY', false);
  ```

- [ ] **Disable the built-in WP-Cron** and replace with a real server-side cron. WP-Cron runs on every page load, wasting resources and being exploitable as a DoS vector.

  In `wp-config.php`:
  ```php
  define('DISABLE_WP_CRON', true);
  ```

  Add a real cron job on the server:
  ```bash
  # /etc/cron.d/wp-cron
  */5 * * * * www-data /usr/local/bin/wp --path=/var/www/html cron event run --due-now --quiet
  ```

  Or via docker exec:
  ```bash
  */5 * * * * root docker exec --user www-data WORDPRESS_CONTAINER wp cron event run --due-now --quiet
  ```

  > **Use `--user www-data`**, not `--allow-root`. Running WP-CLI as root inside the container means any file WP-CLI creates (caches, temp files) will be root-owned and may cause permission errors for subsequent www-data requests. `docker exec --user www-data` runs the command as the web server user.

- [ ] **Set a custom database table prefix** (ideally at install time — harder to change later but worth doing for new installs).

  ```php
  $table_prefix = 'wp_a7x3_';  // not 'wp_'
  ```

  > **Why this matters:** SQL injection attacks often guess `wp_users` and `wp_options` by name. A custom prefix does not prevent SQL injection, but it forces attackers to enumerate the actual table names.

- [ ] **Disable concatenation of admin scripts** (minor performance + security: prevents admin JS errors from being hidden).

  ```php
  define('CONCATENATE_SCRIPTS', false);
  ```

---

## 2. Nginx Configuration

> Nginx is your first line of defense. Block known-bad endpoints, rate limit sensitive ones, and add security headers before the request ever reaches WordPress.

- [ ] **Block WordPress installation and upgrade scripts** — these should never be accessible on a live site.

  ```nginx
  location ~* ^/wp-admin/(install|upgrade)\.php$ {
      return 404;
  }
  ```

- [ ] **Block xmlrpc.php.** XML-RPC is a legacy WordPress API that enables brute-force amplification attacks (one request can try thousands of password combinations via multicall). Unless you have a specific need for it, block it entirely.

  ```nginx
  location = /xmlrpc.php {
      return 404;
  }
  ```

  > **Why 404 not 403?** Returning 403 confirms the file exists. Returning 404 tells scanners there is nothing there, reducing follow-up probing.

- [ ] **Block direct access to wp-cron.php** (you replaced it with server-side cron above).

  ```nginx
  location = /wp-cron.php {
      return 404;
  }
  ```

- [ ] **Rate limit wp-login.php** to 5 requests per minute per IP. This is your primary brute-force mitigation.

  ```nginx
  limit_req_zone $binary_remote_addr zone=wplogin:10m rate=5r/m;

  location = /wp-login.php {
      limit_req zone=wplogin burst=2 nodelay;
      include fastcgi_params;
      fastcgi_pass wordpress:9000;
      fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
  }
  ```

- [ ] **Rate limit admin-ajax.php** to prevent abuse of AJAX endpoints.

  ```nginx
  limit_req_zone $binary_remote_addr zone=wpadmin:10m rate=10r/m;

  location = /wp-admin/admin-ajax.php {
      limit_req zone=wpadmin burst=5 nodelay;
      include fastcgi_params;
      fastcgi_pass wordpress:9000;
      fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
  }
  ```

- [ ] **Rate limit WP Statistics hit endpoint** (or any high-frequency stats/analytics endpoint) to prevent log flooding DoS.

  ```nginx
  limit_req_zone $binary_remote_addr zone=wpstats:10m rate=2r/m;

  location ~* /wp-json/wp-statistics/v2/ {
      limit_req zone=wpstats burst=3 nodelay;
      try_files $uri $uri/ /index.php?$args;
  }
  ```

- [ ] **Deny PHP execution in the uploads directory.** This prevents uploaded PHP webshells from being executed. This is one of the most critical rules.

  ```nginx
  location ~* /wp-content/uploads/.*\.php$ {
      deny all;
      return 404;
  }
  ```

- [ ] **Block `?author=N` enumeration.** WordPress leaks usernames via this URL pattern by default, redirecting to `/author/username/`.

  ```nginx
  if ($query_string ~* "author=\d+") {
      return 403;
  }
  ```

- [ ] **Remove the `X-Powered-By` header** to avoid disclosing the PHP version.

  ```nginx
  fastcgi_hide_header X-Powered-By;
  ```

  Also set in php.ini: `expose_php = Off`

- [ ] **Add all required security headers.** These protect against clickjacking, MIME sniffing, cross-site scripting, and data leakage.

  ```nginx
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
  add_header X-Frame-Options "SAMEORIGIN" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

  # Content Security Policy — start restrictive and loosen as needed
  add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'self';" always;
  ```

  > **Note on CSP:** `unsafe-inline` and `unsafe-eval` are required by many WordPress themes and plugins. Start here and tighten once you audit your dependencies. Use `report-uri` or `report-to` to discover violations before enforcing.

  > **`X-XSS-Protection` removed:** This header was deprecated by all modern browsers (Chrome 78+, Firefox, Safari). It has no effect on current browsers and can trigger XSS vulnerabilities (UXSS) in legacy Internet Explorer by interfering with inline scripts that are not attacks. CSP with `frame-ancestors` already provides equivalent protection.

- [ ] **Verify headers are set correctly** using curl or a tool like securityheaders.com.

  ```bash
  curl -I https://yourdomain.com
  ```

- [ ] **Repeat `add_header` directives in every child location block that has its own headers.**

  > **Critical nginx inheritance gotcha:** In nginx, if a `location` block contains ANY `add_header` directive, it inherits **none** of the `add_header` directives from the parent `server` or `http` block. A `location = /wp-login.php` that adds one header will silently drop all the security headers above for that path.
  >
  > The fix is to put all shared headers in an include file:
  >
  > ```nginx
  > # /etc/nginx/snippets/security-headers.conf
  > add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
  > add_header X-Frame-Options "SAMEORIGIN" always;
  > add_header X-Content-Type-Options "nosniff" always;
  > add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  > add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
  > add_header Content-Security-Policy "..." always;
  >
  > # Then in each location block that needs additional headers:
  > location = /wp-login.php {
  >     include snippets/security-headers.conf;
  >     limit_req zone=wplogin burst=2 nodelay;
  >     # ...fastcgi config
  > }
  > ```
  >
  > For a simple WordPress config where only the catch-all `location /` handles most traffic, placing `add_header` inside `location /` avoids this issue for the majority of requests. Still repeat headers explicitly in any other location block that sets its own headers.

---

## 3. PHP Hardening

> PHP's default configuration exposes too much. These settings minimize information leakage and prevent dangerous function calls.

- [ ] **Disable PHP version disclosure.**

  In `php.ini`:
  ```ini
  expose_php = Off
  ```

- [ ] **Disable dangerous PHP functions** that should never be called in a WordPress/web context.

  ```ini
  disable_functions = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,proc_get_status,pcntl_fork,pcntl_signal,mail,putenv,dl
  ```

  > **Why this matters:** If an attacker finds a code injection vulnerability (RCE), `disable_functions` is a second layer preventing them from running system commands. It does not prevent all attacks, but it raises the bar significantly.

  > **`mail`, `putenv`, and `dl` are required here** to block the Chankro disable_functions bypass: an attacker calls `putenv('LD_PRELOAD=/tmp/evil.so')` to set the dynamic linker environment variable, then calls `mail()` — which forks a `sendmail` subprocess. That subprocess inherits `LD_PRELOAD` and loads the malicious `.so` file, executing arbitrary code completely outside PHP's disable_functions list. `dl()` loads PHP extensions at runtime, bypassing disable_functions directly. WordPress does not require any of these three functions when using an SMTP relay plugin (see Section 11) — `wp_mail()` goes through the SMTP plugin, not PHP's `mail()`.

  > **Note:** Some plugins or CLI tools (like WP-CLI) may use the other functions in this list. Test after applying. `proc_open` is used by some plugins; remove it from the list only if you have a verified need.

- [ ] **Harden PHP session security.**

  ```ini
  session.cookie_httponly = 1
  session.cookie_secure = 1
  session.use_strict_mode = 1
  session.cookie_samesite = Lax
  ```

- [ ] **Set a reasonable upload size limit** — do not leave it at unlimited.

  ```ini
  upload_max_filesize = 10M
  post_max_size = 12M
  ```

- [ ] **Disable `allow_url_fopen` and `allow_url_include`** to block remote file inclusion attacks.

  ```ini
  allow_url_fopen = Off
  allow_url_include = Off
  ```

  > **Note:** Some plugins legitimately use `allow_url_fopen` for HTTP requests. WordPress itself uses `WP_HTTP` which does not rely on this. Test with your plugin set before disabling.

- [ ] **Set `open_basedir`** to restrict PHP file access to the webroot and upload tmp directory only. This limits the damage if an attacker achieves code execution — they cannot read `/etc/passwd` or files outside the web directory.

  ```ini
  open_basedir = /var/www/html:/tmp:/var/tmp
  ```

  > **In Docker:** Set this in your mounted `security.ini` file. Test carefully after enabling — some plugins perform legitimate file operations outside the webroot (e.g. writing to `/tmp`). If a plugin breaks, add its required path to `open_basedir` rather than disabling it.

  > **Known bypass: `chdir` + `ini_set`**. If `chdir` and `ini_set` are available (not in `disable_functions`), an attacker can call `chdir('/')` followed by `ini_set('open_basedir', '/')` to remove the restriction entirely. If your plugin set does not require these functions in end-user code paths, add them to `disable_functions`. Note: WordPress core uses `chdir` in some admin flows and `ini_set` for memory limits — test thoroughly before disabling.

- [ ] **Disable PHP FFI** (PHP 7.4+). The Foreign Function Interface extension allows calling arbitrary C library functions directly from PHP, bypassing `disable_functions` entirely.

  ```ini
  ffi.enable = false
  ```

  > WordPress does not use FFI. If any plugin requires it, that is a red flag worth investigating before enabling.

- [ ] **Isolate upload and session temp directories** per application.

  ```ini
  upload_tmp_dir = /var/www/html/wp-content/tmp-uploads
  session.save_path = /var/www/html/wp-content/tmp-sessions
  ```

  Create these directories with restricted permissions:

  ```bash
  mkdir -p /var/www/html/wp-content/tmp-uploads /var/www/html/wp-content/tmp-sessions
  chmod 700 /var/www/html/wp-content/tmp-uploads /var/www/html/wp-content/tmp-sessions
  chown www-data:www-data /var/www/html/wp-content/tmp-uploads /var/www/html/wp-content/tmp-sessions
  ```

- [ ] **Harden PHP OPcache** — prevents cache poisoning and reduces information leakage.

  ```ini
  opcache.enable = 1
  opcache.memory_consumption = 128
  opcache.validate_timestamps = 1
  opcache.revalidate_freq = 2
  opcache.max_accelerated_files = 10000
  ; Restrict OPcache API calls (opcache_invalidate, opcache_reset) to scripts under this path.
  ; An empty string means NO restriction — any PHP script anywhere can call the OPcache API.
  ; Setting to the webroot prevents scripts running from /tmp or injected paths from poisoning the cache.
  opcache.restrict_api = /var/www/html
  ```

  > **`validate_timestamps = 1` with `revalidate_freq = 2`:** PHP checks each file for changes at most every 2 seconds. This is essential for git-pull deployments — with `validate_timestamps = 0`, code changes are never picked up until PHP-FPM is restarted/reloaded. If your deploy script does `git pull` but never runs `php-fpm reload`, old bytecode silently stays live after a security patch or code fix. The 2-second window has negligible performance impact (&lt;1%) and eliminates stale-code deployment bugs.

- [ ] **In a Docker setup, set PHP config via a mounted ini file** — do not bake credentials or environment-specific values into the image.

  ```yaml
  volumes:
    - ./php/security.ini:/usr/local/etc/php/conf.d/security.ini:ro
  ```

---

## 4. WordPress REST API

> The REST API is powerful and exposed by default. Lock down endpoints that are not intended for public use.

- [ ] **Disable unauthenticated access to internal namespaces.** The following endpoints expose site health data, editor capabilities, and block editor internals — none of which should be public.

  Add to your theme's `functions.php` or a custom plugin:

  ```php
  add_filter('rest_authentication_errors', function($result) {
      if (!empty($result)) {
          return $result;
      }
      $blocked_namespaces = ['wp-site-health', 'wp-block-editor'];
      $request = $GLOBALS['wp']->query_vars['rest_route'] ?? '';
      foreach ($blocked_namespaces as $ns) {
          if (str_starts_with(ltrim($request, '/'), $ns)) {
              return new WP_Error('rest_forbidden', 'Access denied.', ['status' => 401]);
          }
      }
      return $result;
  });
  ```

- [ ] **Disable the `/wp/v2/users` endpoint** to prevent username enumeration via the REST API.

  ```php
  add_filter('rest_endpoints', function($endpoints) {
      if (isset($endpoints['/wp/v2/users'])) {
          unset($endpoints['/wp/v2/users']);
      }
      if (isset($endpoints['/wp/v2/users/(?P<id>[\d]+)'])) {
          unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
      }
      return $endpoints;
  });
  ```

- [ ] **Block `?author=` redirect at Nginx level** (covered in Section 2 above, but double-check it is in place).

- [ ] **Require nonces for custom REST endpoints** that perform state-changing operations and are not intended for public/third-party use.

  ```php
  register_rest_route('myplugin/v1', '/action', [
      'methods' => 'POST',
      'callback' => 'my_callback',
      'permission_callback' => function() {
          return current_user_can('edit_posts');
      },
  ]);
  ```

- [ ] **Audit all registered REST routes** on your production site.

  ```bash
  curl -s https://yourdomain.com/wp-json/ | jq '.namespaces'
  curl -s https://yourdomain.com/wp-json/wp/v2/ | jq 'keys'
  ```

- [ ] **Consider disabling the REST API entirely for unauthenticated users** if your site does not use it for public-facing features (e.g. a brochure site with no headless frontend).

  ```php
  add_filter('rest_authentication_errors', function($result) {
      if (!is_user_logged_in()) {
          return new WP_Error('rest_disabled', 'REST API is disabled.', ['status' => 401]);
      }
      return $result;
  });
  ```

---

## 5. Login Security

> WordPress's login page is one of the most targeted endpoints on the internet. Defense-in-depth here is essential.

- [ ] **Use generic error messages for failed logins.** By default, WordPress tells you "incorrect password" vs "no account with that email" — this helps attackers enumerate valid usernames.

  ```php
  add_filter('login_errors', function() {
      return 'Invalid username or password.';
  });
  ```

- [ ] **Rate limit wp-login.php at Nginx** (covered in Section 2 — verify it is in place).

- [ ] **Configure fail2ban for WordPress login failures** (covered in the Linux hardening guide — verify the nginx-wplogin jail is active).

- [ ] **Block XML-RPC entirely** (covered in Section 2 — xmlrpc.php returns 404).

- [ ] **Do not disclose the WordPress admin URL** in error messages, comments, or meta tags.

- [ ] **Enable two-factor authentication** for admin accounts using a plugin like WP 2FA or Two Factor.

- [ ] **Use a strong, unique password** for all WordPress admin accounts — at least 20 characters, generated by a password manager.

- [ ] **Delete unused admin accounts.** Every admin account is an attack surface.

- [ ] **Check for the `admin` username** — if it exists as an admin, create a new admin, log in as the new admin, and delete the `admin` account.

  ```bash
  wp user list --role=administrator --fields=user_login,user_email
  ```

---

## 6. File Permissions

> Loose file permissions are a common way for attackers to escalate from a file write to a full compromise.

- [ ] **Set `wp-config.php` to 440** — readable only by owner and group, not world-readable.

  ```bash
  chmod 440 /var/www/html/wp-config.php
  ```

- [ ] **Set uploads directory to 755** — writable by the web server user, not executable.

  ```bash
  chmod -R 755 /var/www/html/wp-content/uploads
  find /var/www/html/wp-content/uploads -type f -exec chmod 644 {} \;
  ```

- [ ] **Block PHP execution in uploads via Nginx** (covered in Section 2).

- [ ] **Set WordPress core files to 644 / directories to 755.**

  ```bash
  find /var/www/html -type f -exec chmod 644 {} \;
  find /var/www/html -type d -exec chmod 755 {} \;
  chmod 440 /var/www/html/wp-config.php
  ```

- [ ] **Verify the web server cannot write to core WordPress files** (only uploads and cache directories should be writable).

- [ ] **In Docker:** ensure the WordPress volume does not have world-writable files.

  ```bash
  find /var/www/html -perm -0002 -type f
  ```

---

## 7. Plugin Supply Chain Security

> Plugins are the primary vector for WordPress compromises. Most WordPress site hacks exploit vulnerable plugins, not WordPress core. Supply chain attacks — where a legitimate plugin is taken over, sold, or abandoned and then injected with malicious code — are increasingly common.

- [ ] **Minimize the number of installed plugins.** Every additional plugin is potential attack surface.

- [ ] **Keep all plugins updated.** Enable auto-updates for plugins where possible.

  ```bash
  wp plugin update --all
  ```

- [ ] **Check for known vulnerabilities before installing a new plugin.**

  ```bash
  wpscan --url https://yourdomain.com --enumerate vp --api-token YOUR_WPSCAN_TOKEN
  ```

- [ ] **Remove deactivated plugins** — a deactivated plugin's files are still accessible on disk and can be exploited.

  ```bash
  wp plugin list --status=inactive
  wp plugin delete PLUGIN_NAME
  ```

- [ ] **Check plugin provenance.** Only install plugins from wordpress.org or known reputable vendors. Nulled (pirated) plugins almost universally contain backdoors.

- [ ] **Review what permissions plugins request.** A plugin that requires filesystem access or database admin privileges for no obvious reason is a red flag.

- [ ] **Check the wordpress.org vulnerability database** for plugins you already have installed.

  - https://wpscan.com/plugins
  - https://patchstack.com/database

### Before Installing Any Plugin — Vetting Checklist

Run through these for every plugin before adding it to production:

- [ ] **Active install count** — plugins with < 1,000 active installs have had less community scrutiny.
- [ ] **Last updated date** — if not updated in 2+ years and WordPress has had major releases since, treat as unmaintained.
- [ ] **Tested up to** version — if it says "tested up to 5.x" and you are running 6.x, there may be compatibility issues or the maintainer is inactive.
- [ ] **Author reputation** — check the plugin author's other plugins and their support forum responses.
- [ ] **Support forum health** — scan recent threads for security-related issues or patterns of unanswered bug reports.
- [ ] **Code review for small plugins** — for plugins under ~500 lines, read the code. Look for: `eval()`, `base64_decode()`, `system()`, `exec()`, outbound `curl` calls, `wp_remote_get()` to external URLs.
- [ ] **Check if the plugin was recently sold or transferred** — ownership changes are a known supply chain attack vector. Plugin changelogs sometimes note this.
- [ ] **Verify plugin on wordpress.org** — do not install ZIP files from unofficial sources unless you have read and understood the code.

### Ongoing Supply Chain Controls

- [ ] **Disable admin-side plugin installation** in production. Plugins should be deployed via code, not clicked in through the admin panel.

  ```php
  define('DISALLOW_FILE_MODS', true);  // prevents plugin/theme install and update from admin
  ```

- [ ] **Run WPScan on a schedule** to catch newly disclosed CVEs in plugins you already have installed. (See `security-audit-automation.md`)

- [ ] **Subscribe to Patchstack or WPScan alerts** for your installed plugins — get notified when a CVE drops before attackers exploit it.

- [ ] **Consider runtime virtual patching** for critical plugin CVEs. Patchstack (free community tier) and Wordfence both deploy WAF rules that block known exploit patterns for specific CVEs — this provides a window of protection between disclosure and your next maintenance window when you can actually update the plugin. It is not a substitute for updating, but it reduces your exposure during the gap.

- [ ] **Test plugin updates in staging before production.** A plugin update that changes a hook or permission can silently break security rules.

---

## 8. WP-Admin Access Strategy

> The `/wp-admin` path is the highest-value target on any WordPress installation. Rate limiting helps, but an additional layer (IP allowlist or Basic Auth) stops untargeted scanners and credential stuffing entirely.

Choose one of the following strategies based on your situation.

### Option A: IP Allowlist (Strongest — for static IP users)

Restrict `wp-admin` to your known IP addresses only at the Nginx level. Anyone else receives 403.

```nginx
# In your nginx server block:
location /wp-admin/ {
    allow 1.2.3.4;        # your home IP
    allow 5.6.7.8;        # your office IP or VPN exit node
    deny all;

    # Pass to PHP-FPM for allowlisted IPs
    try_files $uri $uri/ /index.php?$args;
}
```

> **Cloudflare users:** If using Cloudflare, your real IP is in `$http_cf_connecting_ip`, not `$remote_addr`. Use `ngx_http_realip_module` to restore the real IP before this block fires, or apply the allowlist rule in Cloudflare's WAF instead (recommended).

**Pros:** An attacker who does not know your IP cannot reach the login page at all.

**Cons:** Breaks if you travel without a VPN. Requires updating when your IP changes.

### Option B: HTTP Basic Authentication (Practical — for dynamic IP users)

Add a password prompt in front of `wp-admin`. Even if an attacker finds the path, they need a second credential.

```bash
# Install apache2-utils for htpasswd
apt install apache2-utils -y

# Create the password file (NOT inside webroot)
htpasswd -c /etc/nginx/wp-admin-auth admin
# Enter a strong password when prompted
chown root:www-data /etc/nginx/wp-admin-auth
chmod 640 /etc/nginx/wp-admin-auth
```

Add to nginx:

```nginx
location /wp-admin/ {
    auth_basic "Restricted";
    auth_basic_user_file /etc/nginx/wp-admin-auth;
    try_files $uri $uri/ /index.php?$args;
}

# wp-login.php needs Basic Auth too
location = /wp-login.php {
    auth_basic "Restricted";
    auth_basic_user_file /etc/nginx/wp-admin-auth;
    limit_req zone=wplogin burst=3 nodelay;
    # ... rest of your fastcgi_pass config
}
```

> **Note:** WordPress AJAX calls go to `/wp-admin/admin-ajax.php`. If your theme uses AJAX for public features, you need to exempt admin-ajax from Basic Auth:
>
> ```nginx
> location = /wp-admin/admin-ajax.php {
>     auth_basic off;
>     # your normal fastcgi config
> }
> ```

**Pros:** Works from any IP. Simple to set up. Stops all automated scanners that don't handle HTTP auth.

**Cons:** Shared credential, harder to revoke per person. Doesn't protect AJAX endpoints for public use.

### Option C: Cloudflare WAF Rule (Best for Cloudflare users)

See `cloudflare-hardening.md` Section 6 for WAF rules that challenge or block `wp-login.php` from non-whitelisted IPs or countries.

---

## 9. WordPress Salts

> Salts and secret keys are used to secure WordPress authentication cookies. Weak or default salts allow session forgery.

- [ ] **Generate cryptographically strong salts** — at least 80 random characters per key.

  ```bash
  # Generate via the WordPress API:
  curl -s https://api.wordpress.org/secret-key/1.1/salt/

  # Or generate locally:
  openssl rand -base64 64
  ```

- [ ] **Do not hardcode salts in `docker-compose.yml`** environment variables that end up in version control.

  Instead, store them in a separate file that is `.gitignore`d:

  ```bash
  # /etc/wordpress/wp-salts.php (mode 400, owned by root)
  define('AUTH_KEY',         'RANDOM_80_CHARS...');
  define('SECURE_AUTH_KEY',  'RANDOM_80_CHARS...');
  define('LOGGED_IN_KEY',    'RANDOM_80_CHARS...');
  define('NONCE_KEY',        'RANDOM_80_CHARS...');
  define('AUTH_SALT',        'RANDOM_80_CHARS...');
  define('SECURE_AUTH_SALT', 'RANDOM_80_CHARS...');
  define('LOGGED_IN_SALT',   'RANDOM_80_CHARS...');
  define('NONCE_SALT',       'RANDOM_80_CHARS...');
  ```

  Include in `wp-config.php` using an absolute path:
  ```php
  require_once('/etc/wordpress/wp-salts.php');
  ```

  > **Use an absolute path.** When WordPress loads `wp-config.php` via `WORDPRESS_CONFIG_EXTRA` in Docker, the `__DIR__` and relative paths may not resolve correctly because the eval context differs from the file's location.

- [ ] **Rotate salts** if you suspect a compromise or after a plugin vulnerability is exploited. Rotating salts logs out all users immediately.

---

## 10. Version Disclosure

> Disclosing your WordPress version and plugin versions helps attackers find applicable CVEs quickly. Remove all version hints.

- [ ] **Remove the WordPress version meta tag** from the `<head>`.

  ```php
  remove_action('wp_head', 'wp_generator');
  ```

- [ ] **Strip `?ver=` version parameters from enqueued scripts and styles.** These expose plugin and WordPress versions to passive scanning.

  ```php
  add_filter('style_loader_src', 'remove_ver_query_string', 10, 2);
  add_filter('script_loader_src', 'remove_ver_query_string', 10, 2);

  function remove_ver_query_string($src) {
      if (strpos($src, 'ver=')) {
          $src = remove_query_arg('ver', $src);
      }
      return $src;
  }
  ```

- [ ] **Verify with curl** that no version is disclosed.

  ```bash
  curl -s https://yourdomain.com | grep -i 'generator\|ver='
  ```

- [ ] **Remove the `readme.html` and `license.txt` files** from the webroot — they disclose the WordPress version.

  ```bash
  rm /var/www/html/readme.html /var/www/html/license.txt
  ```

  Or block via Nginx:
  ```nginx
  location ~* ^/(readme|license)\.(html|txt)$ {
      return 404;
  }
  ```

---

## 11. Email Security (SPF / DKIM / DMARC)

> WordPress sends email: password resets, contact form submissions, admin notifications. Without proper email authentication, these emails are easily spoofed — an attacker can send phishing emails that appear to come from your domain. Email security is also required for password reset emails to reliably reach inboxes.

### Why This Matters

- **SPF** — tells receiving mail servers which IP addresses are authorized to send email for your domain. Prevents basic spoofing.
- **DKIM** — cryptographic signature on outgoing mail. Proves the email was sent by someone with access to your domain's private key.
- **DMARC** — ties SPF and DKIM together. Tells receiving servers what to do with email that fails both checks (reject, quarantine, or report only).

Together: if an attacker tries to send `From: noreply@yourdomain.com`, receiving mail servers will reject or quarantine the message.

### Step 1: Use an SMTP Relay for WordPress Mail

WordPress uses PHP's `mail()` by default. This sends from the web server's IP — which is not in your SPF record and not signed with DKIM. Use a dedicated SMTP service instead.

Recommended free-tier options:
- **Mailgun** (5,000 emails/month free)
- **SendGrid** (100 emails/day free)
- **Brevo (Sendinblue)** (300 emails/day free)

Install **WP Mail SMTP** plugin and configure it with your SMTP relay credentials.

```php
// Or configure SMTP directly in wp-config.php via a constants-based plugin
define('WPMS_ON', true);
define('WPMS_MAILER', 'smtp');
define('WPMS_SMTP_HOST', 'smtp.mailgun.org');
define('WPMS_SMTP_PORT', 587);
define('WPMS_SSL', 'tls');
define('WPMS_SMTP_AUTH', true);
define('WPMS_SMTP_USER', 'postmaster@mg.yourdomain.com');
define('WPMS_SMTP_PASS', 'YOUR_MAILGUN_SMTP_PASSWORD');
define('WPMS_SET_RETURN_PATH', true);
```

### Step 2: Add DNS Records

Add to your domain's DNS (at your registrar or Cloudflare):

**SPF record** (TXT record at `@` or `yourdomain.com`):

```
v=spf1 include:mailgun.org ~all
```

If using multiple services, include all of them:

```
v=spf1 include:mailgun.org include:_spf.google.com ~all
```

> Use `~all` (softfail) initially, then tighten to `-all` (hard reject) once you are confident all your sending sources are listed.

**DKIM record** — your SMTP provider generates this. Mailgun example (TXT record):

```
# Name: mailo._domainkey.yourdomain.com
# Value: (provided by Mailgun in their dashboard)
v=DKIM1; k=rsa; p=MIGfMA0GCSqG...
```

  > **The DKIM selector (`mailo` in this example) is provider-assigned**, not something you choose. Mailgun uses `mailo` as their default selector; SendGrid, Brevo, and other providers use different names (e.g. `s1`, `smtp`, `em`). Always copy the exact record name from your provider's DNS setup instructions — do not guess.

**DMARC record** (TXT record at `_dmarc.yourdomain.com`):

Start with `p=none` to collect reports without blocking, then tighten:

```
v=DMARC1; p=none; rua=mailto:dmarc-reports@yourdomain.com; ruf=mailto:dmarc-reports@yourdomain.com; fo=1
```

After 2-4 weeks of reviewing reports, move to:

```
v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@yourdomain.com; pct=100
```

And eventually:

```
v=DMARC1; p=reject; rua=mailto:dmarc-reports@yourdomain.com; pct=100
```

### Step 3: Verify

```bash
# Check SPF record
dig TXT yourdomain.com | grep spf

# Check DMARC record
dig TXT _dmarc.yourdomain.com

# Online validators
# https://mxtoolbox.com/spf.aspx
# https://dmarcian.com/dmarc-inspector/
```

### Step 4: Protect Contact Forms from Abuse

WordPress contact forms (Contact Form 7, WPForms, Gravity Forms) are a common spam vector. Protect them:

- [ ] **Add reCAPTCHA v3** (invisible, no challenge for real users) to all public-facing forms.
- [ ] **Rate limit form submission** endpoints at Nginx level.
- [ ] **Use Akismet** for comment and form spam filtering.
- [ ] **Do not expose the admin email** in form `From:` headers — use a dedicated `noreply@yourdomain.com`.

---

## 12. Backup

> See the Linux hardening guide for the full backup strategy. WordPress-specific additions:

- [ ] **Back up the database with `mysqldump`**, not by copying the raw database files (which may be inconsistent on a running server).

  ```bash
  docker exec DB_CONTAINER mysqldump -u root -p"$MYSQL_ROOT_PASSWORD" \
    --single-transaction --add-drop-table wordpress > /backups/wp-db-$(date +%Y%m%d).sql
  ```

- [ ] **Back up the `wp-content/uploads` directory** — this is user data that cannot be reconstructed.

- [ ] **Test your restore procedure.** Know exactly how to restore a backup before you need to.

- [ ] **If using UpdraftPlus:** configure remote storage (S3, Google Drive, SFTP). Local-only backups do not protect against server loss.

- [ ] **After any major change** (plugin install, core update, config change), take a manual backup before proceeding.

---

## 13. Red Flags to Check

> Run these checks periodically and always after a security incident. Each item represents a common misconfiguration or compromise indicator.

- [ ] **`debug.log` accessible from the web** — contains database credentials, file paths, and errors.

  ```bash
  curl -s -o /dev/null -w "%{http_code}" https://yourdomain.com/wp-content/debug.log
  # Should be 404
  ```

- [ ] **`.git` directory exposed** — leaks your entire source code, history, and potentially credentials.

  ```bash
  curl -s -o /dev/null -w "%{http_code}" https://yourdomain.com/.git/config
  # Should be 404
  ```

- [ ] **`wp-config.php.bak` or `wp-config.php.old`** accessible — these are backup files created by some editors and contain all your database credentials.

  ```bash
  curl -s -o /dev/null -w "%{http_code}" https://yourdomain.com/wp-config.php.bak
  # Should be 404
  ```

- [ ] **`phpinfo.php` in webroot** — discloses PHP version, loaded modules, configuration, and server paths.

  ```bash
  curl -s -o /dev/null -w "%{http_code}" https://yourdomain.com/phpinfo.php
  # Should be 404
  ```

- [ ] **`backup.zip`, `backup.tar.gz`, or similar archives in webroot** — this is a complete site backup downloadable by anyone.

  ```bash
  curl -s -o /dev/null -w "%{http_code}" https://yourdomain.com/backup.zip
  # Should be 404
  ```

- [ ] **User enumeration via `?author=1` redirect** — should not redirect to `/author/USERNAME/`.

  ```bash
  curl -s -o /dev/null -w "%{http_code}" "https://yourdomain.com/?author=1"
  # Should be 403 or not redirect to author page
  ```

---

## 14. Regular Audit Commands

> Run these on a schedule (monthly minimum) and after any significant change.

```bash
# Full WPScan with API key (checks plugin CVEs)
wpscan --url https://yourdomain.com \
  --enumerate vp,vt,u \
  --api-token YOUR_WPSCAN_TOKEN

# Check currently active plugins
wp plugin list --status=active --fields=name,version,update

# Check REST API user enumeration
curl -s https://yourdomain.com/wp-json/wp/v2/users | jq '.[].slug'
# Should return 401 or empty

# Check security headers
curl -I https://yourdomain.com | grep -iE 'strict-transport|x-frame|x-content|referrer|permissions|content-security'

# Verify xmlrpc is blocked
curl -s -o /dev/null -w "%{http_code}" https://yourdomain.com/xmlrpc.php
# Should be 404

# Check for debug.log exposure
curl -s -o /dev/null -w "%{http_code}" https://yourdomain.com/wp-content/debug.log
# Should be 404

# Check for .git exposure
curl -s -o /dev/null -w "%{http_code}" https://yourdomain.com/.git/config
# Should be 404

# Check fail2ban status for WordPress jail
fail2ban-client status nginx-wplogin

# Check for recently modified files (potential compromise indicator)
find /var/www/html -name "*.php" -newer /var/www/html/wp-config.php -mtime -7

# SSL check
curl -vI https://yourdomain.com 2>&1 | grep -iE 'SSL|TLS|expire|issuer'
```

---

*Last reviewed: 2025 | Applies to: WordPress, Nginx, PHP (modern versions)*
