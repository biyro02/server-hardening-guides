# Local to Production Deployment Checklist

**Everything to verify before and after deploying a web application to a production server**

> This checklist covers the full lifecycle of a production deployment — from verifying your local environment is clean, through infrastructure checks, to post-deploy validation. It is written for containerized web applications (Docker + Nginx) but most sections apply broadly. Work through it linearly on your first deploy; use it as a spot-check on subsequent deploys.

---

## Table of Contents

1. [Pre-Deploy: Environment Separation](#1-pre-deploy-environment-separation)
2. [Pre-Deploy: Dependency Audit](#2-pre-deploy-dependency-audit)
3. [Pre-Deploy: Secrets Audit](#3-pre-deploy-secrets-audit)
4. [Infrastructure Checklist](#4-infrastructure-checklist)
5. [Application Checklist](#5-application-checklist)
6. [Docker Deployment Checklist](#6-docker-deployment-checklist)
7. [Post-Deploy Verification](#7-post-deploy-verification)
8. [Monitoring Setup](#8-monitoring-setup)
9. [Rollback Plan](#9-rollback-plan)
10. [CI/CD Security](#10-cicd-security)
11. [DNS Security](#11-dns-security)
12. [Security Scan Commands](#12-security-scan-commands)
13. [Common Mistakes](#13-common-mistakes)

---

## 1. Pre-Deploy: Environment Separation

> The most common production incident is a dev environment config ending up on a production server. Treat every environment as distinct, from the first line of your `.env` file.

- [ ] **Maintain separate `.env` files** for local, staging, and production. Never copy your local `.env` to the server.

  ```
  .env.local        # local dev
  .env.staging      # staging server
  .env.production   # production (never committed to git)
  ```

- [ ] **Verify `APP_ENV` or equivalent is set to `production`**, not `development` or `local`.

- [ ] **Disable all debug flags in production.**

  - `WP_DEBUG = false`
  - `APP_DEBUG = false`
  - `NODE_ENV = production`
  - Remove or disable any debug toolbar plugins.

- [ ] **Use production database credentials** — never point production at a local or staging database.

- [ ] **Use different salts, secret keys, and JWT secrets** per environment. A secret shared across environments means a breach in one environment compromises all.

- [ ] **Verify `FORCE_SSL_ADMIN = true`** (WordPress) or equivalent HTTPS enforcement for admin paths.

- [ ] **Check that the production `SITE_URL` and `HOME_URL`** (WordPress) or equivalent are set to the production domain, not localhost.

  ```bash
  # WordPress via WP-CLI
  wp option get siteurl
  wp option get home
  ```

- [ ] **Remove or disable demo data, test accounts, and seed users** before going live.

- [ ] **Confirm the production domain is in `ALLOWED_HOSTS`** (Django), CORS settings, or CSP `connect-src` — and that `localhost` is not.

---

## 2. Pre-Deploy: Dependency Audit

> Dependencies are code you did not write and may not control. Audit them before every production deployment.

- [ ] **Run Node.js dependency audit.**

  ```bash
  npm audit
  # Fix critical and high severity issues
  npm audit fix
  # Review what cannot be auto-fixed
  npm audit --audit-level=high
  ```

- [ ] **Run Composer dependency audit** (PHP).

  ```bash
  composer audit
  ```

- [ ] **Check for outdated packages** — being current reduces vulnerability surface.

  ```bash
  npm outdated
  composer outdated
  ```

- [ ] **For WordPress: check all plugins and themes are up to date.**

  ```bash
  wp plugin list --update=available
  wp theme list --update=available
  ```

- [ ] **Review any packages added since the last deploy.** New dependencies should be intentional, not transitive surprises.

  ```bash
  git diff LAST_DEPLOY_TAG..HEAD -- package.json composer.json
  ```

- [ ] **Pin dependency versions** in production — avoid `^` and `~` ranges in `package.json` for production builds. Use `npm ci` (which respects `package-lock.json`) rather than `npm install`.

  ```bash
  npm ci --omit=dev
  ```

- [ ] **Check Docker image versions** — do not use `:latest` in production (covered in Docker section below).

---

## 3. Pre-Deploy: Secrets Audit

> A single leaked credential in a git commit can compromise your entire infrastructure. Run these checks before every push to main.

- [ ] **Grep the codebase for common secret patterns.**

  ```bash
  # Passwords and tokens
  grep -rE "(password|passwd|secret|token|api_key|apikey|api-key)\s*=\s*.{8,}" \
    --include="*.php" --include="*.js" --include="*.py" --include="*.ts" \
    --exclude-dir={node_modules,vendor,.git}

  # Hardcoded IPs (may expose infrastructure)
  grep -rE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" \
    --include="*.php" --include="*.js" --include="*.env" \
    --exclude-dir={node_modules,vendor,.git}

  # Private key headers
  grep -rE "BEGIN (RSA|EC|OPENSSH) PRIVATE KEY" --exclude-dir=.git
  ```

- [ ] **Use a dedicated secrets scanner** for a thorough check.

  ```bash
  # Gitleaks (scans git history, not just working tree)
  gitleaks detect --source . --verbose

  # Trufflehog (scans git history for high-entropy strings)
  trufflehog git file://. --only-verified
  ```

- [ ] **Verify `.gitignore` covers all secret files** before the first commit.

  ```gitignore
  .env
  .env.*
  !.env.example
  wp-config.php
  **/wp-salts.php
  *.pem
  *.key
  secrets/
  ```

- [ ] **Audit git history** for any previously committed secrets (they persist in history even after deletion).

  ```bash
  git log --all --full-history -- .env
  git log --all --full-history -- wp-config.php
  git log -p --all | grep -i "password\|secret\|token" | head -30
  ```

  If secrets are found in history, rotate them immediately and use `git filter-repo` to remove them.

- [ ] **Verify `.env.example` exists and contains only placeholder values** — this is what goes in version control.

  ```bash
  cat .env.example | grep -v "^#" | grep -v "^$"
  # Every value should be a placeholder like "changeme" or empty
  ```

- [ ] **Check that your CI/CD environment variables are not echoed in build logs.**

- [ ] **Audit credentials injected into the frontend by your backend.** Any server-side code that renders a JS global or JSON config block for client consumption must be audited line by line. A common pattern seen in real production applications:

  ```php
  // DANGEROUS — masterKey bypasses all ACLs on Parse Server
  echo "var API_CONFIG = " . json_encode([
      "parseServerConfig" => [
          "appId"     => $config["appId"],
          "masterKey" => $config["masterKey"],   // ← must never reach the client
          "parseUrl"  => $config["parseUrl"],
      ]
  ]);
  ```

  The masterKey (Parse Server), service role key (Supabase), admin SDK credential (Firebase), or any equivalent **server-only secret** must not appear in the rendered HTML or any API response that is sent to unauthenticated or low-privilege users. A single leaked masterKey gives full read/write/delete access to every object in the database, bypassing all per-object ACLs and Class-Level Permissions.

  What to check:

  - [ ] No `masterKey` / `serviceRoleKey` / admin SDK credential in any `<script>` tag or JSON config endpoint
  - [ ] Client-side SDKs receive only the **client key** or **anonymous key** — keys scoped to public read-only operations
  - [ ] BaaS Class-Level Permissions (CLP) are set so that a valid client key alone cannot enumerate or export sensitive classes (`_User`, `_Session`, patient records, etc.)
  - [ ] If your app currently exposes a masterKey to the client, treat it as fully compromised: rotate the key, audit the `_Session` table for active tokens that were issued while the key was exposed, and bulk-invalidate them

  ```bash
  # Quick check — does your rendered HTML contain the word "masterKey"?
  curl -s https://your-app.example.com/ | grep -i "masterKey\|serviceRoleKey\|adminKey"

  # Check all API config endpoints without authentication
  curl -s https://your-app.example.com/api/config | python3 -m json.tool | grep -i "key\|secret\|token"
  ```

- [ ] **Verify BaaS / backend-as-a-service access controls before go-live.** If your application uses Parse Server, Firebase, Supabase, Back4App, or a similar platform:

  - [ ] Class-Level Permissions (CLP) on sensitive classes are set to deny public `find` and `get` — verify via the dashboard or the schema API
  - [ ] Object-level ACLs are set on every record that should not be world-readable
  - [ ] The Parse `masterKey`, Supabase `service_role` key, or Firebase admin credential is stored only in server-side environment variables — never in client bundles, `localStorage`, or HTML

  ```bash
  # Parse Server: check CLP on the _User class (requires masterKey — run server-side only)
  curl -s -X GET "https://parse.example.com/parse/schemas/_User" \
    -H "X-Parse-Application-Id: YOUR_APP_ID" \
    -H "X-Parse-Master-Key: YOUR_MASTER_KEY" \
    | python3 -m json.tool | grep -A 20 '"classLevelPermissions"'
  # Expected: find/get/count should be false or restricted to authenticated users
  ```

---

## 4. Infrastructure Checklist

> Infrastructure issues cause silent failures that are hard to debug after deploy. Verify these before you push anything.

- [ ] **Firewall rules are correct and verified.**

  ```bash
  ufw status verbose
  # Only required ports open: 22 (or custom SSH), 80, 443
  ```

- [ ] **Docker containers are not directly exposing ports** that should only be accessible via Nginx.

  ```bash
  docker ps --format "table {{.Names}}\t{{.Ports}}"
  # Database should show 127.0.0.1:3306 or nothing — not 0.0.0.0:3306
  ```

- [ ] **SSL certificate is valid and covers all required domains.**

  ```bash
  openssl s_client -connect yourdomain.com:443 -servername yourdomain.com </dev/null 2>/dev/null \
    | openssl x509 -noout -dates -subject
  ```

- [ ] **SSL auto-renewal is configured and tested.**

  ```bash
  # Certbot dry run
  certbot renew --dry-run

  # Or check renewal timer
  systemctl status certbot.timer
  ```

  > **If using Cloudflare Authenticated Origin Pulls (`ssl_verify_client on`):** HTTP-01 ACME challenge may fail when certbot contacts your origin directly — nginx will reject the connection because it requires Cloudflare's client certificate. Use **DNS-01 challenge** instead, which validates via a DNS TXT record and never makes an HTTP connection to your server:
  >
  > ```bash
  > pip install certbot-dns-cloudflare
  >
  > # Create scoped API token: Zone → DNS → Edit (specific zone only)
  > # Save to /etc/letsencrypt/cloudflare.ini (chmod 600):
  > # dns_cloudflare_api_token = YOUR_SCOPED_TOKEN
  >
  > certbot certonly \
  >   --dns-cloudflare \
  >   --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
  >   -d yourdomain.com -d www.yourdomain.com
  > ```

- [ ] **DNS has propagated** for all required records.

  ```bash
  dig yourdomain.com +short
  dig www.yourdomain.com +short
  # Verify output matches your server IP
  ```

- [ ] **Health checks are configured** on containers and load balancer (if applicable).

- [ ] **Server time is synchronized** — skewed time causes TLS handshake failures and log confusion.

  ```bash
  timedatectl status
  # Should show "synchronized: yes"
  ```

- [ ] **Verify the correct Nginx config is loaded** (not a leftover test config).

  ```bash
  nginx -T | grep -E "server_name|listen|root"
  ```

---

## 5. Application Checklist

> These are application-layer issues that require code-level verification — your framework and server cannot automatically catch all of them.

- [ ] **Error pages do not leak stack traces, file paths, or database credentials.**

  ```bash
  # Trigger a 404
  curl -s https://yourdomain.com/this-page-does-not-exist-12345

  # Trigger a 500 (test endpoint or misconfiguration)
  # Verify the response contains only a user-friendly message
  ```

- [ ] **File upload validation is in place:**
  - Validate MIME type server-side (not just the client-supplied `Content-Type`)
  - Validate file extension against an allowlist
  - Store uploaded files outside the webroot or in a directory with PHP execution blocked
  - Limit file size

- [ ] **All user input is sanitized and validated.** Check forms, query parameters, REST API payloads, and file names.

- [ ] **CSRF protection is enabled** for all state-changing forms. Verify the token is checked server-side, not just rendered client-side.

  ```bash
  # Test: submit a form without the CSRF token
  # Should receive 403, not succeed
  ```

- [ ] **Rate limiting is applied** to sensitive endpoints:
  - Login
  - Password reset
  - API endpoints that trigger email sending or payment processing
  - File upload endpoints

- [ ] **Authentication is required** for all admin and internal endpoints — verify there is no `?admin=true` bypass or similar debug parameter.

- [ ] **Session cookies use `HttpOnly`, `Secure`, and `SameSite=Lax`** attributes.

- [ ] **The application does not expose a directory listing** for any public path.

  ```bash
  curl -s https://yourdomain.com/wp-content/uploads/ | grep -i "index of"
  # Should return nothing (or 403/404)
  ```

---

## 6. Docker Deployment Checklist

> Docker makes deployments reproducible, but also introduces its own failure modes. Run through these for every production deployment.

- [ ] **Do not use `:latest` tags.** Pin to specific image versions.

  ```yaml
  # Bad
  image: wordpress:latest

  # Good
  image: wordpress:X.Y.Z-phpA.B-fpm
  ```

  > **Why this matters:** `:latest` changes without notice. A routine `docker pull` can silently upgrade your PHP version, change default configs, or introduce a breaking change.

- [ ] **Health checks are defined** for every service that serves traffic.

  ```yaml
  healthcheck:
    test: ["CMD-SHELL", "mysqladmin ping -u root -p${MYSQL_ROOT_PASSWORD} || exit 1"]
    interval: 30s
    timeout: 10s
    retries: 3
    start_period: 60s
  ```

- [ ] **Restart policies are set** on all services.

  ```yaml
  restart: unless-stopped
  ```

- [ ] **No privileged containers** in production.

  ```yaml
  # These should NOT appear in production compose files:
  privileged: true
  cap_add:
    - SYS_ADMIN
  ```

  Verify:
  ```bash
  docker inspect CONTAINER_NAME | grep -i privileged
  # Should return: "Privileged": false
  ```

- [ ] **`no-new-privileges` is set** on all application containers.

  ```yaml
  security_opt:
    - no-new-privileges:true
  ```

- [ ] **Volumes containing data are identified** and backed up before deploy.

  ```bash
  docker volume ls
  # Know which volumes contain database files, uploads, and config
  ```

- [ ] **Separate networks are used** — application containers should not be on the same Docker network as unrelated services.

- [ ] **Database is not accessible from outside the Docker network.** Its port should bind to `127.0.0.1` only or not be published at all.

  ```yaml
  services:
    db:
      # No 'ports' key at all — Nginx/app reaches it via Docker network name
  ```

- [ ] **Environment variables with secrets are not baked into the image.** Use `.env` files or Docker secrets, and verify the image does not contain them.

  ```bash
  docker history IMAGE_NAME --no-trunc | grep -iE "password|secret|token"
  # Should return nothing
  ```

- [ ] **The deployment does not cause downtime.** Use rolling updates or a maintenance window with a visible maintenance page if needed.

---

## 7. Post-Deploy Verification

> After deployment, verify the system behaves correctly from the outside — as an attacker or a user would see it.

- [ ] **All critical blocked endpoints return 404 (not 200 or 403).**

  ```bash
  for endpoint in xmlrpc.php wp-cron.php wp-content/debug.log .git/config readme.html; do
      code=$(curl -s -o /dev/null -w "%{http_code}" "https://yourdomain.com/$endpoint")
      echo "$code  $endpoint"
  done
  # All should be 404
  ```

- [ ] **Security headers are present and correct.**

  ```bash
  curl -sI https://yourdomain.com | grep -iE \
    'strict-transport|x-frame|x-content-type|content-security|referrer|permissions'
  ```

- [ ] **SSL is rated A or A+** on SSLLabs.

  ```bash
  # Check via API
  curl -s "https://api.ssllabs.com/api/v3/analyze?host=yourdomain.com&fromCache=on&all=done" \
    | jq '.endpoints[0].grade'
  # Or visit: https://www.ssllabs.com/ssltest/analyze.html?d=yourdomain.com
  ```

- [ ] **WPScan finds no high-severity vulnerabilities.**

  ```bash
  wpscan --url https://yourdomain.com --enumerate vp --api-token YOUR_TOKEN
  ```

- [ ] **Nikto finds no obvious misconfiguration.**

  ```bash
  nikto -h https://yourdomain.com -C all
  ```

- [ ] **The site loads correctly** — spot-check key pages, forms, and user flows.

- [ ] **Check application logs for errors** immediately after deploy.

  ```bash
  docker logs WORDPRESS_CONTAINER --tail=100 --follow
  docker logs NGINX_CONTAINER --tail=100 --follow
  ```

- [ ] **Verify fail2ban jails are active.**

  ```bash
  fail2ban-client status
  fail2ban-client status nginx-wplogin
  fail2ban-client status sshd
  ```

- [ ] **Verify backups ran successfully** after the deploy (or trigger a manual backup).

---

## 8. Monitoring Setup

> Monitoring is only useful if it alerts someone and the alert is actionable. Set a minimum viable monitoring baseline before launch.

- [ ] **Uptime monitoring from an external service.** An on-server monitor cannot alert you if the server is down.

  Recommended free-tier options:
  - UptimeRobot (5-minute check intervals)
  - BetterUptime
  - Freshping

  Configure alerts for:
  - HTTPS response != 200
  - SSL certificate expiring within 14 days
  - Response time > 5 seconds

- [ ] **Disk space alerts.** A full disk silently kills your database.

  ```bash
  # Add to cron — alert when disk > 80% full
  df -h / | awk 'NR==2{if(substr($5,0,length($5)-1)+0 > 80) print "DISK ALERT: " $5 " on " ENVIRON["HOSTNAME"]}' \
    | mail -s "Disk Alert" admin@yourdomain.com
  ```

- [ ] **Error log alerting.** Know about PHP fatal errors and Nginx 5xx responses before your users do.

  ```bash
  # Simple: alert on 500 errors in Nginx log
  grep " 500 " /var/log/nginx/access.log | tail -5
  ```

- [ ] **Backup success verification.** Confirm that scheduled backups are completing and producing non-zero files.

  ```bash
  # Check last backup file age and size
  find /backups -name "*.sql*" -mtime -1 -size +100k
  # If empty, last night's backup didn't run or was empty
  ```

- [ ] **Container health check monitoring.** Know when a container enters `unhealthy` state.

  ```bash
  docker ps --filter health=unhealthy
  ```

- [ ] **Configure `MAILTO` in crontab** so cron failures go somewhere.

  ```bash
  crontab -e
  # Add at the top:
  MAILTO=admin@yourdomain.com
  ```

---

## 9. Rollback Plan

> You must know how to roll back before you deploy. Discovering your rollback procedure during an outage is too late.

- [ ] **Git rollback procedure is documented and tested.**

  ```bash
  # Roll back to the last known good commit
  git log --oneline -10  # Identify the target commit hash
  git checkout COMMIT_HASH -- .
  # OR revert the deploy commit
  git revert HEAD
  git push origin main
  # Trigger your deploy pipeline (or manually pull + restart on server)
  ```

- [ ] **Database restore procedure is documented and tested.**

  ```bash
  # Stop the application first to prevent writes during restore
  docker stop WORDPRESS_CONTAINER

  # Restore from backup
  docker exec -i DB_CONTAINER mysql -u root -p"$MYSQL_ROOT_PASSWORD" wordpress \
    < /backups/wp-db-YYYYMMDD.sql

  # Restart
  docker start WORDPRESS_CONTAINER
  ```

  > **Important:** Always restore to a test environment first to verify the backup is valid before touching production.

- [ ] **DNS failover plan exists** if your primary server becomes unreachable.

  Options:
  - Secondary server with the same content (database replication or periodic sync)
  - Static maintenance page hosted on S3/Cloudflare Pages
  - Low TTL on DNS records (set before deploying, not after an incident)

- [ ] **Rollback decision criteria is defined** — agree in advance on what conditions trigger a rollback (error rate > X%, critical feature broken, data integrity issue, etc.).

- [ ] **Communication plan** — who to notify and how if the site goes down for more than 5 minutes.

---

## 10. CI/CD Security

> Your deployment pipeline has access to your production server. A compromised CI/CD system is a direct path to production. These controls prevent your automation from becoming an attack vector.

### Repository Security

- [ ] **Enable branch protection on `main`** — require pull request reviews before merging, no direct pushes.

  On GitHub: Settings → Branches → Add branch protection rule for `main`:
  - Require pull request reviews before merging (1+ reviewer)
  - Require status checks to pass
  - Require branches to be up to date before merging
  - Do not allow bypassing (even for admins in high-security setups)

- [ ] **Enable GitHub secret scanning** — GitHub will alert you if credentials are accidentally committed.

  Settings → Code security and analysis → Secret scanning → Enable

- [ ] **Enable Dependabot** for automated dependency vulnerability alerts.

  Create `.github/dependabot.yml`:

  ```yaml
  version: 2
  updates:
    - package-ecosystem: "npm"
      directory: "/"
      schedule:
        interval: "weekly"
    - package-ecosystem: "composer"
      directory: "/"
      schedule:
        interval: "weekly"
    - package-ecosystem: "docker"
      directory: "/"
      schedule:
        interval: "weekly"
  ```

- [ ] **Use signed commits** for production deployments — provides a verifiable audit trail of who deployed what.

  ```bash
  git config --global commit.gpgsign true
  git config --global user.signingkey YOUR_GPG_KEY_ID
  ```

### Deploy Credentials

- [ ] **Use a dedicated deploy user** on the production server — not your personal SSH key. The deploy user should have minimal permissions: pull code, restart specific Docker services, nothing else.

  ```bash
  adduser deploy
  # No sudo for deploy user
  # Restricted to specific commands via sudoers if needed:
  echo "deploy ALL=(ALL) NOPASSWD: /usr/bin/docker compose -f /opt/app/docker-compose.yml pull, /usr/bin/docker compose -f /opt/app/docker-compose.yml up -d" >> /etc/sudoers.d/deploy
  ```

- [ ] **Store all secrets in GitHub Actions Secrets** — never in the repository, `.env` files in the repo, or CI/CD YAML directly.

  On GitHub: Settings → Secrets and variables → Actions → New repository secret

  Reference in workflows:
  ```yaml
  env:
    DEPLOY_KEY: ${{ secrets.DEPLOY_SSH_KEY }}
    SERVER_HOST: ${{ secrets.PROD_SERVER_IP }}
  ```

- [ ] **Rotate deploy keys every 6-12 months.** SSH keys do not expire — rotation is the only way to limit the blast radius if a key is silently compromised.

- [ ] **Check that CI logs do not echo secrets.** Add `set +x` before commands that use secrets in bash scripts.

  ```bash
  set +x
  echo "$SECRET" | some-command
  set -x
  ```

### Workflow Security

- [ ] **Pin GitHub Actions to specific commit SHAs** rather than tags (e.g. `uses: actions/checkout@v4` → `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`). Tags are mutable; SHAs are not.

  > **Why:** Supply chain attacks on GitHub Actions are real — an attacker who takes over a popular action and pushes a new version to `@v4` can execute arbitrary code in your CI environment. Pinning to a SHA is immune to this.

- [ ] **Use `CODEOWNERS`** to require security review on changes to sensitive files.

  Create `.github/CODEOWNERS`:
  ```
  # Deployment config requires review from the infrastructure owner
  docker-compose*.yml @YourOrg/infra-team
  .github/workflows/ @YourOrg/infra-team
  nginx/ @YourOrg/infra-team
  ```

---

## 11. DNS Security

> Your domain is the front door to everything. Domain hijacking or DNS poisoning redirects all your users to an attacker's server. These controls make your domain much harder to steal.

- [ ] **Enable registrar lock (domain lock) on your domain.** This prevents unauthorized domain transfers without going through a multi-step unlock process.

  Most registrars call this "domain lock" or "transfer lock" — enable it in your registrar dashboard. It is usually a single toggle.

- [ ] **Enable two-factor authentication on your domain registrar account.** A stolen registrar login is all that is needed for domain hijacking.

- [ ] **Enable WHOIS privacy** to prevent your contact details from being used in social engineering attacks against the registrar.

- [ ] **Set low TTL values before a planned migration** (e.g. change from 3600 to 300), then set them back to normal after the migration succeeds. Low TTL lets you roll back DNS changes quickly.

- [ ] **Add CAA (Certification Authority Authorization) DNS records** to specify which certificate authorities are allowed to issue SSL certificates for your domain. This prevents attackers from getting a certificate from a different CA even if they can influence DNS.

  ```
  # TXT record at yourdomain.com:
  0 issue "letsencrypt.org"
  0 issuewild ";"         ; disallow wildcard certs from anyone
  0 iodef "mailto:admin@yourdomain.com"   ; report unauthorized attempts
  ```

  Verify:
  ```bash
  dig CAA yourdomain.com
  ```

- [ ] **Monitor for certificate transparency logs** — every SSL certificate issued for your domain is logged publicly. Set up alerts at crt.sh or use a service like Cert Spotter to be notified if an unexpected certificate is issued for your domain.

  ```bash
  # Check current certificates for your domain
  curl -s "https://crt.sh/?q=yourdomain.com&output=json" | jq '.[].name_value' | sort -u
  ```

- [ ] **If using Cloudflare:** restrict your Cloudflare API token to the minimum required permissions — do not use a global API key in CI/CD scripts.

  Cloudflare Dashboard → My Profile → API Tokens → Create Token  
  Scope: Zone → DNS → Edit for specific zone only

- [ ] **Verify DNS propagation** after any changes before celebrating.

  ```bash
  # Check from multiple resolvers
  dig @8.8.8.8 yourdomain.com A    # Google DNS
  dig @1.1.1.1 yourdomain.com A    # Cloudflare DNS
  dig @9.9.9.9 yourdomain.com A    # Quad9 DNS
  ```

---

## 12. Security Scan Commands

> Keep this as a runbook. Run the full suite before launch, then on a monthly schedule or after significant changes.

```bash
# -----------------------------------------------------------------------
# 1. Port scan — check what's actually exposed on your server IP
# -----------------------------------------------------------------------
nmap -sV -p 1-65535 YOUR_SERVER_IP
# Expected open: 22 (or custom SSH), 80, 443 only

# -----------------------------------------------------------------------
# 2. WPScan — WordPress vulnerability scan
# -----------------------------------------------------------------------
wpscan --url https://yourdomain.com \
  --enumerate vp,vt,u,cb,dbe \
  --api-token YOUR_WPSCAN_TOKEN \
  --output wpscan-$(date +%Y%m%d).txt

# -----------------------------------------------------------------------
# 3. Nikto — generic web server misconfiguration check
# -----------------------------------------------------------------------
nikto -h https://yourdomain.com -C all -output nikto-$(date +%Y%m%d).txt

# -----------------------------------------------------------------------
# 4. HTTP security headers
# -----------------------------------------------------------------------
curl -sI https://yourdomain.com | grep -iE \
  'strict-transport|x-frame|x-content|content-security|referrer|permissions|x-xss'

# -----------------------------------------------------------------------
# 5. Verify blocked WordPress endpoints
# -----------------------------------------------------------------------
for path in \
  "xmlrpc.php" \
  "wp-cron.php" \
  "wp-admin/install.php" \
  "wp-admin/upgrade.php" \
  "wp-content/debug.log" \
  "readme.html" \
  "license.txt" \
  ".git/config" \
  "phpinfo.php" \
  "wp-config.php.bak"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://yourdomain.com/$path")
  printf "%-45s %s\n" "$path" "$code"
done

# -----------------------------------------------------------------------
# 6. REST API user enumeration check
# -----------------------------------------------------------------------
curl -s "https://yourdomain.com/wp-json/wp/v2/users" | python3 -m json.tool | head -20
# Should return 401 or empty array

# -----------------------------------------------------------------------
# 7. Author enumeration check
# -----------------------------------------------------------------------
curl -s -o /dev/null -w "%{http_code}" "https://yourdomain.com/?author=1"
# Should be 403 and not redirect to /author/username/

# -----------------------------------------------------------------------
# 8. SSL/TLS quality
# -----------------------------------------------------------------------
curl -s "https://api.ssllabs.com/api/v3/analyze?host=yourdomain.com&fromCache=on" \
  | jq '{grade: .endpoints[0].grade, ip: .endpoints[0].ipAddress}'

# -----------------------------------------------------------------------
# 9. Fail2ban status
# -----------------------------------------------------------------------
fail2ban-client status
for jail in sshd nginx-wplogin; do
  echo "=== $jail ==="
  fail2ban-client status $jail
done

# -----------------------------------------------------------------------
# 10. Docker security audit
# -----------------------------------------------------------------------
# Check for privileged containers
docker ps -q | xargs docker inspect --format \
  '{{.Name}}: Privileged={{.HostConfig.Privileged}} Caps={{.HostConfig.CapAdd}}'

# Check port bindings (nothing should bind to 0.0.0.0 except 80/443)
docker ps --format "{{.Names}}: {{.Ports}}"

# Check for containers running as root
docker ps -q | xargs -I{} docker exec {} id 2>/dev/null

# -----------------------------------------------------------------------
# 11. Check for world-writable files
# -----------------------------------------------------------------------
find /var/www/html -perm -0002 -type f 2>/dev/null

# -----------------------------------------------------------------------
# 12. Check recently modified PHP files (compromise indicator)
# -----------------------------------------------------------------------
find /var/www/html -name "*.php" -mtime -7 -type f | sort
```

---

## 13. Common Mistakes

> These are the most frequently observed mistakes in production web deployments — along with how to detect each one.

| Mistake | What Goes Wrong | How to Detect |
|---|---|---|
| Committing `.env` to git | All credentials exposed in repository history | `git log --all --full-history -- .env` — any result means it was committed |
| Using `:latest` Docker tags | Surprise upgrades break the app on next `docker pull` | `docker-compose config | grep image` — any `:latest` is a risk |
| Database port bound to `0.0.0.0` | Database accessible from the internet | `docker ps --format "{{.Ports}}"` — look for `0.0.0.0:3306` |
| `WP_DEBUG = true` in production | Stack traces leak to all visitors | `curl -s https://yourdomain.com/wp-config.php` — should 404 or not expose this |
| Salts not rotated from defaults | Attacker can forge authentication cookies | `curl -s https://api.wordpress.org/secret-key/1.1/salt/` — if your salts match any default, rotate |
| `xmlrpc.php` not blocked | Amplified brute-force attacks, DoS | `curl -s -o/dev/null -w "%{http_code}" https://yourdomain.com/xmlrpc.php` — should be 404 |
| `debug.log` in webroot | Credentials and paths exposed publicly | `curl -s https://yourdomain.com/wp-content/debug.log` — should be 404 |
| PHP execution allowed in uploads | Uploaded PHP shell is executable | `curl -s https://yourdomain.com/wp-content/uploads/test.php` — should 404 |
| UFW enabled but Docker bypassing it | Containers exposed despite firewall rules | `nmap -p 1-65535 YOUR_SERVER_IP` — any port not in your allowlist is a bypass |
| Same secrets across environments | Dev breach = prod breach | Compare `.env.local` and `.env.production` — no shared passwords or tokens |
| No offsite backup | Server loss = data loss | Check last backup file age and verify it exists somewhere other than the server |
| Fail2ban backend = systemd with file logpath | Jail silently never fires | `fail2ban-client status sshd` — if `Currently banned: 0` after known attack attempts, check backend |
| `?author=` redirect not blocked | Usernames enumerated passively | `curl -v "https://yourdomain.com/?author=1" 2>&1 | grep -i location` — should not reveal username |
| Version numbers in asset URLs | Plugin/WP version fingerprinted by scanners | `curl -s https://yourdomain.com | grep "ver="` — should return nothing |
| No rate limiting on login | Unlimited brute-force attempts | `ab -n 100 -c 10 https://yourdomain.com/wp-login.php` — should trigger 429 or bans after a few attempts |
| Containers using `privileged: true` | Container escape to host root | `docker inspect NAME | grep Privileged` — should be `false` |
| No health checks defined | Crashed container not restarted | `docker ps --filter health=unhealthy` — test your health check endpoint manually |

---

*Last reviewed: 2025 | Applies to: Docker Compose, Nginx, WordPress, Debian-based Linux*
