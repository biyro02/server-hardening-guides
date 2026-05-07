# Security Audit Automation

**Tools and scripts for recurring server security checks**

> Security posture degrades over time — packages go unpatched, configurations drift, new vulnerabilities are discovered in dependencies. Automated audits catch this drift before attackers do. This guide covers the tools worth running, how to set them up, and how to interpret results.

---

## Table of Contents

1. [Lynis — System Audit](#1-lynis--system-audit)
2. [rkhunter — Rootkit Detection](#2-rkhunter--rootkit-detection)
3. [AIDE — File Integrity Monitoring](#3-aide--file-integrity-monitoring)
4. [auditd — Kernel Audit Trail](#4-auditd--kernel-audit-trail)
5. [CrowdSec — Collaborative Threat Intelligence](#5-crowdsec--collaborative-threat-intelligence)
6. [WPScan — Scheduled WordPress Scans](#6-wpscan--scheduled-wordpress-scans)
7. [Automated Reporting Setup](#7-automated-reporting-setup)
8. [Manual Audit Runbook](#8-manual-audit-runbook)
9. [Operational Drift — Security Posture Over Time](#9-operational-drift--security-posture-over-time)

---

## 1. Lynis — System Audit

Lynis is the most practical general-purpose Linux security audit tool. It checks hundreds of settings, prints findings in a single report, and gives a hardening index score. Run it quarterly or after major changes.

### Installation

```bash
# From the official repo (always up-to-date)
curl -fsSL https://packages.cisofy.com/keys/cisofy-software-public.key | gpg --dearmor -o /usr/share/keyrings/cisofy.gpg
echo "deb [signed-by=/usr/share/keyrings/cisofy-software-public.key] https://packages.cisofy.com/community/lynis/deb/ stable main" \
  | tee /etc/apt/sources.list.d/cisofy-lynis.list
apt update && apt install lynis -y
```

### Run an audit

```bash
lynis audit system
```

The report is saved to `/var/log/lynis.log` and the report summary to `/var/log/lynis-report.dat`.

### Interpreting results

Lynis scores your system from 0–100 (higher is better). Common starting scores on a fresh Ubuntu VPS: 55–65. After applying the hardening guides in this repo: 75–85+. A score below 60 means significant work is needed.

Focus on `[WARNING]` and `[SUGGESTION]` items that Lynis marks as high priority. Not every suggestion is appropriate for every server — Lynis is a checklist, not a mandate.

### Automate quarterly audits

```bash
# /etc/cron.d/lynis-audit
0 4 1 */3 * root lynis audit system --quiet --cronjob >> /var/log/lynis-cron.log 2>&1
```

---

## 2. rkhunter — Rootkit Detection

rkhunter scans for rootkits, backdoors, and local exploits. It checks file permissions, binary hashes, known rootkit signatures, and suspicious network ports.

### Installation

```bash
apt install rkhunter -y
```

### Initial setup

```bash
# Build a baseline of known-good file properties (run on a clean system)
rkhunter --propupd

# Update the signature database
rkhunter --update
```

### Run a scan

```bash
rkhunter --check --skip-keypress 2>&1 | tee /var/log/rkhunter-scan.log
```

### Interpreting output

- `[OK]` — passed
- `[Warning]` — investigate; may be a false positive
- `[Unknown]` — rkhunter cannot determine state; verify manually

Common false positives:
- Package manager updates change binary hashes — run `rkhunter --propupd` after `apt upgrade`
- Non-default packages in `/usr/local/bin`

After `apt upgrade`, always update the baseline:

```bash
apt upgrade -y && rkhunter --propupd
```

### Automate weekly scans

```bash
# /etc/cron.weekly/rkhunter
#!/bin/bash
rkhunter --update --quiet
rkhunter --check --skip-keypress --report-warnings-only \
  --logfile /var/log/rkhunter-$(date +%Y%m%d).log \
  --mail-on-warning admin@yourdomain.com 2>&1
```

```bash
chmod +x /etc/cron.weekly/rkhunter
```

---

## 3. AIDE — File Integrity Monitoring

AIDE (Advanced Intrusion Detection Environment) detects unauthorized changes to files. It creates a cryptographic database of file hashes, then compares the current state against it. Any modification — a webshell being planted, a binary being replaced, a config being altered — triggers an alert.

> **Use case:** AIDE does not prevent attacks, it detects them. A change to `/usr/bin/sudo` that rkhunter misses will be caught by AIDE.

### Installation

```bash
apt install aide -y
```

### Configuration

Edit `/etc/aide/aide.conf` to define what to monitor. The defaults are reasonable. Key additions for a web server:

```
# Monitor web application files for modifications
/var/www/html/wp-config.php Full
/var/www/html/wp-includes Full
/opt/myapp CONTENT+md5+sha256

# Monitor Nginx config
/etc/nginx Full

# Monitor fail2ban config
/etc/fail2ban Full

# Exclude upload directories (they legitimately change)
!/var/www/html/wp-content/uploads
!/var/www/html/wp-content/cache
```

### Initialize the database (run on a known-clean system)

```bash
aideinit
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

### Run a check

```bash
aide --check
```

### Automate daily checks

```bash
# /etc/cron.d/aide-check
30 5 * * * root /usr/bin/aide --check --config=/etc/aide/aide.conf \
  >> /var/log/aide/aide-daily.log 2>&1
```

### Update the database after intentional changes

After a planned deployment or package upgrade:

```bash
aide --update
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

> **Store the AIDE database off-server.** An attacker with root access can modify both the files and the AIDE database — defeating detection. Automate a daily copy to your backup machine:
> ```bash
> # /etc/cron.d/aide-offsite
> 35 5 * * * root rsync -az /var/lib/aide/aide.db \
>   backup-user@BACKUP_HOST:/opt/aide-db/aide.db.$(date +\%Y\%m\%d) 2>&1 | logger -t aide-offsite
> ```
> Keep 30 days of daily snapshots on the backup machine — if you need to investigate a breach, you can compare the current database against a snapshot from before the breach date.

> **Docker volume path note:** AIDE monitors host filesystem paths. If WordPress uses Docker named volumes, the paths configured above (e.g. `/var/www/html/wp-config.php`, `/var/www/html/wp-includes`) may not exist on the host or may point to overlay filesystem layers that AIDE cannot traverse meaningfully. Find the actual host mount path: `docker inspect VOLUME_NAME | grep Mountpoint`. Paths typically look like `/var/lib/docker/volumes/appname_wordpress/_data`. Monitor those paths in `aide.conf` instead. Alternatively, run AIDE inside the container as part of a security scan script.

---

## 4. auditd — Kernel Audit Trail

auditd logs security-relevant events at the kernel level: file access, syscalls, privilege escalation attempts, network connections. It is harder to tamper with than application-level logs (a rootkit can hide from `ps`, but kernel audit events are harder to intercept).

### Installation

```bash
apt install auditd audispd-plugins -y
systemctl enable auditd
systemctl start auditd
```

### Key rules to add

Create `/etc/audit/rules.d/hardening.rules`:

```bash
# Deletions and attribute changes (potential attacker cleanup)
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# Modification of critical config files
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege-escalation
-w /etc/ssh/sshd_config -p wa -k ssh-config

# Privilege escalation commands
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -k privilege-escalation
-a always,exit -F arch=b64 -S execve -F path=/bin/su -k privilege-escalation

# Network connections from suspicious locations
-a always,exit -F arch=b64 -S connect -k network-connection

# File creation in /tmp and /dev/shm (staging area for malware)
-w /tmp -p wa -k staging
-w /dev/shm -p wa -k staging

# Web application directory monitoring
-w /var/www/html/wp-content/uploads -p wa -k webshell-upload
-w /var/www/html/wp-config.php -p rwa -k wp-config

# Cron modification
-w /var/spool/cron -p wa -k cron-modification
-w /etc/cron.d -p wa -k cron-modification
```

Apply the rules:

```bash
augenrules --load
systemctl restart auditd
```

> **Docker volume path note:** auditd watches host filesystem paths. If WordPress runs inside a Docker container with a named volume, `/var/www/html` inside the container is NOT the same path on the host. Rules targeting `/var/www/html/wp-content/uploads` and `/var/www/html/wp-config.php` will be silently ignored for Docker-named-volume setups. To find the real host path: `docker inspect VOLUME_NAME | grep Mountpoint` — it will be something like `/var/lib/docker/volumes/appname_wp-content/_data`. Update the `-w` paths in the rules above to the actual volume mount path.

### Log rotation

Configure auditd's own rotation in `/etc/audit/auditd.conf` — auditd manages its own log files independently of logrotate. Without this, `/var/log/audit/audit.log` grows unbounded and will eventually fill the disk, at which point auditd stops logging new events:

```ini
max_log_file = 100        # MB per log file
max_log_file_action = ROTATE
num_logs = 10             # keep 10 rotated files = max 1GB
space_left = 75           # MB free before warning
space_left_action = SYSLOG
admin_space_left = 50
admin_space_left_action = SUSPEND  # stop logging rather than crash the system
```

Reload after changing:

```bash
systemctl reload auditd
```

### Querying audit logs

```bash
# Recent privilege escalation attempts
ausearch -k privilege-escalation --start recent

# Files modified in /tmp
ausearch -k staging --start today

# All web config changes
ausearch -k wp-config --start recent

# Failed sudo attempts
ausearch -m USER_AUTH -sv no --start today

# Summary of audit events
aureport --summary --start today
```

---

## 5. CrowdSec + Cloudflare — Automated Threat Response

CrowdSec detects attacks by reading logs and matching patterns from community-contributed scenarios. When it identifies an attacker IP, a **bouncer** acts on that decision. With the Cloudflare bouncer, the ban is pushed to Cloudflare's edge — the attacker is blocked before the request even reaches your server.

**What this gives you:**
- Community blocklist: IPs that attacked other CrowdSec servers are pre-banned on yours
- Real-time detection of brute force, scanning, WordPress exploit attempts
- Cloudflare-level blocks (no server load from banned IPs at all)
- Stays effective even during high-volume attacks that would overwhelm fail2ban

> **Relationship with fail2ban:** Run both. CrowdSec covers community threat intelligence and Cloudflare-level blocking; fail2ban handles local UFW bans for network-level threats. They watch the same logs but act on different layers.

### Architecture

```
nginx access.log → CrowdSec agent → decision (ban IP)
                                  → CF bouncer → Cloudflare API → IP blocked at edge
                                  → (optional) iptables bouncer → UFW ban on server
```

### Option A: Docker Compose (recommended for containerized stacks)

CrowdSec reads nginx logs via a shared host volume. No Docker socket access required.

**Step 1: Configure nginx to write logs to a file**

Nginx in Docker logs to stdout by default. Add a log-format config file and enable file-based access logging:

```nginx
# nginx/log-format.conf (mounted at /etc/nginx/conf.d/00-log-format.conf)
# log_format must be in http context — a separate conf file loaded before the server block
log_format crowdsec_real '$http_x_real_ip - $remote_user [$time_local] '
                         '"$request" $status $body_bytes_sent '
                         '"$http_referer" "$http_user_agent"';
```

In the nginx server block (`nginx.conf`):
```nginx
access_log /var/log/nginx/access.log crowdsec_real;
```

> **Why `$http_x_real_ip` instead of `$remote_addr`?** Behind a proxy (Cloudflare → host nginx → container nginx), `$remote_addr` is the proxy IP, not the attacker's. The real client IP arrives in the `X-Real-IP` header set by the upstream proxy. CrowdSec must see the real IP to ban the right address.

**Step 2: Add CrowdSec and Cloudflare bouncer to `docker-compose.server.yml`**

```yaml
  nginx:
    # ... existing config ...
    volumes:
      - /path/to/nginx/log-format.conf:/etc/nginx/conf.d/00-log-format.conf:ro
      - /path/to/nginx/nginx.conf:/etc/nginx/conf.d/default.conf:ro
      # ... other volumes ...
      - /opt/myapp/logs/nginx:/var/log/nginx  # shared with CrowdSec

  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: myapp_crowdsec
    restart: unless-stopped
    environment:
      COLLECTIONS: "crowdsecurity/nginx crowdsecurity/wordpress crowdsecurity/linux"
    volumes:
      - crowdsec_config:/etc/crowdsec
      - crowdsec_data:/var/lib/crowdsec/data
      - /path/to/crowdsec/acquis.yaml:/etc/crowdsec/acquis.d/nginx.yaml:ro
      - /opt/myapp/logs/nginx:/var/log/nginx:ro  # read-only
    networks:
      - app-network

  cf-bouncer:
    image: crowdsecurity/cloudflare-bouncer:latest
    container_name: myapp_cf_bouncer
    restart: unless-stopped
    volumes:
      - /path/to/crowdsec/cf-bouncer.yaml:/etc/crowdsec/bouncers/crowdsec-cloudflare-bouncer.yaml:ro
    depends_on:
      - crowdsec
    networks:
      - app-network

volumes:
  crowdsec_config:
  crowdsec_data:
```

**Step 3: CrowdSec acquisition config**

Create `crowdsec/acquis.yaml`:

```yaml
filenames:
  - /var/log/nginx/access.log
labels:
  type: nginx
```

**Step 4: First-time bouncer key generation**

The CF bouncer needs an API key issued by CrowdSec. This is a one-time step:

```bash
# Start CrowdSec first (without the bouncer)
docker compose up -d crowdsec
sleep 15

# Generate bouncer key
docker exec myapp_crowdsec cscli bouncers add cloudflare-bouncer -o raw
# → save this key for the cf-bouncer.yaml
```

**Step 5: Cloudflare bouncer config**

Create `crowdsec/cf-bouncer.yaml` (keep out of git — contains API keys):

```yaml
crowdsec_config:
  lapi_url: http://crowdsec:8080
  lapi_key: YOUR_BOUNCER_KEY_FROM_CSCLI

cloudflare_config:
  accounts:
    - id: YOUR_CF_ACCOUNT_ID
      zones:
        - zone_id: YOUR_CF_ZONE_ID
          token: YOUR_CF_API_TOKEN
          # Token permissions: Zone → Firewall Services → Edit
          #                    Zone → Zone Settings → Read
          actions:
            - block
          default_action: block

update_frequency: 10s
log_level: info
log_mode: stdout
```

```bash
# Start the bouncer
docker compose up -d cf-bouncer
```

### Option B: Host installation (non-Docker setups)

```bash
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
apt install crowdsec -y

cscli collections install crowdsecurity/nginx
cscli collections install crowdsecurity/wordpress
cscli collections install crowdsecurity/linux

# Install Cloudflare bouncer
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
apt install crowdsec-cloudflare-bouncer -y
```

### Verify CrowdSec is working

```bash
# Check active decisions (currently banned IPs)
docker exec myapp_crowdsec cscli decisions list

# Check recent alerts (triggered scenarios)
docker exec myapp_crowdsec cscli alerts list

# Check metrics (log lines parsed, scenarios triggered)
docker exec myapp_crowdsec cscli metrics

# Verify bouncer is connected
docker exec myapp_crowdsec cscli bouncers list
```

### Dashboard (optional)

Register at app.crowdsec.net and enroll your CrowdSec instance for a web UI showing all alerts, decisions, and metrics.

```bash
docker exec myapp_crowdsec cscli console enroll YOUR_ENROLLMENT_KEY
```

### Harden the Cloudflare API token file

The `cf-bouncer.yaml` file contains your Cloudflare API token in plaintext on disk. An attacker who achieves file-read access post-compromise can steal the token and use it to modify your Cloudflare zone.

```bash
chmod 600 /path/to/crowdsec/cf-bouncer.yaml
chown root:root /path/to/crowdsec/cf-bouncer.yaml
```

Additionally, in the Cloudflare Dashboard, **restrict the API token to your server's IP address:** My Profile → API Tokens → Edit token → **Client IP Address Filtering** → Add your VPS IP. This limits the blast radius if the token leaks: it will only work from your server, not from an attacker's machine.

Rotate the token quarterly.

### CrowdSec bans and Cloudflare bypass interaction

CrowdSec's Cloudflare bouncer pushes banned IPs as block rules to **your** Cloudflare zone. This means banned IPs are blocked only for traffic routed through your zone's Cloudflare proxy.

If an attacker bypasses Cloudflare and connects directly to your origin IP (via IP discovery + their own Cloudflare account or a direct HTTP request that passes UFW because it originates from a Cloudflare IP range), CrowdSec bans will not protect you — they only apply at the CF edge of your zone.

**This is why the X-Origin-Verify mechanism in `cloudflare-hardening.md §1` is load-bearing for CrowdSec to be effective.** Without it, an attacker who finds your origin IP bypasses both your WAF rules and your CrowdSec bans simultaneously.

---

## 6. WPScan — Scheduled WordPress Scans

WPScan checks for known CVEs in WordPress core, plugins, and themes. Schedule it weekly. Get a free API token at wpscan.com (25 free API calls per day is enough for weekly scans).

### Installation

```bash
# If running as a Docker container (avoids Ruby dependency management):
alias wpscan='docker run --rm wpscanteam/wpscan'

# Or install as a gem:
gem install wpscan
```

### Weekly scan script

Create `/usr/local/bin/wpscan-report.sh`:

```bash
#!/usr/bin/env bash
SITE="https://yourdomain.com"
TOKEN="YOUR_WPSCAN_API_TOKEN"
REPORT_DIR="/var/log/wpscan"
REPORT_FILE="$REPORT_DIR/wpscan-$(date +%Y%m%d).json"
ALERT_EMAIL="admin@yourdomain.com"

mkdir -p "$REPORT_DIR"

docker run --rm wpscanteam/wpscan \
  --url "$SITE" \
  --api-token "$TOKEN" \
  --enumerate vp,vt,u \
  --format json \
  --output "$REPORT_FILE" 2>/dev/null

# Extract high/critical findings and email if any found
HIGH=$(jq -r '.vulnerabilities[] | select(.cvss.score >= 7) | .title' "$REPORT_FILE" 2>/dev/null)

if [ -n "$HIGH" ]; then
  echo "WPScan found high/critical vulnerabilities on $SITE:" | \
    mail -s "WPScan Alert: $(date +%Y-%m-%d)" -a "From: server@$(hostname)" \
    "$ALERT_EMAIL" <<< "$HIGH"
fi
```

```bash
chmod +x /usr/local/bin/wpscan-report.sh

# Schedule weekly on Monday at 06:00
echo "0 6 * * 1 root /usr/local/bin/wpscan-report.sh" > /etc/cron.d/wpscan-weekly
```

---

## 7. Automated Reporting Setup

Pull the individual tools together into a weekly security digest email.

Create `/usr/local/bin/security-digest.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

ALERT_EMAIL="admin@yourdomain.com"
HOSTNAME=$(hostname)
DATE=$(date +%Y-%m-%d)

report() {
  echo ""
  echo "=== $1 ==="
  eval "$2" 2>/dev/null || echo "(error running check)"
}

BODY="Security Digest: $HOSTNAME — $DATE"

BODY+=$(report "Disk Usage" "df -h / | tail -1")
BODY+=$(report "Failed SSH Logins (last 24h)" "grep 'Failed password' /var/log/auth.log | grep -c '' || echo 0")
BODY+=$(report "fail2ban Bans (last 24h)" "fail2ban-client status | grep -A2 'Jail list'")
BODY+=$(report "Docker Container Status" "docker ps --format 'table {{.Names}}\t{{.Status}}'")
BODY+=$(report "Packages Needing Security Update" "apt list --upgradable 2>/dev/null | grep -i security | head -10 || echo 'None'")
BODY+=$(report "Recently Modified PHP Files (last 7d)" "find /var/www/html -name '*.php' -mtime -7 -type f 2>/dev/null | head -10 || echo 'None'")
BODY+=$(report "Lynis Hardening Score" "grep 'Hardening index' /var/log/lynis.log 2>/dev/null | tail -1 || echo 'Run lynis to get score'")
BODY+=$(report "rkhunter Warnings" "grep Warning /var/log/rkhunter.log 2>/dev/null | tail -5 || echo 'None'")
BODY+=$(report "AIDE Changes" "aide --check 2>&1 | grep -E 'changed|added|removed' | head -10 || echo 'No changes'")

echo "$BODY" | mail -s "Security Digest: $HOSTNAME $DATE" "$ALERT_EMAIL"
```

```bash
chmod +x /usr/local/bin/security-digest.sh

# Every Monday at 08:00
echo "0 8 * * 1 root /usr/local/bin/security-digest.sh" > /etc/cron.d/security-digest
```

> **Email prerequisite:** This requires a working mail setup on the server. Install `mailutils` (`apt install mailutils`) and configure an SMTP relay, or use a service like Mailgun/SendGrid via `msmtp`.

---

## 8. Manual Audit Runbook

Run the full suite manually before major deployments, after incidents, and monthly.

```bash
#!/usr/bin/env bash
# Full manual security audit — run as root
# Estimated time: 15-20 minutes

echo "=== $(date) Security Audit: $(hostname) ==="
echo ""

echo "--- 1. System info ---"
uname -r
cat /etc/os-release | grep PRETTY_NAME

echo "--- 2. Pending security updates ---"
apt list --upgradable 2>/dev/null | grep -i security

echo "--- 3. Listening ports ---"
ss -tlnp

echo "--- 4. Active fail2ban jails ---"
fail2ban-client status

echo "--- 5. Docker containers ---"
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"

echo "--- 6. Docker port bindings (verify no 0.0.0.0 exposure) ---"
docker ps --format "{{.Names}}: {{.Ports}}"

echo "--- 7. UFW status ---"
ufw status verbose

echo "--- 8. Privileged containers (should be empty) ---"
docker ps -q | xargs docker inspect --format '{{.Name}}: Privileged={{.HostConfig.Privileged}}' 2>/dev/null

echo "--- 9. SSH authorized keys (check for unfamiliar keys) ---"
find /home /root -name "authorized_keys" 2>/dev/null -exec echo "== {} ==" \; -exec cat {} \;

echo "--- 10. Recently modified PHP files ---"
find /var/www -name "*.php" -mtime -7 -type f 2>/dev/null

echo "--- 11. PHP files in uploads (should be empty) ---"
find /var/www/html/wp-content/uploads -name "*.php" 2>/dev/null || echo "None"

echo "--- 12. Lynis hardening score ---"
grep "Hardening index" /var/log/lynis.log 2>/dev/null | tail -1 || echo "Run: lynis audit system"

echo "--- 13. Last backup date ---"
ls -lt /opt/myapp/backups/daily/ 2>/dev/null | head -3

echo "--- 14. Disk usage ---"
df -h /

echo "=== Audit complete ==="
```

Save as `/usr/local/bin/security-audit.sh`, `chmod +x`, and run when needed.

---

## 9. Operational Drift — Security Posture Over Time

> Security is not a state, it is a process. Most small-team servers are well-hardened on day one and progressively less so over the following months. This section names the specific ways that drift happens and what to check.

A server hardened today will have measurably weaker security in 6–12 months under normal maintenance patterns. The following checklist is designed for a **quarterly review** — 2-3 hours per quarter is enough to catch most drift before it becomes a liability.

### Cloudflare IP range drift

Cloudflare periodically adds new IP ranges to `https://www.cloudflare.com/ips-v4` and `https://www.cloudflare.com/ips-v6`. UFW rules that allowlist Cloudflare IPs and nginx `set_real_ip_from` blocks become stale when new ranges are added.

```bash
# Check current CF IPs vs your nginx config quarterly
curl -s https://www.cloudflare.com/ips-v4
# Compare against set_real_ip_from blocks in your nginx CF config
```

Automate the UFW update (nginx requires a manual reload after):

```bash
# /etc/cron.monthly/update-cf-ips
#!/bin/bash
ufw --force reset
# Re-apply all your standard rules, then:
for IP in $(curl -s https://www.cloudflare.com/ips-v4); do ufw allow from $IP to any port 80,443 proto tcp; done
for IP in $(curl -s https://www.cloudflare.com/ips-v6); do ufw allow from $IP to any port 80,443 proto tcp; done
ufw enable
```

### Docker image version lag

`docker compose pull` fetches newer tags within your pinned minor version (e.g. `wordpress:6.7-php8.3-fpm`). After 3+ months, running `docker images` and checking the `Created` date tells you how stale your images are.

```bash
docker images --format "table {{.Repository}}:{{.Tag}}\t{{.CreatedSince}}"
docker compose pull && docker compose up -d  # pull and restart with latest patch
```

### Plugin update fatigue

The most common WordPress breach pattern is not a sophisticated exploit — it is a vulnerable plugin that was not updated because "it still works." Check:

```bash
docker exec --user www-data WP_CONTAINER wp plugin list --update=available --format=table
```

If you have more than 2-3 outstanding updates, the plugins are not being maintained. Either automate updates or reduce the plugin count.

### fail2ban jail health

fail2ban jails can silently stop working after OS updates, log rotation changes, or Docker restarts. Quarterly check:

```bash
fail2ban-client status               # all jails
fail2ban-client status nginx-wplogin # specific jail — check "Currently banned"
grep "Ban\|Unban" /var/log/fail2ban.log | tail -20  # recent activity
```

If "Currently banned" is always zero and you have a public-facing site, the jail is likely broken.

### Backup restore drill

Run a partial restore drill quarterly. At minimum:

```bash
restic snapshots --repo YOUR_REPO | tail -5     # list recent snapshots
restic restore SNAPSHOT_ID --target /tmp/restore-test --include "db*.sql.gz"
gzip -t /tmp/restore-test/*.sql.gz && echo "OK"  # verify integrity
rm -rf /tmp/restore-test
```

A backup that has never been successfully restored is not a backup. The first time you discover the passphrase is wrong or the snapshot is corrupted should not be during a real incident.

### Certbot renewal health

```bash
certbot certificates
# Check expiry dates — if any cert expires in < 30 days, renewal is broken
systemctl status certbot.timer
```

### CrowdSec scenario updates

```bash
docker exec CROWDSEC_CONTAINER cscli hub update
docker exec CROWDSEC_CONTAINER cscli hub upgrade
```

CrowdSec's threat intelligence (scenario files) should be updated regularly. Stale scenarios miss new attack patterns.

---

*Last reviewed: 2025 | Applies to: Debian-based Linux, Lynis, AIDE*
