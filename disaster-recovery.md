# Disaster Recovery

**Restoring service after data loss, server failure, or ransomware**

> This guide assumes you have followed the backup strategy in `linux-server-hardening.md §10`. If you do not have working offsite backups before a disaster, recovery options are limited. Read this guide before you need it.

---

## Table of Contents

1. [Scenario Matrix](#1-scenario-matrix)
2. [Pre-Disaster Requirements](#2-pre-disaster-requirements)
3. [Scenario Playbooks](#3-scenario-playbooks)
   - [3a. Accidental File or Database Deletion](#3a-accidental-file-or-database-deletion)
   - [3b. Corrupted WordPress Database](#3b-corrupted-wordpress-database)
   - [3c. Failed Deployment — Site Broken](#3c-failed-deployment--site-broken)
   - [3d. Full Server Rebuild After Loss](#3d-full-server-rebuild-after-loss)
   - [3e. Ransomware — Data Encrypted on Server](#3e-ransomware--data-encrypted-on-server)
   - [3f. Domain or DNS Hijacking](#3f-domain-or-dns-hijacking)
   - [3g. Cloudflare Account Compromise](#3g-cloudflare-account-compromise)
   - [3h. Database Password Lost](#3h-database-password-lost)
4. [Backup Verification Drill](#4-backup-verification-drill)
5. [Recovery Time Estimates](#5-recovery-time-estimates)

---

## 1. Scenario Matrix

| Scenario | Data at Risk | Estimated Recovery | Section |
|---|---|---|---|
| Accidental file or DB deletion | Hours of data | 30–60 min | 3a |
| Corrupted WordPress database | Current DB state | 20–40 min | 3b |
| Failed deployment, site down | Nothing (code rollback) | 10–20 min | 3c |
| VPS destroyed / provider failure | Everything since last backup | 2–4 hours | 3d |
| Ransomware (server compromised) | Everything since last clean snapshot | 3–6 hours | 3e |
| Domain / DNS hijacking | Site unavailable (data intact) | 1–48 hours | 3f |
| Cloudflare account compromised | Traffic rerouted, certs at risk | 30 min | 3g |
| Database password lost | DB inaccessible | 20 min | 3h |

> **RTO** (Recovery Time Objective) = how long until service is restored.  
> **RPO** (Recovery Point Objective) = how much data can you afford to lose.  
> With daily backups your worst-case RPO is ~24 hours. With hourly snapshots it is ~1 hour.

---

## 2. Pre-Disaster Requirements

These must exist **before** any disaster. Verify quarterly.

### Backups

- [ ] Offsite encrypted restic repository (not on the production VPS)
- [ ] At minimum: daily DB dump + uploads snapshot
- [ ] Backup passphrase stored in password manager, **not** on the server
- [ ] Backup passphrase tested: confirm you can actually decrypt a snapshot

```bash
# Verify passphrase and repo integrity
restic -r YOUR_REPO check
restic -r YOUR_REPO snapshots | tail -5
```

### Credentials

Write these down in your password manager — not in a file on the server:

- [ ] VPS provider login (email + 2FA backup codes)
- [ ] Domain registrar login (email + 2FA backup codes)
- [ ] Cloudflare account login (email + 2FA backup codes)
- [ ] SSH key (private key backed up off-server)
- [ ] Database root password
- [ ] WordPress admin password
- [ ] Restic repository passphrase
- [ ] `.env` file contents (or a copy in password manager)

### Recovery documentation

- [ ] You know which VPS region / datacenter image to use
- [ ] You have the `docker-compose.yml` in version control (not only on the server)
- [ ] You have the `nginx.conf` in version control
- [ ] You know how to apply the hardening configs from scratch (or have an IaC script)

---

## 3. Scenario Playbooks

---

### 3a. Accidental File or Database Deletion

**Situation:** You deleted a file, a table, or ran the wrong SQL command. The server is running normally.

**Step 1 — Stop further writes if the situation is ongoing**

```bash
# If the problem is active writes corrupting data, stop the app container
docker stop APP_CONTAINER
```

**Step 2 — List recent restic snapshots**

```bash
restic -r YOUR_REPO snapshots
```

**Step 3 — Restore only the deleted item**

```bash
# Restore a single file from the most recent snapshot
restic -r YOUR_REPO restore latest \
  --target /tmp/restore \
  --include "/var/www/html/wp-content/uploads/2024/01/specific-image.jpg"

# Or restore a database dump from a specific snapshot
restic -r YOUR_REPO restore SNAPSHOT_ID \
  --target /tmp/restore \
  --include "db-*.sql.gz"
```

**Step 4 — Import the database if needed**

```bash
gunzip -c /tmp/restore/db-20241201.sql.gz \
  | docker exec -i DB_CONTAINER mysql -u root -p"$MYSQL_ROOT_PASSWORD" wordpress
```

**Step 5 — Verify and restart**

```bash
docker start APP_CONTAINER
# Confirm site loads and the restored content is present
```

---

### 3b. Corrupted WordPress Database

**Situation:** Site shows database connection errors or SQL errors. The server is running.

**Step 1 — Check if the DB container is running**

```bash
docker ps | grep db
docker logs DB_CONTAINER --tail 50
```

**Step 2 — Attempt repair before restoring**

```bash
docker exec DB_CONTAINER mysqlcheck \
  -u root -p"$MYSQL_ROOT_PASSWORD" \
  --auto-repair wordpress
```

If repair succeeds, restart the app container and verify.

**Step 3 — If repair fails, restore from backup**

Identify the last working snapshot. Check your application logs for when errors started:

```bash
# Find when DB errors began
docker logs APP_CONTAINER 2>&1 | grep -i "error\|SQLSTATE" | head -20
```

Then restore:

```bash
# Stop the app to prevent mid-restore writes
docker stop APP_CONTAINER

# Drop and recreate the database
docker exec DB_CONTAINER mysql -u root -p"$MYSQL_ROOT_PASSWORD" \
  -e "DROP DATABASE IF EXISTS wordpress; CREATE DATABASE wordpress CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"

# Restore from the last known-good dump
restic -r YOUR_REPO restore SNAPSHOT_ID \
  --target /tmp/restore \
  --include "db-*.sql.gz"

gunzip -c /tmp/restore/db-YYYYMMDD.sql.gz \
  | docker exec -i DB_CONTAINER mysql -u root -p"$MYSQL_ROOT_PASSWORD" wordpress

docker start APP_CONTAINER
```

---

### 3c. Failed Deployment — Site Broken

**Situation:** You deployed new code or updated a plugin and the site is now broken or throwing errors.

**Option A — Docker image rollback (if using pinned image tags)**

```bash
# Roll back to the previous compose configuration
git checkout HEAD~1 -- docker-compose.yml
docker compose up -d
```

**Option B — Plugin rollback via WP-CLI**

```bash
# Deactivate the last-updated plugin
docker exec --user www-data APP_CONTAINER wp plugin deactivate PLUGIN_SLUG --allow-root

# Or list recently updated plugins and roll back
docker exec --user www-data APP_CONTAINER wp plugin list --format=table
```

**Option C — File restore from restic**

```bash
# Restore wp-content/plugins to state from yesterday's snapshot
restic -r YOUR_REPO restore SNAPSHOT_ID \
  --target /tmp/restore \
  --include "/var/www/html/wp-content/plugins/"

# Copy restored plugins over the broken ones
cp -r /tmp/restore/var/www/html/wp-content/plugins/* \
  DOCKER_VOLUME_PATH/wp-content/plugins/

docker restart APP_CONTAINER
```

**Option D — Enable maintenance mode while debugging**

```bash
docker exec --user www-data APP_CONTAINER wp maintenance-mode activate --allow-root
# ... investigate and fix ...
docker exec --user www-data APP_CONTAINER wp maintenance-mode deactivate --allow-root
```

---

### 3d. Full Server Rebuild After Loss

**Situation:** The VPS is gone — provider datacenter failure, provider billing issue, server destroyed. Offsite backups are intact.

**Step 1 — Provision a new VPS**

From your VPS provider:
- Same region and OS (Ubuntu 22.04 LTS)
- Add your SSH public key during provisioning
- Note the new server IP

**Step 2 — Apply base hardening**

Follow `linux-server-hardening.md` in order. At minimum before restoring data:

```bash
# On the new server:
apt update && apt upgrade -y
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp   # SSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable

# Install Docker
curl -fsSL https://get.docker.com | sh

# Create app user, directories, copy your compose config from git
```

**Step 3 — Restore application config**

Your `docker-compose.yml`, `.env`, and `nginx.conf` should be in version control or in your password manager. Copy them to the new server.

```bash
# If using git:
git clone https://github.com/YOUR_ORG/YOUR_PRIVATE_REPO /var/www/APP_DIR
cd /var/www/APP_DIR
# Restore .env from password manager (not in git)
```

**Step 4 — Start the application stack (empty DB)**

```bash
docker compose up -d
# Let containers initialize and create the DB schema
sleep 15
docker compose ps   # confirm all containers running
```

**Step 5 — Restore database from offsite backup**

```bash
# On your local machine or backup server:
restic -r YOUR_OFFSITE_REPO snapshots   # pick the right snapshot

restic -r YOUR_OFFSITE_REPO restore SNAPSHOT_ID \
  --target /tmp/restore \
  --include "db-*.sql.gz"

# Transfer to new server
scp /tmp/restore/db-YYYYMMDD.sql.gz deploy@NEW_SERVER_IP:/tmp/

# On new server — import
docker stop APP_CONTAINER

docker exec DB_CONTAINER mysql -u root -p"$MYSQL_ROOT_PASSWORD" \
  -e "DROP DATABASE IF EXISTS wordpress; CREATE DATABASE wordpress CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"

gunzip -c /tmp/db-YYYYMMDD.sql.gz \
  | docker exec -i DB_CONTAINER mysql -u root -p"$MYSQL_ROOT_PASSWORD" wordpress

docker start APP_CONTAINER
```

**Step 6 — Restore uploaded files**

```bash
# On your local machine or backup server:
restic -r YOUR_OFFSITE_REPO restore SNAPSHOT_ID \
  --target /tmp/restore-uploads \
  --include "/var/www/html/wp-content/uploads/"

# Sync to new server
rsync -avz /tmp/restore-uploads/ \
  deploy@NEW_SERVER_IP:DOCKER_VOLUME_UPLOADS_PATH/
```

**Step 7 — Update DNS to new IP**

```bash
# Via Cloudflare API — update the A record for your domain
curl -X PATCH "https://api.cloudflare.com/client/v4/zones/ZONE_ID/dns_records/RECORD_ID" \
  -H "Authorization: Bearer CF_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"content": "NEW_SERVER_IP"}'
```

DNS TTL must propagate (5 min with Cloudflare proxied; up to 24 hours with low TTL direct records).

**Step 8 — Rotate all credentials**

Any credential that existed on the old server must be considered exposed. See `incident-response-checklist.md §7`.

---

### 3e. Ransomware — Data Encrypted on Server

**Situation:** An attacker gained root, encrypted files on the server, or destroyed your local restic repository with `restic forget --prune`. Offsite/append-only backups are the only path to recovery.

> If the local restic repo was destroyed but you used append-only mode or object-locked cloud storage, your snapshots are intact. If the local repo was the only copy and it was deleted, recovery is not possible without data loss.

**Step 1 — Do not pay. Do not attempt to clean the compromised server.**

**Step 2 — Verify offsite snapshot integrity**

```bash
# From your backup machine or local machine
restic -r YOUR_OFFSITE_REPO check
restic -r YOUR_OFFSITE_REPO snapshots
```

Find the last snapshot that predates the intrusion. Check your server logs for the earliest malicious activity:

```bash
# If you still have log access:
grep -E "(POST /wp-login|/wp-content/uploads/.*\.php|eval\()" \
  /var/log/nginx/access.log | sort | head -5
```

**Step 3 — Destroy the compromised server entirely**

Do not attempt to clean it. Provision a new VPS (see §3d above).

**Step 4 — Restore from the pre-compromise snapshot**

If the breach was 3 days ago and you have daily backups, the last 3 snapshots may contain the compromise. Use the snapshot immediately before the earliest malicious log entry.

**Step 5 — Fix the entry point before going back online**

Do not restore and re-expose the same vulnerability. Identify how they got in (see `incident-response-checklist.md §4`) and resolve it before re-enabling public access.

---

### 3f. Domain or DNS Hijacking

**Situation:** Your domain was transferred or DNS records were changed without your authorization. The site is serving attacker-controlled content or is unreachable.

**Immediate steps:**

- [ ] Log into your domain registrar directly (type the URL — do not click email links)
- [ ] Change your registrar account password immediately
- [ ] Check: is the domain still under your account? If transferred, initiate a domain dispute with ICANN.
- [ ] Check DNS records for unauthorized changes (A, CNAME, MX, TXT)

**If DNS records were modified:**

```bash
# Revert to your correct A record
# Via Cloudflare dashboard or API
```

**If MX records were changed** — an attacker may have received email sent to your domain during the period of hijacking. Audit any password resets, account confirmations, or sensitive emails from that window.

**Mitigation for the future:**

- Enable **registrar lock** (transfer lock) at your registrar — prevents unauthorized transfers
- Enable **DNSSEC** — cryptographically signs DNS records; unauthorized changes fail validation
- Use a **registrar with 2FA** — most breaches happen via credential stuffing, not registrar exploits

---

### 3g. Cloudflare Account Compromise

**Situation:** An attacker accessed your Cloudflare account. Possible actions: DNS records changed, SSL disabled, origin IP exposed, WAF rules deleted.

**Step 1 — Log into Cloudflare immediately and change your password**

**Step 2 — Check audit log**

Cloudflare → My Profile → Audit Log. Look for changes in the last 24 hours.

**Step 3 — Verify and revert DNS records**

Check that your A record still points to your origin IP (proxied). Look for any new records, especially MX changes.

**Step 4 — Verify SSL mode is still Full (Strict)**

SSL/TLS → Overview → Encryption mode.

**Step 5 — Regenerate all Cloudflare API tokens**

Any API token that existed during the compromise should be rotated. Check `~/.env`, cron jobs, and deploy pipelines for places where the old token is used.

**Step 6 — Rotate the X-Origin-Verify secret header value** (if in use)

The secret in your nginx config and Cloudflare Transform Rule must be changed together. Update nginx, reload, then update the CF Transform Rule.

---

### 3h. Database Password Lost

**Situation:** The database password is unknown and the DB container will not accept connections.

**Option A — Read from the running environment** (fastest, if DB is running)

```bash
docker exec DB_CONTAINER env | grep MYSQL_ROOT_PASSWORD
# or
docker inspect DB_CONTAINER | grep -i password
```

**Option B — Read from your .env file**

```bash
cat /path/to/project/.env | grep MYSQL
```

**Option C — Reset via MariaDB safe mode**

```bash
# Stop the DB container
docker stop DB_CONTAINER

# Start a temporary container with the same volume, bypassing auth
docker run --rm -it \
  -v DB_VOLUME:/var/lib/mysql \
  mariadb:latest \
  --skip-grant-tables

# In the MariaDB shell:
FLUSH PRIVILEGES;
ALTER USER 'root'@'localhost' IDENTIFIED BY 'NEW_ROOT_PASSWORD';
FLUSH PRIVILEGES;
exit

# Update .env and restart normally
docker start DB_CONTAINER
```

---

## 4. Backup Verification Drill

Run this monthly to confirm backups are actually working. It restores a database snapshot to a throwaway path and verifies integrity — no impact on the running site.

```bash
#!/usr/bin/env bash
# /usr/local/bin/backup-drill.sh
# Run monthly: 0 6 1 * * root /usr/local/bin/backup-drill.sh >> /var/log/backup-drill.log 2>&1

set -euo pipefail

REPO="YOUR_RESTIC_REPO"
RESTORE_DIR="/tmp/backup-drill-$(date +%Y%m%d)"
REPORT="/var/log/backup-drill.log"

echo "=== Backup drill $(date) ==="

# 1. Check repo integrity
echo "[1] Checking repository integrity..."
restic -r "$REPO" check --read-data-subset=5% \
  && echo "[1] PASS: repository is valid" \
  || { echo "[1] FAIL: repository integrity check failed"; exit 1; }

# 2. List snapshots and confirm recency
echo "[2] Checking snapshot recency..."
LATEST=$(restic -r "$REPO" snapshots --latest 1 --json | python3 -c \
  "import sys,json; s=json.load(sys.stdin); print(s[-1]['time'][:10] if s else 'none')")
echo "[2] Latest snapshot: $LATEST"
TODAY=$(date +%Y-%m-%d)
if [ "$LATEST" != "$TODAY" ]; then
  echo "[2] WARN: latest snapshot is not from today"
fi

# 3. Restore latest DB dump
echo "[3] Restoring database dump..."
mkdir -p "$RESTORE_DIR"
restic -r "$REPO" restore latest \
  --target "$RESTORE_DIR" \
  --include "db-*.sql.gz" \
  --quiet

# 4. Verify the restored file
DUMP=$(ls "$RESTORE_DIR"/db-*.sql.gz 2>/dev/null | head -1)
if [ -z "$DUMP" ]; then
  echo "[4] FAIL: no database dump found in snapshot"
  rm -rf "$RESTORE_DIR"
  exit 1
fi

gzip -t "$DUMP" \
  && echo "[4] PASS: dump is valid gzip: $(basename $DUMP) ($(du -sh $DUMP | cut -f1))" \
  || { echo "[4] FAIL: dump is corrupt"; rm -rf "$RESTORE_DIR"; exit 1; }

# 5. Verify SQL structure (does not require a running DB)
gunzip -c "$DUMP" | grep -q "^CREATE TABLE" \
  && echo "[5] PASS: SQL structure present" \
  || echo "[5] WARN: no CREATE TABLE found — dump may be empty"

# 6. Cleanup
rm -rf "$RESTORE_DIR"

echo "=== Drill complete: $(date) ==="
```

```bash
chmod +x /usr/local/bin/backup-drill.sh

# Add to cron: first of every month at 6am
echo "0 6 1 * * root /usr/local/bin/backup-drill.sh >> /var/log/backup-drill.log 2>&1" \
  > /etc/cron.d/backup-drill
```

Check the log after the first run:

```bash
tail -30 /var/log/backup-drill.log
```

---

## 5. Recovery Time Estimates

These are realistic estimates for a single-operator running a Docker Compose WordPress stack with restic backups. Times assume working backups and access to version-controlled config.

| Scenario | Steps | Realistic RTO |
|---|---|---|
| Single file or DB table restored | Restic restore → import | 20–40 min |
| DB corruption (repair succeeds) | mysqlcheck → restart | 10–15 min |
| DB corruption (restore from backup) | Stop → restore → start | 30–60 min |
| Broken deployment (rollback) | git checkout → compose up | 10–20 min |
| Full server rebuild (clean backups) | Provision → harden → restore | 2–4 hours |
| Ransomware (append-only backups) | Destroy → rebuild → restore | 3–6 hours |
| DNS hijacking | Revert records → wait for TTL | 30 min + TTL |
| No offsite backup | Start from scratch | Days + data loss |

> These estimates degrade significantly if you have not done a restore drill recently. The first time you restore from restic under pressure is not when you want to discover your passphrase is wrong.

---

*Last reviewed: 2025 | Applies to: Debian-based Linux, Docker Compose, WordPress on Nginx, restic*
