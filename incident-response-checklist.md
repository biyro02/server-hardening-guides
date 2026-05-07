# Incident Response Checklist

**What to do in the first hour when your server is compromised**

> Speed matters, but order matters more. Doing things in the wrong sequence destroys evidence or makes recovery harder. Follow this checklist linearly.

---

## Table of Contents

1. [The First 5 Minutes](#1-the-first-5-minutes)
2. [Evidence Collection](#2-evidence-collection)
3. [Isolation](#3-isolation)
4. [Investigation](#4-investigation)
5. [Scope Assessment](#5-scope-assessment)
6. [Recovery](#6-recovery)
7. [Credential Rotation](#7-credential-rotation)
8. [Post-Incident](#8-post-incident)
9. [Indicators of Compromise Reference](#9-indicators-of-compromise-reference)

---

## 1. The First 5 Minutes

> Your instinct will be to reboot or delete things. Resist it. Rebooting destroys in-memory evidence. Deleting files destroys forensic traces. Both make recovery harder.

- [ ] **Do not reboot.**

  A running system retains:
  - Active network connections (what is the attacker connected to right now?)
  - Running processes (what are they executing?)
  - Bash history in memory (what commands did they run?)
  - Temporary files in `/tmp`, `/dev/shm`

  Rebooting clears all of this.

- [ ] **Do not run `apt upgrade` or restart services** — changes to the filesystem destroy evidence.

- [ ] **Confirm the incident is real** before taking drastic action. Common false positives:
  - A port scanner hitting your server (normal background noise — check if anything was actually accessed)
  - fail2ban firing on a legitimate user who mistyped their password
  - Elevated CPU from a backup job or cron task

- [ ] **Open a separate terminal window** for investigation — do not close your existing SSH session.

- [ ] **Start a timestamped log of everything you observe and do.** A simple text file is fine. You will thank yourself later.

  ```bash
  script /tmp/incident-$(date +%Y%m%d-%H%M%S).log
  # Everything you type and all output will be logged
  # End with: exit
  ```

- [ ] **If you believe the incident is active and ongoing** (attacker currently logged in or running processes), skip to Section 3 (Isolation) immediately, then come back.

---

## 2. Evidence Collection

> Collect before you change anything. Run these commands and save the output. If this ends up being a false alarm, you lose nothing. If it is real, you will need this data.

```bash
# --- SNAPSHOT: run all of these immediately ---

# Who is currently logged in
who
w
last | head -30

# All active network connections
ss -tnp
ss -tlnp
netstat -tnp 2>/dev/null || true

# Running processes sorted by CPU
ps auxf --sort=-%cpu | head -40

# Processes with open network connections
lsof -i -n -P 2>/dev/null | head -40

# Recently modified files in web root and config dirs (last 24h)
find /var/www /etc /opt /tmp /dev/shm -mtime -1 -type f 2>/dev/null | sort

# Recently modified PHP files (last 7 days) — webshell indicator
find /var/www -name "*.php" -mtime -7 -type f 2>/dev/null | sort

# Files in /tmp and /dev/shm (often used for staging malware)
ls -la /tmp/ /dev/shm/ /var/tmp/

# SUID/SGID files (attacker may plant escalation tools)
find / -perm /6000 -type f 2>/dev/null | grep -v proc

# Cron jobs (all users)
crontab -l 2>/dev/null
cat /etc/cron.d/* 2>/dev/null
ls -la /var/spool/cron/crontabs/ 2>/dev/null
cat /etc/crontab

# Authorized SSH keys (any unfamiliar keys?)
find /home /root -name "authorized_keys" 2>/dev/null -exec echo "=== {} ===" \; -exec cat {} \;

# /etc/passwd changes (new users?)
cat /etc/passwd | grep -v "nologin\|false"

# Bash history for all accessible users
cat /root/.bash_history 2>/dev/null
for h in /home/*/.bash_history; do echo "=== $h ==="; cat "$h" 2>/dev/null; done

# Docker containers status
docker ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null

# systemd service changes
systemctl list-units --state=failed
systemctl list-timers

# Kernel modules loaded (look for unfamiliar names)
lsmod | sort
```

Save this output somewhere safe — ideally your local machine, not the compromised server.

```bash
# Stream evidence to your local machine
ssh YOUR_SERVER 'ss -tnp; ps auxf; last -30; find /tmp -type f' > /local/evidence-$(date +%Y%m%d).txt
```

---

## 3. Isolation

> Isolation stops an active breach from spreading and prevents the attacker from covering tracks. Do this when you confirm an active intrusion or when you need to stop ongoing damage.

- [ ] **Block all inbound traffic immediately** (you will still have your existing SSH session).

  ```bash
  ufw default deny incoming
  ufw reload
  ```

  > **Warning:** This will make the site unavailable to users. Decide based on severity — a slow defacement may not warrant this; active data exfiltration does.

- [ ] **Alternatively, block by source IP** if you have identified the attacker's IP.

  ```bash
  ufw insert 1 deny from ATTACKER_IP to any
  ufw reload
  ```

- [ ] **If attacker has an active SSH session**, terminate it.

  ```bash
  who   # Identify attacker's PTY (e.g. pts/1)
  pkill -9 -t pts/1
  ```

- [ ] **If breach is via a container**, stop the affected container without removing it (removing destroys evidence).

  ```bash
  docker stop CONTAINER_NAME  # stop, not remove
  ```

- [ ] **Revoke all SSH authorized keys** until you can audit them.

  ```bash
  # Backup first
  cp /root/.ssh/authorized_keys /root/.ssh/authorized_keys.backup
  # Then inspect manually — remove any key you do not recognize
  ```

- [ ] **Change the SSH port immediately** if you believe the attacker knows it and might reconnect.

---

## 4. Investigation

> Now that you have collected evidence and stopped active harm, investigate what happened. Do not skip evidence collection — you cannot un-corrupt data you have already changed.

### 4a. Entry Point

```bash
# Check Nginx access logs for the attack pattern
# Look for: unusual POST requests, /../ traversal, base64 strings, /etc/passwd
grep -E "(\.\.\/|base64|/etc/passwd|cmd=|exec\(|eval\(|/bin/sh)" /var/log/nginx/access.log | tail -50

# Check WordPress logs for PHP errors indicating exploitation
docker logs WORDPRESS_CONTAINER 2>&1 | grep -iE "(error|warning|fatal|exception)" | tail -50

# Look for webshell access patterns (unusual direct PHP file access)
grep -E "GET /wp-content/(uploads|plugins|themes)/.*\.php" /var/log/nginx/access.log | tail -30

# Check fail2ban for what it caught
fail2ban-client status
fail2ban-client status nginx-wplogin
fail2ban-client status sshd

# Check auth log for SSH brute force or successful logins
grep -E "(Failed|Accepted|Invalid)" /var/log/auth.log | tail -50
```

### 4b. Persistence Mechanisms

Attackers plant persistence. Check all of these:

```bash
# New or modified cron jobs
diff <(ls -la /var/spool/cron/crontabs/) /tmp/known-good-cron 2>/dev/null || \
  ls -lat /var/spool/cron/crontabs/

# New systemd services (added after your last known-good date)
find /etc/systemd /lib/systemd -name "*.service" -newer /etc/hostname

# New SUID binaries
find / -perm -4000 -type f 2>/dev/null

# New SSH keys
find / -name "authorized_keys" -newer /etc/hostname 2>/dev/null

# WordPress users with unexpected admin roles
docker exec WORDPRESS_CONTAINER wp user list --role=administrator --allow-root

# WordPress plugin files modified recently (backdoor via plugin)
find /var/www/html/wp-content/plugins -name "*.php" -mtime -3 -type f 2>/dev/null
```

### 4c. Data Access

```bash
# What files were read or executed recently
find /var/www /etc /opt -atime -1 -type f 2>/dev/null | grep -v "\.log$" | sort

# Check MariaDB query log (if enabled)
docker exec DB_CONTAINER mysql -u root -p"$MYSQL_ROOT_PASSWORD" \
  -e "SHOW VARIABLES LIKE 'general_log%'"

# Database: check for new admin users or modified emails
docker exec DB_CONTAINER mysql -u root -p"$MYSQL_ROOT_PASSWORD" wordpress \
  -e "SELECT user_login, user_email, user_registered FROM wp_users;"

# Database persistence: check wp_options for injected code (malicious shortcodes,
# autoloaded PHP, eval-based backdoors that survive file-system cleanup)
docker exec DB_CONTAINER mysql -u root -p"$MYSQL_ROOT_PASSWORD" wordpress \
  -e "SELECT option_name, LEFT(option_value, 300) FROM wp_options
      WHERE autoload = 'yes'
        AND (option_value LIKE '%base64_decode%'
          OR option_value LIKE '%eval(%'
          OR option_value LIKE '%<?php%'
          OR option_value LIKE '%gzinflate%')
      ORDER BY option_id DESC LIMIT 20;"

# Database persistence: check for unexpected scheduled WP-Cron events
# Attackers can register cron events that re-install backdoors after cleanup
docker exec --user www-data WP_CONTAINER wp cron event list

# Check for PHP eval/base64_decode in uploaded files (obfuscated webshell)
grep -rE "(eval\s*\(|base64_decode\s*\(|gzinflate|str_rot13|assert\s*\()" \
  /var/www/html/wp-content/uploads/ 2>/dev/null
```

---

## 5. Scope Assessment

Before beginning recovery, answer these questions:

- [ ] **What was the entry point?** (Compromised plugin? Brute-forced password? SSH key theft? Supply chain?)
- [ ] **How long did the attacker have access?** (Check first malicious log entry vs current time)
- [ ] **What did they do?**
  - Read data only?
  - Modified files?
  - Planted persistence?
  - Exfiltrated the database?
  - Lateral movement to other systems?
- [ ] **Is your backup clean?** (If the breach was days ago and backups run daily, your last backup may contain the compromise)
- [ ] **Are there other systems at risk?** (Same SSH keys, same passwords, same secrets)

---

## 6. Recovery

> Do not try to clean a compromised system. Cleaning is error-prone — a missed backdoor means you go through this entire process again. Rebuild from a clean image and restore data from a known-good backup.

- [ ] **Identify the last known-good backup** — find the breach timestamp first, then choose a snapshot that predates it.

  ```bash
  # Step 1: Find the earliest malicious log entry to establish the breach timestamp
  grep -E "POST /wp-login.php|/wp-content/uploads/.*\.php|eval\(" \
    /var/log/nginx/access.log | sort | head -5

  # Step 2: List restic snapshots — choose one that predates the breach date
  restic snapshots --repo /opt/myapp/backups/encrypted-repo
  # The snapshot date = when the backup ran, NOT when the data was clean.
  # If the breach was 5 days ago and daily backups ran, the last 5 snapshots may be contaminated.
  ```

  > **If the attacker deleted your restic snapshots** (via `restic forget --prune`): check your backup machine or object storage first. If you used append-only mode or B2/S3 object lock, snapshots are intact regardless. If the local repository is empty and no offsite copy exists, recovery from backup is not possible — you are rebuilding from scratch with data loss.

- [ ] **Test the restore on a non-production system** before wiping production.

- [ ] **Rebuild the application container from a clean image** — do not trust any container that was running during the compromise.

  ```bash
  docker compose down
  docker compose pull   # fresh images from registry
  docker compose up -d
  ```

- [ ] **Restore database from the known-good backup.**

  ```bash
  docker exec -i DB_CONTAINER mysql -u root -p"$MYSQL_ROOT_PASSWORD" wordpress \
    < /backups/db-KNOWN-GOOD-DATE.sql
  ```

- [ ] **Restore uploaded files from backup** if they were modified.

  > **If running with `read_only: true` containers:** `read_only: true` applies to the container's overlay filesystem layer — named volumes (e.g. `wp-content/uploads`) remain writable. Restore scripts should write to the volume path, not to paths inside the container's own filesystem. When restoring via `docker exec`, write operations to volume-mounted paths work normally. Paths that are part of the container image or tmpfs (e.g. `/run`, `/tmp`) cannot be written to and that is expected behavior, not a sign of a broken restore.

- [ ] **Do not restore `wp-content/plugins`** from a backup if plugins were the entry point — reinstall them fresh from trusted sources.

- [ ] **Verify the restored site functions correctly** before re-enabling public access.

- [ ] **Re-enable UFW rules** (if you tightened them during isolation).

---

## 7. Credential Rotation

> After any confirmed breach, assume all credentials are compromised. Rotate all of them — not just the obvious ones.

Rotate in this order (most critical first):

- [ ] **SSH keys** — generate new keys, replace `authorized_keys` on all servers.

  ```bash
  ssh-keygen -t ed25519 -C "post-incident-$(date +%Y%m%d)"
  ```

- [ ] **WordPress admin passwords** — reset all admin accounts.

  ```bash
  docker exec WORDPRESS_CONTAINER wp user update USERNAME --user_pass="NEW_STRONG_PASSWORD" --allow-root
  ```

- [ ] **Database password** — rotate and update in all config files.

  ```bash
  docker exec DB_CONTAINER mysql -u root -p"$OLD_ROOT_PASS" \
    -e "ALTER USER 'wp_user'@'%' IDENTIFIED BY 'NEW_PASSWORD';"
  # Update .env and restart containers
  ```

- [ ] **WordPress salts** — rotating salts invalidates all existing session cookies (logs everyone out).

  ```bash
  curl -s https://api.wordpress.org/secret-key/1.1/salt/
  # Replace in wp-salts.php
  ```

- [ ] **API keys and tokens** — GitHub tokens, payment processor keys, email service API keys, anything in `.env`.

- [ ] **SSL certificates** — if private keys may have been exposed.

- [ ] **CI/CD deploy keys** — replace any GitHub deploy keys or CI tokens.

---

## 8. Post-Incident

- [ ] **Write an incident timeline** — when did the breach start, what happened, how was it discovered, what was done. This is required for GDPR notification if personal data was involved.

- [ ] **Identify and fix the root cause** — do not just restore and hope. If it was a vulnerable plugin, remove it. If it was a weak password, mandate 2FA. If it was a misconfiguration, fix it and add it to the checklist.

- [ ] **Add detection for the attack pattern** — if the attacker used a specific URL pattern or payload, add a fail2ban rule or Nginx block for it.

- [ ] **Test your backups worked** — confirm the restore was successful and data is intact.

- [ ] **Notify affected parties** if personal data was accessed — GDPR requires notification within 72 hours if there is a high risk to individuals.

- [ ] **Update this checklist** with anything that was missing or unclear during the incident.

---

## 9. Indicators of Compromise Reference

Patterns that indicate active or past compromise. Check for these during routine audits:

### Webshells

```bash
# PHP webshell patterns in uploaded files
grep -rE "(eval\s*\(base64|system\s*\(\$_|exec\s*\(\$_|passthru\s*\(\$_|shell_exec\s*\(\$_)" \
  /var/www/html/wp-content/ 2>/dev/null

# PHP files in uploads directory (should never exist)
find /var/www/html/wp-content/uploads -name "*.php" 2>/dev/null

# Recently created PHP files (check each one)
find /var/www/html -name "*.php" -newer /var/www/html/wp-login.php -type f 2>/dev/null
```

### Cryptominers

```bash
# High CPU process not from your known containers
top -bn1 | head -20

# Network connections to mining pools (common ports: 3333, 4444, 9999, 14444)
ss -tnp | grep -E ":3333|:4444|:9999|:14444"

# Miner binary names
ps aux | grep -iE "(xmrig|minerd|cgminer|bfgminer|cpuminer|kswapd0|kworker)"
```

### Data Exfiltration

```bash
# Large outbound data transfers
# Check your VPS provider's bandwidth graph — a spike is a red flag

# Outbound connections on unusual ports
ss -tnp | grep -vE ":80|:443|:22|:3306"

# DNS queries for unusual domains
grep -i "NXDOMAIN\|REFUSED" /var/log/syslog 2>/dev/null | tail -20
```

### Persistence

```bash
# New systemd services installed after your known-good date
find /etc/systemd/system /lib/systemd/system -newer /etc/hostname -name "*.service" 2>/dev/null

# Unusual entries in /etc/rc.local or /etc/profile.d/
cat /etc/rc.local 2>/dev/null
ls /etc/profile.d/

# New cron files
find /var/spool/cron /etc/cron.d -newer /etc/hostname 2>/dev/null
```

---

*Last reviewed: 2025 | Applies to: Debian-based Linux, Docker Compose, WordPress on Nginx*
