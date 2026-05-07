# Linux Server Hardening Checklist

**Production-ready security baseline for Ubuntu/Debian VPS**

> This checklist is based on real-world experience hardening production servers running Docker workloads on Ubuntu 24.04 LTS. It assumes a fresh VPS from a provider like Hetzner, DigitalOcean, or Vultr. Work through it top-to-bottom on first setup, then revisit periodically.

---

## Table of Contents

1. [Initial Setup](#1-initial-setup)
2. [SSH Hardening](#2-ssh-hardening)
3. [Firewall (UFW + Docker)](#3-firewall-ufw--docker)
4. [Fail2ban](#4-fail2ban)
5. [Kernel Hardening](#5-kernel-hardening)
6. [Docker Security](#6-docker-security)
7. [System Updates](#7-system-updates)
8. [Attack Surface Reduction](#8-attack-surface-reduction)
9. [Filesystem Hardening](#9-filesystem-hardening)
10. [Backup Strategy](#10-backup-strategy)
11. [Monitoring](#11-monitoring)
12. [Incident Response Quick Reference](#12-incident-response-quick-reference)

---

## 1. Initial Setup

> First contact with a new server is high-risk. Do this before anything else is installed.

- [ ] **Change root password immediately** on first login, or disable root login entirely once a sudo user exists.

  ```bash
  passwd root
  ```

- [ ] **Create a non-root sudo user** — never operate day-to-day as root.

  ```bash
  adduser deploy
  usermod -aG sudo deploy
  ```

- [ ] **Copy your SSH public key** to the new user before locking down SSH.

  ```bash
  # From your local machine:
  ssh-copy-id deploy@YOUR_SERVER_IP

  # Or manually on the server:
  mkdir -p /home/deploy/.ssh
  chmod 700 /home/deploy/.ssh
  echo "YOUR_PUBLIC_KEY" >> /home/deploy/.ssh/authorized_keys
  chmod 600 /home/deploy/.ssh/authorized_keys
  chown -R deploy:deploy /home/deploy/.ssh
  ```

- [ ] **Verify SSH key login works** in a separate terminal before changing anything in sshd_config.

  ```bash
  ssh deploy@YOUR_SERVER_IP
  ```

- [ ] **Set the hostname** to something meaningful (avoids confusion in logs).

  ```bash
  hostnamectl set-hostname your-server-name
  ```

- [ ] **Set the timezone** to UTC for consistent log timestamps across tools.

  ```bash
  timedatectl set-timezone UTC
  ```

- [ ] **Update all packages** immediately after first login.

  ```bash
  apt update && apt upgrade -y
  ```

---

## 2. SSH Hardening

> SSH is the most common attack surface on any internet-facing server. Lock it down hard.

- [ ] **Edit `/etc/ssh/sshd_config`** — make the following changes:

  ```
  PermitRootLogin prohibit-password
  PasswordAuthentication no
  PubkeyAuthentication yes
  MaxAuthTries 3
  MaxSessions 3
  X11Forwarding no
  AllowTcpForwarding no
  LoginGraceTime 20
  ClientAliveInterval 300
  ClientAliveCountMax 2
  PrintLastLog yes
  ```

  > **Why `PermitRootLogin prohibit-password` instead of `no`?**  
  > It allows emergency key-based root login (e.g. if your sudo user is broken) while still blocking password brute-force. On fully locked-down servers, `no` is fine.

  > **Why `MaxAuthTries 3`?**  
  > Limits brute-force attempts per connection. Combined with fail2ban, this significantly slows automated attacks.

- [ ] **Change the default SSH port** (optional, reduces noise in logs — not a security measure on its own).

  ```
  Port 2222
  ```

  If you change the port, remember to update UFW rules accordingly.

- [ ] **Restrict SSH to specific users** if you have multiple system accounts.

  ```
  AllowUsers deploy
  ```

- [ ] **Reload SSH** after changes — never restart (that would kill your session).

  ```bash
  systemctl reload sshd
  ```

- [ ] **Verify the config is valid** before reloading.

  ```bash
  sshd -t
  ```

- [ ] **Use Ed25519 keys** on the client side (stronger than RSA 2048).

  ```bash
  ssh-keygen -t ed25519 -C "your@email.com"
  ```

- [ ] **Disable weak ciphers** (optional hardening for high-security environments).

  Add to `sshd_config`:
  ```
  KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
  MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
  ```

- [ ] **Keep OpenSSH patched** — `apt upgrade openssh-server` at every maintenance window.

  > **CVE-2024-6387 (regreSSHion):** A signal handler race condition in OpenSSH 8.5p1–9.7p1 allows unauthenticated remote code execution as root on glibc-based Linux systems. Public exploit code exists. Ubuntu 22.04 and 24.04 were affected. The fix landed in openssh-server package updates in July 2024 — if you have not run `apt upgrade` since then, you may still be vulnerable. Affected: `ssh -V` showing `OpenSSH_8.5p1` through `OpenSSH_9.7p1`. `MaxAuthTries` and `PasswordAuthentication no` do not mitigate this because the vulnerability is in the pre-authentication code path. Patch is the only fix.
  >
  > Check your version: `ssh -V`  
  > Patched at: Ubuntu 22.04 ≥ `1:8.9p1-3ubuntu0.10`, Ubuntu 24.04 ≥ `1:9.6p1-3ubuntu13.3`

---

## 3. Firewall (UFW + Docker)

> UFW is simple and sufficient for most VPS setups. However, Docker bypasses UFW by default — this is a critical gotcha that has exposed thousands of servers.

- [ ] **Install UFW** if not present.

  ```bash
  apt install ufw -y
  ```

- [ ] **Set default policies** — deny all inbound, allow all outbound.

  ```bash
  ufw default deny incoming
  ufw default allow outgoing
  ```

- [ ] **Allow only required ports** before enabling.

  ```bash
  ufw allow 22/tcp      # or your custom SSH port
  ufw allow 80/tcp      # HTTP
  ufw allow 443/tcp     # HTTPS
  ```

- [ ] **Enable UFW**.

  ```bash
  ufw enable
  ufw status verbose
  ```

- [ ] **Fix the Docker UFW bypass vulnerability.**

  > **Why this matters:** Docker modifies iptables directly, bypassing UFW entirely. A container with a published port (`-p 8080:80`) will be reachable from the internet even if UFW blocks port 8080. This is a widely-reported issue that has caused unintended exposure of databases, admin panels, and internal services. See Docker documentation on network security for details.

  **Option A (Recommended): Bind containers to localhost only.**

  In `docker-compose.yml`, never use `ports: "8080:80"` for internal services.  
  Use `ports: "127.0.0.1:8080:80"` to bind only to localhost.

  ```yaml
  ports:
    - "127.0.0.1:8080:80"
  ```

  This is the simplest and most reliable fix — it prevents Docker from publishing the port to any interface except loopback, regardless of iptables state.

  **Option B: DOCKER-USER chain** (use when localhost binding is not possible).

  The DOCKER-USER chain is processed before Docker's own rules and is preserved across `docker restart`. A correct implementation requires allowing established connections *before* the DROP rule, otherwise return traffic from outbound container connections (DNS, API calls, package downloads) is also dropped:

  ```bash
  # Allow established/related connections (return traffic from container outbound calls)
  iptables -I DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  # Allow from trusted management IP
  iptables -I DOCKER-USER -i eth0 -s YOUR_TRUSTED_IP -j ACCEPT

  # Drop everything else direct to containers
  iptables -A DOCKER-USER -i eth0 -j DROP
  ```

  > **Do not run `netfilter-persistent save` while Docker is running.** Docker adds ephemeral chains (DOCKER, DOCKER-ISOLATION-*) that will be captured in the saved rules but will conflict on the next boot when Docker recreates them. Save rules only before starting Docker, or use the DOCKER-USER approach with a startup script that re-applies rules after Docker is running.
  >
  > **IPv6:** If your server has IPv6 enabled, apply the same rules with `ip6tables`. iptables and ip6tables are separate — a rule in one does not affect the other.
  >
  > ```bash
  > ip6tables -I DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  > ip6tables -I DOCKER-USER -i eth0 -s YOUR_TRUSTED_IPV6 -j ACCEPT
  > ip6tables -A DOCKER-USER -i eth0 -j DROP
  > ```

- [ ] **Make DOCKER-USER rules persistent** if using Option B.

  ```bash
  apt install iptables-persistent -y
  # Apply rules via a post-start script, not netfilter-persistent save while Docker runs
  ```

- [ ] **Verify no unintended ports are exposed.**

  ```bash
  ss -tlnp
  nmap -sV YOUR_SERVER_IP
  ```

---

## 4. Fail2ban

> Fail2ban reads log files and temporarily bans IPs that show signs of brute-force or abuse. It is your last line of defense after SSH key-only auth and rate limiting.

- [ ] **Install fail2ban**.

  ```bash
  apt install fail2ban -y
  ```

- [ ] **Create a local jail config** — never edit the default `jail.conf` (it gets overwritten on updates).

  ```bash
  cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
  ```

- [ ] **Configure the SSH jail** in `/etc/fail2ban/jail.local`:

  ```ini
  [sshd]
  enabled  = true
  port     = ssh
  backend  = systemd
  maxretry = 3
  bantime  = 3600
  findtime = 600
  ```

  > **Use `backend = systemd` for sshd on Ubuntu 22.04 / 24.04.** On modern Ubuntu, sshd logs to journald, not to a file. Using `backend = auto` or specifying `logpath = /var/log/auth.log` causes the jail to silently find no logs and ban nothing — you think fail2ban is protecting you, but it isn't. The `systemd` backend reads from journald directly and does not use `logpath`.
  >
  > For nginx and other file-based jails, use `backend = auto` (or `backend = polling`) with the appropriate `logpath`.

- [ ] **Configure a WordPress login jail** (if running WordPress + Nginx):

  Create `/etc/fail2ban/filter.d/nginx-wplogin.conf`:

  ```ini
  [Definition]
  failregex = ^<HOST> .* "POST /wp-login\.php[^"]*" (401|403|429) 
  ignoreregex =
  ```

  > **Match only failed responses, not all POSTs.** A failregex that matches every POST to wp-login.php will also match successful admin logins (which return 200 or 302). After 5 successful logins, fail2ban bans the admin's own IP. The response-code filter `(401|403|429)` ensures only actual failures count.

  Add to `jail.local`:

  ```ini
  [nginx-wplogin]
  enabled  = true
  port     = http,https
  filter   = nginx-wplogin
  backend  = auto
  logpath  = /var/log/nginx/access.log
  maxretry = 5
  bantime  = 3600
  findtime = 300
  ```

  > **Docker setups:** If nginx runs inside a Docker container, its logs go to Docker's log driver (`docker logs`) — not to `/var/log/nginx/access.log` on the host. fail2ban cannot watch container logs by default. Two solutions:
  > 1. **Host nginx** (recommended): Run a host-level nginx for SSL termination and external access; let it write to `/var/log/nginx/access.log`. fail2ban watches the host nginx log. Container nginx handles WordPress internally.
  > 2. **Log volume mount**: Mount a host directory into the container as the nginx log path, then point fail2ban's `logpath` there.

- [ ] **Restart and verify fail2ban is running.**

  ```bash
  systemctl restart fail2ban
  systemctl status fail2ban
  fail2ban-client status
  fail2ban-client status sshd
  ```

- [ ] **Test that banning works** (from a throwaway IP or using `fail2ban-client set sshd banip TEST_IP`).

- [ ] **Whitelist your own IP** to avoid locking yourself out.

  In `jail.local`:
  ```ini
  [DEFAULT]
  ignoreip = 127.0.0.1/8 ::1 YOUR_HOME_IP
  ```

---

## 5. Kernel Hardening

> Kernel parameters control how the OS responds to network attacks, memory access, and system events. These sysctl values are widely recommended security baselines.

- [ ] **Create `/etc/sysctl.d/99-hardening.conf`** with the following settings:

  ```ini
  # Protect against ptrace-based attacks (e.g. one process dumping another's memory)
  kernel.yama.ptrace_scope = 1

  # Hide kernel pointer addresses from unprivileged users (prevents info leaks)
  kernel.kptr_restrict = 2

  # Disable core dumps for setuid programs (prevents credential exposure)
  fs.suid_dumpable = 0

  # Enable SYN cookies to protect against SYN flood DoS attacks
  net.ipv4.tcp_syncookies = 1

  # Enable reverse path filtering (blocks spoofed source IPs)
  net.ipv4.conf.all.rp_filter = 1
  net.ipv4.conf.default.rp_filter = 1

  # Disable SysRq key (prevents console-based attacks)
  kernel.sysrq = 0

  # Ignore ICMP broadcast requests (Smurf attack mitigation)
  net.ipv4.icmp_echo_ignore_broadcasts = 1

  # Ignore bogus ICMP error responses
  net.ipv4.icmp_ignore_bogus_error_responses = 1

  # Disable IP source routing
  net.ipv4.conf.all.accept_source_route = 0
  net.ipv4.conf.default.accept_source_route = 0

  # Disable ICMP redirects (prevents routing table manipulation)
  net.ipv4.conf.all.accept_redirects = 0
  net.ipv4.conf.default.accept_redirects = 0
  net.ipv6.conf.all.accept_redirects = 0

  # Do not send ICMP redirects
  net.ipv4.conf.all.send_redirects = 0

  # Restrict dmesg to privileged users
  kernel.dmesg_restrict = 1
  ```

- [ ] **Apply the settings immediately.**

  ```bash
  sysctl -p /etc/sysctl.d/99-hardening.conf
  ```

- [ ] **Verify settings are applied.**

  ```bash
  sysctl kernel.yama.ptrace_scope
  sysctl net.ipv4.tcp_syncookies
  ```

---

## 6. Docker Security

> Docker's defaults are not production-safe. These settings reduce the blast radius if a container is compromised.

- [ ] **Never run containers with `--privileged`** unless absolutely necessary (and document why). A privileged container has full access to the host.

- [ ] **Set `no-new-privileges: true`** in docker-compose to prevent privilege escalation inside containers.

  ```yaml
  services:
    app:
      security_opt:
        - no-new-privileges:true
  ```

- [ ] **Do not mount `/var/run/docker.sock`** into containers unless the container explicitly needs to manage Docker (e.g. Watchtower, Portainer). A container with the Docker socket can escape to the host with full root access.

  > **CVE note:** Multiple CVEs involve Docker socket exposure leading to full host compromise. This is one of the most common container escape vectors.

- [ ] **Use the default seccomp profile** — it blocks ~44 dangerous syscalls. Verify it is not disabled.

  ```yaml
  security_opt:
    - seccomp:default
  ```

- [ ] **Use separate Docker networks per application** — containers from different apps should not be on the same network.

  ```yaml
  networks:
    app-network:
      driver: bridge
  ```

- [ ] **Set restart policies** so containers recover from crashes but don't restart infinitely on crash loops.

  ```yaml
  restart: unless-stopped
  ```

- [ ] **Set resource limits** to prevent one container from consuming all server resources.

  ```yaml
  deploy:
    resources:
      limits:
        memory: 512m
        cpus: "0.5"
  ```

- [ ] **Do not use `:latest` tags in production** — pin to specific versions for reproducibility and to avoid surprise breaking changes.

  ```yaml
  image: wordpress:X.Y-phpA.B-fpm  # not wordpress:latest
  ```

- [ ] **Bind container ports to localhost** when Nginx or another reverse proxy handles external access.

  ```yaml
  ports:
    - "127.0.0.1:9000:9000"
  ```

- [ ] **Schedule weekly Docker image cleanup** to prevent disk bloat.

  Old image layers accumulate silently with every `docker compose pull` — images that are replaced by newer pulls are not automatically removed. On a VPS with a small disk, this fills the disk over weeks or months, eventually causing MariaDB write failures, log suppression, or container startup failures.

  ```bash
  # /etc/cron.weekly/docker-prune
  #!/bin/bash
  docker image prune -f >> /var/log/docker-prune.log 2>&1
  ```

  ```bash
  chmod +x /etc/cron.weekly/docker-prune
  ```

  > **`docker image prune -f` removes only dangling images** — untagged layers no longer referenced by any running or stopped container. It will not remove images for running containers. For a more aggressive cleanup after confirmed-clean deploys, `docker image prune -a -f` also removes stopped images; use with care since it requires re-pulling everything on the next deploy.

- [ ] **Audit running containers regularly.**

  ```bash
  docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"
  docker inspect CONTAINER_NAME | grep -E "Privileged|SecurityOpt"
  ```

---

## 7. System Updates

> Unpatched systems are the most common vector in breaches. Automate where possible, but verify automation is actually working.

- [ ] **Enable unattended-upgrades** for security patches.

  ```bash
  apt install unattended-upgrades -y
  dpkg-reconfigure --priority=low unattended-upgrades
  ```

- [ ] **Verify unattended-upgrades config** in `/etc/apt/apt.conf.d/50unattended-upgrades`:

  ```
  Unattended-Upgrade::Allowed-Origins {
      "${distro_id}:${distro_codename}-security";
  };
  Unattended-Upgrade::AutoFixInterruptedDpkg "true";
  Unattended-Upgrade::Remove-Unused-Dependencies "true";
  Unattended-Upgrade::Automatic-Reboot "false";  // Review reboots manually
  ```

- [ ] **Check update logs** periodically.

  ```bash
  cat /var/log/unattended-upgrades/unattended-upgrades.log
  ```

- [ ] **Manually review and apply kernel updates** on a planned schedule (requires reboot).

  ```bash
  apt list --upgradable 2>/dev/null | grep linux-image
  ```

- [ ] **Update Docker and containerd** on a regular schedule — they are not covered by standard apt security updates in all configurations.

  ```bash
  apt update && apt upgrade docker-ce docker-ce-cli containerd.io
  ```

- [ ] **Subscribe to security advisories** for your major dependencies (Docker, Nginx, PHP, WordPress).

---

## 8. Attack Surface Reduction

> Every running service, loaded kernel module, and installed package is potential attack surface. The less that runs, the less can be exploited.

### Disable Unused Services

- [ ] **Audit all running services** — identify what each one does before disabling.

  ```bash
  systemctl list-units --type=service --state=running
  ```

- [ ] **Disable services that have no purpose on a server VPS.** Common candidates:

  ```bash
  # Printing system — no printers on a server
  systemctl disable --now cups cups-browsed 2>/dev/null || true

  # Avahi mDNS — useful on local networks, not on a VPS
  systemctl disable --now avahi-daemon 2>/dev/null || true

  # RPC portmapper — only needed for NFS/NIS
  systemctl disable --now rpcbind 2>/dev/null || true

  # Bluetooth — no hardware, no need
  systemctl disable --now bluetooth 2>/dev/null || true

  # ModemManager — no modems on a VPS
  systemctl disable --now ModemManager 2>/dev/null || true
  ```

  > **Verify before disabling:** Check `systemctl status SERVICE` to confirm nothing you care about depends on it.

- [ ] **Remove packages you do not use.**

  ```bash
  # Telnet and FTP clients/servers — insecure, use SSH/SFTP instead
  apt purge telnet ftp lftp vsftpd proftpd-* 2>/dev/null || true
  ```

  > **On Docker servers, do not remove gcc/make from the host.** It is sometimes recommended that removing compilers prevents attackers from compiling exploits after gaining access. On a Docker server, this provides minimal protection: an attacker operating through a container exploit can download pre-compiled binaries, compile inside the container's build environment, or use exploitation tools that require no compilation. Meanwhile, removing host compilers breaks system package hooks, kernel module builds, and many debugging workflows. The cost is real; the benefit is not.

### Kernel Module Blacklisting

- [ ] **Blacklist truly unused filesystem modules** — but check before you do.

  Create `/etc/modprobe.d/blacklist-rare-filesystems.conf`:

  ```
  # Rarely-used filesystems — check before adding squashfs/udf (see notes below)
  install cramfs /bin/false
  install freevxfs /bin/false
  install jffs2 /bin/false
  install hfs /bin/false
  install hfsplus /bin/false
  ```

  > **Do not blacklist squashfs on Ubuntu 22/24 if snap is installed.** Snap packages are squashfs images — blacklisting squashfs breaks all snap-based software (including snapd itself). Check first: `snap list`. If snap is in use, leave squashfs alone.
  >
  > **Do not blacklist udf if you ever need to mount ISO files or DVDs.** UDF is the filesystem used by most modern ISO images.
  >
  > **Why `install X /bin/false`?** More effective than `blacklist X`. The blacklist directive can be overridden by explicit `modprobe X`. The `install` directive replaces the install command itself.

- [ ] **Blacklist USB storage** if the server has physical USB ports and you never mount USB drives.

  Create `/etc/modprobe.d/blacklist-usb-storage.conf`:

  ```
  install usb-storage /bin/false
  ```

- [ ] **Disable IPv6** if you are not using it. An unused network stack is an unnecessary attack surface.

  Add to `/etc/sysctl.d/99-hardening.conf`:

  ```ini
  net.ipv6.conf.all.disable_ipv6 = 1
  net.ipv6.conf.default.disable_ipv6 = 1
  net.ipv6.conf.lo.disable_ipv6 = 1
  ```

  Apply: `sysctl -p /etc/sysctl.d/99-hardening.conf`

  > **Check first:** Run `ip -6 addr` to verify you are not actually using IPv6. If your server has IPv6 addresses that you use for anything, do not disable it.

---

## 9. Filesystem Hardening

> Restricting what can execute in temporary directories removes a major post-exploitation staging area. Attackers commonly write and execute malware in `/tmp`, `/dev/shm`, and `/var/tmp`.

### Mount Options for Temporary Filesystems

- [ ] **Add security mount options** to `/etc/fstab` for temporary directories.

  ```
  # /tmp — no executable files, no SUID, no device files
  tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0

  # /dev/shm — shared memory, often used for staging
  tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec 0 0

  # /var/tmp — persists across reboots, same restrictions
  # If /var/tmp is on a separate partition:
  /dev/sda3 /var/tmp ext4 defaults,nosuid,nodev,noexec 0 2
  ```

  Apply without rebooting:

  ```bash
  mount -o remount /tmp
  mount -o remount /dev/shm
  ```

  > **Verify Docker compatibility:** Some Docker operations write to `/tmp`. Test your Docker compose stack after applying these restrictions. If containers fail to start, you may need to leave `/tmp` executable and instead restrict `/dev/shm` only.

- [ ] **Verify restrictions are applied.**

  ```bash
  # Try to execute a script in /tmp — should fail
  echo '#!/bin/bash; echo ok' > /tmp/test.sh
  chmod +x /tmp/test.sh
  /tmp/test.sh
  # Expected: Permission denied or "cannot execute binary file"
  rm /tmp/test.sh
  ```

### Protecting Critical System Files

- [ ] **Set a restrictive umask** for newly created files.

  Add to `/etc/profile` or `/etc/bash.bashrc`:

  ```bash
  umask 027
  ```

  This means new files are `640` (owner read/write, group read, world none) and new directories are `750`.

- [ ] **Verify no world-writable directories exist outside of /tmp.**

  ```bash
  find / -xdev -type d -perm -0002 2>/dev/null | grep -v "^/tmp\|^/var/tmp\|^/dev"
  ```

---

## 10. Backup Strategy

> A backup that has never been tested is not a backup. Backups on the same disk as the data are not backups.

- [ ] **Define what needs backing up:**
  - Database dumps (not just volume files — a running DB file copy may be corrupt)
  - Uploaded files / media
  - Configuration files (`docker-compose.yml`, `.env`, Nginx config)
  - SSL certificates (if not using auto-renew)

- [ ] **Create a backup script that dumps and compresses the database in one step.**

  ```bash
  docker exec MARIADB_CONTAINER mysqldump -u root -p"$DB_ROOT_PASS" \
    --single-transaction --all-databases \
    | gzip > /backups/db-$(date +%Y%m%d).sql.gz
  ```

  > Pipe directly through gzip — do not create an intermediate `.sql` file and compress later. If you create `.sql` and then `.sql.gz`, integrity checks on the `.gz` cannot catch truncation or corruption that happened during the mysqldump step.

- [ ] **Compress and timestamp uploads.**

  ```bash
  tar -czf /backups/uploads-$(date +%Y%m%d).tar.gz /var/www/html/wp-content/uploads
  ```

- [ ] **Rotate local backups** — keep 7 daily, 4 weekly. Never let backups fill your disk.

  ```bash
  find /backups -name "*.sql.gz" -mtime +7 -delete
  ```

- [ ] **Verify backup integrity** before relying on it. Verify the same artifact you actually created.

  ```bash
  gzip -t /backups/db-$(date +%Y%m%d).sql.gz && echo "OK" || echo "CORRUPT"
  ```

- [ ] **Pull backups offsite** — from a second server or your local machine, not pushed from the production server.

  ```bash
  # From your backup machine:
  rsync -avz deploy@PROD_SERVER:/backups/ /local/backup-storage/
  ```

  > **Why pull not push?** If the production server is compromised, an attacker could push corrupted or malicious backups. A pull-based system means the attacker cannot overwrite your backup storage.

- [ ] **Encrypt backups at rest** using restic or borg. Plain-text database dumps expose credentials to anyone who gains access to your backup storage.

  ```bash
  # Install restic
  apt install restic -y

  # Initialize a local encrypted repository
  restic init --repo /opt/backups/encrypted-repo
  # Enter a strong passphrase — store it in a password manager, not on the server

  # Back up database dump + uploads
  restic backup --repo /opt/backups/encrypted-repo \
    /tmp/db-dump.sql.gz \
    /var/www/html/wp-content/uploads

  # List snapshots
  restic snapshots --repo /opt/backups/encrypted-repo

  # Restore a snapshot
  restic restore latest --repo /opt/backups/encrypted-repo --target /tmp/restore/
  ```

  > **Store the passphrase off-server.** A backup you can't decrypt is useless. The passphrase should be in your password manager and tested during quarterly restore drills.

- [ ] **Follow the 3-2-1 rule:** 3 copies, 2 different media/locations, 1 offsite.

  Example: local disk + VPS provider's backup service + your local machine. A ransomware attack that encrypts your VPS cannot touch your local machine's copy.

- [ ] **Test restores** at least once per quarter. A restore drill uncovers issues before you actually need it.

- [ ] **Schedule backups via cron.**

  ```bash
  # /etc/cron.d/backup
  0 3 * * * root /usr/local/bin/backup.sh >> /var/log/backup.log 2>&1
  ```

---

## 11. Monitoring

> You cannot respond to incidents you do not know about. Set up basic alerting on day one.

- [ ] **Configure logrotate** for all service logs. Left unmanaged, logs can fill your disk and crash your database — a simple DoS vector.

  **Nginx** (`/etc/logrotate.d/nginx`):
  ```
  /var/log/nginx/*.log {
      daily
      missingok
      rotate 14
      compress
      delaycompress
      notifempty
      sharedscripts
      postrotate
          nginx -s reopen 2>/dev/null || true
      endscript
  }
  ```

  **Auth log** (`/etc/logrotate.d/auth-log`):
  ```
  /var/log/auth.log {
      weekly
      missingok
      rotate 8
      compress
      delaycompress
      notifempty
  }
  ```

  **fail2ban** (`/etc/logrotate.d/fail2ban-log`):
  ```
  /var/log/fail2ban.log {
      weekly
      missingok
      rotate 8
      compress
      delaycompress
      notifempty
      postrotate
          fail2ban-client flushlogs 2>/dev/null || true
      endscript
  }
  ```

  **Application/Docker logs** — if your app writes to a file (not just Docker's log driver):
  ```
  /var/www/html/wp-content/debug.log {
      weekly
      missingok
      rotate 4
      compress
      notifempty
  }
  ```

  Test all logrotate configs:
  ```bash
  logrotate --debug /etc/logrotate.conf
  ```

- [ ] **Set up disk space alerting.** A full disk will kill your database and crash your app silently.

  ```bash
  # Simple cron-based alert
  df -h / | awk 'NR==2{if($5+0 > 80) print "ALERT: Disk " $5 " full on " ENVIRON["HOSTNAME"]}' \
    | mail -s "Disk Alert" admin@yourdomain.com
  ```

- [ ] **Configure Docker container health checks** so your orchestration knows when a container is sick.

  ```yaml
  healthcheck:
    test: ["CMD", "curl", "-f", "http://localhost/health"]
    interval: 30s
    timeout: 10s
    retries: 3
    start_period: 40s
  ```

- [ ] **Set up uptime monitoring** using an external service (UptimeRobot free tier, BetterUptime, etc.) — this catches issues your on-server monitoring cannot.

- [ ] **Monitor fail2ban** for unusual ban rates (may indicate an active attack).

  ```bash
  fail2ban-client status
  ```

- [ ] **Review auth logs** weekly.

  ```bash
  grep "Failed password\|Invalid user\|Accepted publickey" /var/log/auth.log | tail -50
  ```

- [ ] **Set up email alerts for cron job failures.** Add `MAILTO=admin@yourdomain.com` to your crontab.

---

## 12. Incident Response Quick Reference

> When something goes wrong, slow and methodical beats fast and chaotic.

- [ ] **Do not panic-reboot.** Rebooting destroys in-memory evidence (running processes, network connections, bash history).

- [ ] **Isolate first if breach is confirmed.** Block inbound traffic at the firewall level while you investigate.

  ```bash
  ufw default deny incoming
  ufw reload
  ```

- [ ] **Capture current state before making changes.**

  ```bash
  # Who is logged in?
  who; w; last | head -20

  # What processes are running?
  ps aux --sort=-%cpu | head -20

  # What network connections exist?
  ss -tlnp; ss -tnp

  # What files were recently modified?
  find /var/www /etc -mtime -1 -type f 2>/dev/null

  # Check bash history for all users
  cat /root/.bash_history
  cat /home/deploy/.bash_history
  ```

- [ ] **Check for unauthorized SSH keys.**

  ```bash
  find /home /root -name "authorized_keys" -exec cat {} \;
  ```

- [ ] **Check for unauthorized cron jobs.**

  ```bash
  crontab -l
  cat /etc/cron.d/*
  ls /var/spool/cron/crontabs/
  ```

- [ ] **Rotate all credentials** after a confirmed breach: SSH keys, database passwords, application secrets, API keys.

- [ ] **Restore from a known-good backup** rather than trying to clean an infected system — cleaning is error-prone.

- [ ] **Document the timeline** of what happened and what you found. This is required for any regulatory notification and helps you prevent recurrence.

---

*Last reviewed: 2025 | Applies to: Debian-based Linux distributions (Ubuntu LTS, Debian stable)*
