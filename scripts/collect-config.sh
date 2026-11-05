#!/usr/bin/env bash
#
# collect-config.sh - READ-ONLY white-box configuration collector
#
# Part of server-hardening-guides. See whitebox-audit.md for what each
# collected file means and how to turn the output into findings.
#
# READ-ONLY STATEMENT
#   This script does not change any configuration, package, service,
#   firewall rule, container, or database. It only runs commands that print
#   state (sshd -T, nginx -T, php -i, php-fpm -tt, ss, ufw status,
#   iptables -S, docker inspect, SHOW GRANTS, sysctl -n, and similar).
#   It writes files ONLY inside the output directory. It makes NO network
#   calls to third parties. Known side effects, all outside our control:
#     - `nginx -T` and `php-fpm -tt` parse the config the same way a reload
#       would, which opens the configured log files for append (and can
#       create them if missing). Set AUDIT_NO_CONFIG_TEST=1 to read the
#       config files with `cat` instead.
#     - `docker exec` creates an exec instance, visible in `docker events`.
#     - MySQL/MariaDB queries are SELECT / SHOW only and appear in the
#       general log if it is enabled.
#     - `iptables -S` on a host that does not use iptables yet can load the
#       ip_tables kernel modules.
#
# SECRETS
#   Every collected file is passed through a sed redaction filter that
#   replaces values of keys that look like passwords, secrets, tokens, API
#   keys, private keys, DSN passwords, and Authorization headers with
#   [REDACTED]. Container environment variables are collected as NAMES only,
#   and the Environment / PHP Variables sections of `php -i` keep names only.
#   Redaction is best effort: review the output before it leaves the host.
#
# USAGE
#   sudo bash collect-config.sh [OUTPUT_DIR]
#
#   OUTPUT_DIR defaults to ./audit-<hostname>-<YYYYMMDD>. It must not exist,
#   or be an empty directory owned by the invoking user (not a symlink).
#   Files are created with umask 077. Under sudo, AUDIT_* variables are
#   dropped by env_reset unless sudoers keeps them (see whitebox-audit.md).
#
# ENVIRONMENT
#   AUDIT_TIMEOUT=30            per-command timeout in seconds
#   AUDIT_ALLOWED_PORTS="80 443" ports allowed on 0.0.0.0 / [::] (SSH ports
#                               from `sshd -T` are added automatically)
#   AUDIT_NO_CONFIG_TEST=1      read nginx / php-fpm config files with cat
#                               instead of running nginx -T / php-fpm -tt
#   AUDIT_SKIP_DOCKER=1         do not inspect or exec into containers
#   AUDIT_SKIP_MYSQL=1          do not query MySQL / MariaDB
#
# TESTED TARGETS
#   Ubuntu 22.04 and 24.04, bash 5.x, GNU sed/awk/coreutils.
#
# EXIT CODE
#   0 when collection finished (even with FAIL findings), 1 on usage error.

set -u
umask 077
export LC_ALL=C

HOST_SHORT=$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo host)
OUT=${1:-./audit-${HOST_SHORT}-$(date +%Y%m%d)}
T=${AUDIT_TIMEOUT:-30}
ALLOWED_PORTS=${AUDIT_ALLOWED_PORTS:-80 443}
NO_TEST=${AUDIT_NO_CONFIG_TEST:-0}
SKIP_DOCKER=${AUDIT_SKIP_DOCKER:-0}
SKIP_MYSQL=${AUDIT_SKIP_MYSQL:-0}

# Refuse anything another user could have prepared (symlinks planted in a
# shared directory would otherwise redirect root's writes).
if [ -e "$OUT" ] || [ -L "$OUT" ]; then
  if [ -L "$OUT" ] || [ ! -d "$OUT" ] || [ ! -O "$OUT" ] || [ -n "$(ls -A -- "$OUT" 2>/dev/null)" ]; then
    echo "Output path $OUT exists and is not an empty directory owned by you. Pass a new path." >&2
    exit 1
  fi
  chmod 700 -- "$OUT" || exit 1
else
  if ! { mkdir -p -- "$(dirname -- "$OUT")" && mkdir -m 700 -- "$OUT"; }; then
    echo "Cannot create $OUT" >&2; exit 1
  fi
fi
FINDINGS="$OUT/findings.txt"
: > "$FINDINGS"

have() { command -v "$1" >/dev/null 2>&1; }

TO=()
if have timeout; then TO=(timeout -k 5 "$T"); fi

# ---------------------------------------------------------------------------
# Redaction. Applied to every file written by run(). Keeps values that start
# with "/" (file paths such as ssl_certificate_key) so evidence stays useful.
# ---------------------------------------------------------------------------
REDACT_PROG=$(cat <<'SED'
s#(-----BEGIN [A-Z ]*PRIVATE KEY-----).*#\1 [REDACTED]#
s#([A-Za-z][A-Za-z0-9+.-]*://[^:/@[:space:]"']*):[^@[:space:]"']+@#\1:[REDACTED]@#g
s#(IDENTIFIED[[:space:]]+(BY[[:space:]]+PASSWORD|BY|VIA[[:space:]]+[A-Za-z_]+[[:space:]]+USING|WITH[[:space:]]+[A-Za-z_]+[[:space:]]+(AS|BY))[[:space:]]+)'[^']*'#\1'[REDACTED]'#Ig
s#(USING[[:space:]]+)'[^']*'#\1'[REDACTED]'#Ig
s#((set|env|fastcgi_param|uwsgi_param|scgi_param|proxy_set_header)[[:space:]]+[$]?[A-Za-z0-9_.-]*(pass|pwd|_pw|secret|token|key|salt|credential|auth)[A-Za-z0-9_.-]*[[:space:]]+)("[^"]*"|'[^']*'|[^;[:space:]]+)#\1[REDACTED]#Ig
s#((proxy-)?(authorization|x-api-key|api-key|cookie)["']?:?[[:space:]]+)("[^"]*"|'[^']*'|((basic|bearer|token|digest)[[:space:]]+)?[^;[:space:]]+)#\1[REDACTED]#Ig
s#('[A-Za-z0-9_.-]*(pass|pwd|_pw|secret|token|key|credential)[A-Za-z0-9_.-]*',[[:space:]]*)'[^']*'#\1'[REDACTED]'#Ig
s#(^|[[:space:]?&;{(])([][A-Za-z0-9_.$'"-]*(pass|pwd|_pw|secret|token|api_?key|apikey|access_?key|private_?key|app_?key|auth_?key|_key|salt|credential)[][A-Za-z0-9_.'"-]*[[:space:]]*=>[[:space:]]*).*#\1\2[REDACTED]#Ig
s#(^|[[:space:]?&;{(])([][A-Za-z0-9_.$'"-]*(pass|pwd|_pw|secret|token|api_?key|apikey|access_?key|private_?key|app_?key|auth|_key|salt|credential)[][A-Za-z0-9_.'"-]*[[:space:]]*[=:][[:space:]]*)("[^"]*"|'[^']*'|[^/>[:space:]"',;][^[:space:]"',;]*)#\1\2[REDACTED]#Ig
SED
)
# `php -i` prints the whole process environment (in a container: every
# secret passed with -e or env_file). Keep names, drop values, in those sections.
# shellcheck disable=SC2016  # awk program, not shell
REDACT_ENV_AWK='
/^(Environment|PHP Variables)$/ { env = 1; print; next }
/^PHP License$/ { env = 0 }
env && index($0, " => ") { print substr($0, 1, index($0, " => ") + 3) "[REDACTED]"; next }
{ print }'
redact() { awk "$REDACT_ENV_AWK" | sed -E "$REDACT_PROG"; }

# run FILE CMD [ARGS...] : run a read-only command with a timeout, redact,
# and save stdout+stderr under $OUT/FILE.
run() {
  local f="$OUT/$1"; shift
  mkdir -p "$(dirname "$f")"
  {
    printf '# command: %s\n' "$*"
    if [ "$(type -t "$1")" = function ]; then
      "$@" 2>&1
    else
      ${TO[@]+"${TO[@]}"} "$@" 2>&1
    fi
    printf '# exit: %s\n' "$?"
  } | redact > "$f"
}

# Record a finding. Levels: FAIL (clear checklist violation), WARN (needs a
# human decision), INFO (context for the report).
# Text can come from container output: strip control characters so the
# summary printed to the terminal cannot carry escape sequences.
finding() { printf '%-4s [%s] %s\n' "$1" "$2" "$3" | tr -d '\000-\010\013-\037\177' >> "$FINDINGS"; }

section() { printf '== %s\n' "$1" >&2; }

# Port allowed on a wildcard address?
port_allowed() {
  local p
  for p in $ALLOWED_PORTS $SSH_PORTS; do [ "$1" = "$p" ] && return 0; done
  return 1
}

# Compare two dotted versions: ver_lt A B is true when A < B.
ver_lt() {
  [ "$1" = "$2" ] && return 1
  [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$1" ]
}

if [ "$(id -u)" -ne 0 ]; then
  echo "WARNING: not running as root. sshd -T, iptables, docker, and MySQL socket" >&2
  echo "auth usually need root. Results will be incomplete." >&2
  finding INFO host "Collector ran without root; some checks are incomplete"
fi

# ===========================================================================
# 1. System
# ===========================================================================
section "system"
run system/os-release.txt cat /etc/os-release
run system/uname.txt uname -a
run system/uptime.txt uptime
have ssh && run system/ssh-version.txt ssh -V
have dpkg-query && run system/openssh-server-pkg.txt dpkg-query -W openssh-server
have apt && run system/apt-upgradable.txt apt list --upgradable
[ -f /var/run/reboot-required ] && finding WARN updates "Reboot required (/var/run/reboot-required present): patched kernel or libraries not yet running"

# ===========================================================================
# 2. SSH (linux-server-hardening.md section 2)
# ===========================================================================
section "ssh"
SSH_PORTS=""
if have sshd || [ -x /usr/sbin/sshd ]; then
  SSHD=$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd)
  run ssh/sshd-T.txt "$SSHD" -T
  S="$OUT/ssh/sshd-T.txt"
  sv() { awk -v k="$1" '$1==k {print $2; exit}' "$S"; }
  SSH_PORTS=$(awk '$1=="port" {print $2}' "$S" | tr '\n' ' ')
  [ "$(sv permitrootlogin)" = "yes" ] && finding FAIL ssh "PermitRootLogin yes"
  [ "$(sv passwordauthentication)" = "yes" ] && finding FAIL ssh "PasswordAuthentication yes"
  [ "$(sv permitemptypasswords)" = "yes" ] && finding FAIL ssh "PermitEmptyPasswords yes"
  if [ "$(sv kbdinteractiveauthentication)" = "yes" ] && [ "$(sv usepam)" = "yes" ]; then
    finding WARN ssh "KbdInteractiveAuthentication yes with UsePAM yes: password login may still work via PAM"
  fi
  [ "$(sv x11forwarding)" = "yes" ] && finding WARN ssh "X11Forwarding yes"
  MAT=$(sv maxauthtries)
  [ -n "$MAT" ] && [ "$MAT" -gt 3 ] 2>/dev/null && finding WARN ssh "MaxAuthTries $MAT (checklist: 3)"
  grep -qiE '^[[:space:]]*Match[[:space:]]' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
    && finding INFO ssh "sshd_config has Match blocks; sshd -T shows the default context only (re-check with sshd -T -C user=...,host=...,addr=...)"
  # Authorized keys: fingerprints only, never key material.
  {
    for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
      [ -f "$f" ] || continue
      echo "== $f"
      ssh-keygen -lf "$f" 2>&1
    done
  } > "$OUT/ssh/authorized-keys-fingerprints.txt"
else
  finding INFO ssh "sshd not found"
fi

# ===========================================================================
# 3. Firewall and listening sockets (linux-server-hardening.md section 3)
# ===========================================================================
section "firewall"
if have ufw; then
  run firewall/ufw-status.txt ufw status verbose
  grep -q '^Status: inactive' "$OUT/firewall/ufw-status.txt" && finding FAIL firewall "UFW is inactive (check firewall/nft-ruleset.txt for another firewall before rating)"
else
  finding WARN firewall "ufw not installed"
fi
if have iptables; then
  run firewall/iptables-S.txt iptables -S
  run firewall/iptables-DOCKER-USER.txt iptables -S DOCKER-USER
fi
have ip6tables && run firewall/ip6tables-DOCKER-USER.txt ip6tables -S DOCKER-USER
have nft && run firewall/nft-ruleset.txt nft list ruleset

if have ss; then
  run network/ss-tlnp.txt ss -H -tlnp
  run network/ss-ulnp.txt ss -H -ulnp
  while read -r _ _ _ local _ rest; do
    [ -n "${local:-}" ] || continue
    port=${local##*:}
    addr=${local%:*}
    addr=${addr%%%*}
    proc=$(printf '%s' "$rest" | sed -n 's/.*users:((\("[^"]*"\).*/\1/p')
    case "$addr" in
      127.*|'[::1]'|'::1') continue ;;
      0.0.0.0|'*'|'[::]'|'::')
        port_allowed "$port" || finding FAIL network "Port $port listens on all interfaces ($addr) via $proc; not in allowed list ($ALLOWED_PORTS $SSH_PORTS)" ;;
      *)
        port_allowed "$port" || finding WARN network "Port $port listens on $addr via $proc; confirm this interface is not public" ;;
    esac
  done < <(grep -v '^#' "$OUT/network/ss-tlnp.txt")
fi

# ===========================================================================
# 4. Kernel sysctl (linux-server-hardening.md section 5)
# ===========================================================================
section "sysctl"
{
  while read -r key want; do
    [ -n "$key" ] || continue
    got=$(sysctl -n "$key" 2>/dev/null || echo "n/a")
    printf '%s = %s (expected %s)\n' "$key" "$got" "$want"
    [ "$got" = "n/a" ] && continue
    [ "$got" = "$want" ] || finding WARN sysctl "$key = $got (checklist: $want)"
  done <<'EOF'
kernel.yama.ptrace_scope 1
kernel.kptr_restrict 2
fs.suid_dumpable 0
net.ipv4.tcp_syncookies 1
net.ipv4.conf.all.rp_filter 1
net.ipv4.conf.default.rp_filter 1
kernel.sysrq 0
net.ipv4.icmp_echo_ignore_broadcasts 1
net.ipv4.icmp_ignore_bogus_error_responses 1
net.ipv4.conf.all.accept_source_route 0
net.ipv4.conf.default.accept_source_route 0
net.ipv4.conf.all.accept_redirects 0
net.ipv4.conf.default.accept_redirects 0
net.ipv6.conf.all.accept_redirects 0
net.ipv4.conf.all.send_redirects 0
kernel.dmesg_restrict 1
EOF
} > "$OUT/system/sysctl.txt"

# ===========================================================================
# 5. Updates (linux-server-hardening.md section 7)
# ===========================================================================
section "updates"
if have apt-config; then
  run updates/apt-periodic.txt apt-config dump APT::Periodic
  grep -q 'APT::Periodic::Unattended-Upgrade "1"' "$OUT/updates/apt-periodic.txt" \
    || finding FAIL updates "APT::Periodic::Unattended-Upgrade is not \"1\": security updates are not applied automatically"
  run updates/apt-unattended.txt apt-config dump Unattended-Upgrade
fi
if have systemctl; then
  run updates/systemd-units.txt systemctl is-enabled unattended-upgrades.service apt-daily-upgrade.timer
fi
[ -r /var/log/unattended-upgrades/unattended-upgrades.log ] \
  && run updates/unattended-upgrades-log-tail.txt tail -n 60 /var/log/unattended-upgrades/unattended-upgrades.log

# ===========================================================================
# 6. fail2ban (linux-server-hardening.md section 4)
# ===========================================================================
section "fail2ban"
if have fail2ban-client; then
  run fail2ban/status.txt fail2ban-client status
  run fail2ban/config-dump.txt fail2ban-client -d
  for j in $(sed -n 's/.*Jail list:[[:space:]]*//p' "$OUT/fail2ban/status.txt" | tr ',' ' '); do
    run "fail2ban/jail-$j.txt" fail2ban-client status "$j"
  done
  be=$(sed -n "s/.*\['add', 'sshd', '\([a-z]*\)'\].*/\1/p" "$OUT/fail2ban/config-dump.txt" | head -n1)
  if [ -z "$be" ]; then
    finding WARN fail2ban "No sshd jail configured"
  elif [ "$be" != "systemd" ]; then
    # File backends work only while rsyslog still writes auth.log.
    if [ -n "$(find /var/log/auth.log -mmin -1440 2>/dev/null)" ]; then
      finding WARN fail2ban "sshd jail backend is '$be'; works only while rsyslog writes /var/log/auth.log, backend = systemd is preferred"
    else
      finding FAIL fail2ban "sshd jail backend is '$be' but /var/log/auth.log is missing or stale; sshd logs to journald only, use backend = systemd"
    fi
  fi
else
  finding WARN fail2ban "fail2ban not installed"
fi

# ===========================================================================
# PHP evaluation helpers (wordpress-server-hardening.md section 3)
# ===========================================================================
# ini_get FILE KEY : value column from `php -i` text output
ini_get() { awk -F' => ' -v k="$2" '$1==k {print $2; exit}' "$1"; }

# Pool names and overrides from `php-fpm -tt` output or raw pool files.
pool_names() { grep -v -e '^[[:space:]]*;' -e '=' "$1" | sed -n 's/.*\[\([A-Za-z0-9_.-]*\)\][[:space:]]*$/\1/p' | grep -vx global | sort -u; }
pool_ov() {
  awk -v pool="$2" -v key="$3" '
    /^[[:space:]]*;/ { next }
    match($0, /\[[A-Za-z0-9_.-]+\][[:space:]]*$/) && $0 !~ /=/ {
      p = substr($0, RSTART + 1); sub(/\].*/, "", p); cur = p; next }
    cur == pool && match($0, /php_(admin_)?(value|flag)\[[^]]+\][[:space:]]*=/) {
      s = substr($0, RSTART); k = s; sub(/^[^[]*\[/, "", k); sub(/\].*/, "", k)
      if (k == key) { v = s; sub(/^[^=]*=[[:space:]]*/, "", v); val = v } }
    END { print val }' "$1"
}

is_on() { case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in on|1|yes|true|stdout|stderr) return 0 ;; esac; return 1; }

# php_eval LABEL PHPINFO_FILE TT_FILE SAPI
php_eval() {
  local label=$1 info=$2 tt=$3 sapi=$4 lvl pools pool key v ov df missing fn ver
  [ -s "$info" ] || return 0
  ver=$(sed -n 's/^PHP Version => \([0-9][0-9.]*\).*/\1/p' "$info" | head -n1)
  if [ -n "$ver" ]; then
    finding INFO php "$label: PHP $ver ($sapi)"
    ver_lt "$ver" "8.2" && finding WARN php "$label: PHP $ver is past upstream security support (check distro backports before rating EOL)"
  fi
  lvl=FAIL
  [ "$sapi" = "cli" ] && lvl=WARN
  pools=""
  [ -n "$tt" ] && [ -s "$tt" ] && pools=$(pool_names "$tt")
  [ -n "$pools" ] || pools="(ini)"
  for pool in $pools; do
    for key in expose_php allow_url_include display_errors allow_url_fopen session.cookie_httponly session.use_strict_mode phar.readonly ffi.enable; do
      v=$(ini_get "$info" "$key")
      ov=""
      [ "$pool" != "(ini)" ] && ov=$(pool_ov "$tt" "$pool" "$key")
      [ -n "$ov" ] && v="$ov (pool override)"
      [ -n "$v" ] || continue
      case "$key" in
        expose_php|allow_url_include|display_errors)
          is_on "${v%% *}" && finding "$lvl" php "$label pool=$pool ($sapi): $key = $v" ;;
        allow_url_fopen|ffi.enable)
          is_on "${v%% *}" && finding WARN php "$label pool=$pool ($sapi): $key = $v" ;;
        session.cookie_httponly|session.use_strict_mode|phar.readonly)
          is_on "${v%% *}" || finding WARN php "$label pool=$pool ($sapi): $key = $v" ;;
      esac
    done
    df=$(ini_get "$info" disable_functions)
    [ "$df" = "no value" ] && df=""
    if [ "$pool" != "(ini)" ]; then
      ov=$(pool_ov "$tt" "$pool" disable_functions)
      [ -n "$ov" ] && df="$df,$ov"
    fi
    if [ -z "$df" ]; then
      finding "$lvl" php "$label pool=$pool ($sapi): disable_functions is empty"
    else
      missing=""
      for fn in exec passthru shell_exec system proc_open popen putenv mail dl; do
        printf ',%s,' "$df" | tr -d ' ' | grep -q ",$fn," || missing="$missing $fn"
      done
      [ -n "$missing" ] && finding WARN php "$label pool=$pool ($sapi): disable_functions missing:$missing"
    fi
    v=$(ini_get "$info" open_basedir)
    [ "$pool" != "(ini)" ] && ov=$(pool_ov "$tt" "$pool" open_basedir) && [ -n "$ov" ] && v=$ov
    [ "$v" = "no value" ] && finding WARN php "$label pool=$pool ($sapi): open_basedir not set"
  done
  if is_on "$(ini_get "$info" opcache.enable)" && [ "$(ini_get "$info" opcache.restrict_api)" = "no value" ]; then
    finding WARN php "$label ($sapi): opcache.restrict_api is empty (means no restriction)"
  fi
  if [ "$sapi" = "fpm" ] && grep -q '^Loaded Configuration File => (none)' "$info"; then
    finding WARN php "$label ($sapi): no php.ini loaded, PHP runs on built-in defaults (display_errors=1, expose_php=On)"
  fi
}

# ===========================================================================
# nginx evaluation (wordpress-server-hardening.md section 2, TLS baseline)
# ===========================================================================
nginx_eval() {
  local label=$1 dump=$2 ver=$3 clean
  [ -s "$dump" ] || return 0
  clean="$dump.nocomments"
  sed -e 's/#.*//' "$dump" > "$clean"
  [ -n "$ver" ] && finding INFO nginx "$label: nginx $ver"
  if grep -Eq '(^|[;{[:space:]])server_tokens[[:space:]]+(on|build)' "$clean"; then
    finding FAIL nginx "$label: server_tokens on (version disclosed)"
  elif ! grep -Eq '(^|[;{[:space:]])server_tokens[[:space:]]+off' "$clean"; then
    finding FAIL nginx "$label: server_tokens not set (default is on, version disclosed)"
  fi
  grep -Eq '(^|[;{[:space:]])autoindex[[:space:]]+on' "$clean" && finding FAIL nginx "$label: autoindex on (directory listing)"
  local uses_ssl=0
  grep -Eq '(listen[^;]*[[:space:]]ssl|ssl_certificate[[:space:]])' "$clean" && uses_ssl=1
  local protos
  protos=$(grep -Eo 'ssl_protocols[^;]*' "$clean" | sort -u)
  if [ -n "$protos" ]; then
    printf '%s\n' "$protos" | grep -Eq 'SSLv|TLSv1([^.0-9]|$)|TLSv1\.1' \
      && finding FAIL nginx "$label: ssl_protocols allows TLSv1/TLSv1.1/SSL: $(printf '%s' "$protos" | tr '\n' '|') (Ubuntu OpenSSL SECLEVEL=2 may still refuse them: confirm live with testssl.sh)"
  elif [ "$uses_ssl" = 1 ] && [ -n "$ver" ] && ver_lt "$ver" "1.23.4"; then
    finding FAIL nginx "$label: no ssl_protocols set and nginx $ver default includes TLSv1 and TLSv1.1"
  fi
  grep -Eo 'ssl_ciphers[^;]*' "$clean" | grep -Eiq '(^|[: ])(RC4|3DES|DES-CBC3|MD5|NULL|EXPORT|aNULL|eNULL)' \
    && finding WARN nginx "$label: ssl_ciphers enables weak ciphers (only !-prefixed entries are exclusions)"
  grep -Eq 'ssl_stapling[[:space:]]+on' "$clean" \
    && finding WARN nginx "$label: ssl_stapling on; Let's Encrypt ended OCSP in 2025 so stapling does nothing for LE certs (expect 'ssl_stapling ignored' warnings)"
  if [ "$uses_ssl" = 1 ] && ! grep -Eiq 'add_header[[:space:]]+["'\'']?strict-transport-security' "$clean"; then
    finding WARN nginx "$label: TLS in use but no Strict-Transport-Security header in nginx (check if set at a CDN edge)"
  fi
  # add_header inheritance trap: a block with its own add_header drops all
  # headers from the nearest ancestor that defines them.
  awk -v q="'" '
    function hdrset(a,  i) { for (i = a; i >= 1; i--) if (hdr[i] != "") return i; return 0 }
    function merged(a,  i) { for (i = a; i >= 1; i--) if (inh[i] != "") return inh[i] == "merge"; return 0 }
    /^# configuration file / { f = $4; sub(/:$/, "", f); next }
    {
      line = $0
      gsub(/"[^"]*"/, "Q", line); gsub(q "[^" q "]*" q, "Q", line); sub(/#.*/, "", line)
      while (length(line) > 0) {
        if (!match(line, /[{};]/)) { stmt = stmt " " line; break }
        stmt = stmt " " substr(line, 1, RSTART - 1); ch = substr(line, RSTART, 1); line = substr(line, RSTART + 1)
        gsub(/^[ \t]+|[ \t]+$/, "", stmt)
        if (ch == "{") { d++; name[d] = stmt; hdr[d] = ""; inh[d] = ""; where[d] = f " (dump line " NR ")" }
        else if (ch == ";") {
          n = split(stmt, w, /[ \t]+/)
          if (w[1] == "add_header") hdr[d] = hdr[d] " " tolower(w[2]) " "
          if (w[1] == "add_header_inherit") inh[d] = w[2]
        } else if (ch == "}") {
          if (hdr[d] != "" && !merged(d)) {
            a = hdrset(d - 1)
            if (a > 0) {
              miss = ""; m = split(hdr[a], pw, " ")
              for (i = 1; i <= m; i++) if (index(hdr[d], " " pw[i] " ") == 0) miss = miss " " pw[i]
              if (miss != "") printf "%s: \"%s\" has its own add_header and drops:%s\n", where[d], name[d], miss
            }
          }
          d--
        }
        stmt = ""
      }
    }' "$dump" > "$dump.add_header-inheritance.txt"
  if [ -s "$dump.add_header-inheritance.txt" ]; then
    while read -r l; do finding FAIL nginx "$label: add_header inheritance: $l"; done < "$dump.add_header-inheritance.txt"
  fi
}

# Fallback for AUDIT_NO_CONFIG_TEST=1: emulate `nginx -T` file markers.
cat_conf_tree() {
  find "$@" -type f \( -name '*.conf' -o -path '*/sites-enabled/*' -o -name nginx.conf \) 2>/dev/null \
    | sort | while read -r f; do printf '# configuration file %s:\n' "$f"; cat "$f"; printf '\n'; done
}

# ===========================================================================
# 7. Host PHP, nginx, MySQL
# ===========================================================================
section "host php"
SEEN=" "
for b in /usr/bin/php /usr/bin/php[0-9]* /usr/local/bin/php; do
  [ -x "$b" ] || continue
  rp=$(readlink -f "$b" 2>/dev/null || echo "$b")
  case "$SEEN" in *" $rp "*) continue ;; esac
  SEEN="$SEEN$rp "
  n=$(basename "$b")
  run "php/host-$n-ini.txt" "$b" --ini
  run "php/host-$n-cli-i.txt" "$b" -i
  php_eval "host $n" "$OUT/php/host-$n-cli-i.txt" "" cli
done
for b in /usr/sbin/php-fpm* /usr/local/sbin/php-fpm; do
  [ -x "$b" ] || continue
  n=$(basename "$b")
  run "php/host-$n-i.txt" "$b" -i
  if [ "$NO_TEST" = 1 ]; then
    v=${n#php-fpm}
    { for f in /etc/php/"$v"/fpm/php-fpm.conf /etc/php/"$v"/fpm/pool.d/*.conf /usr/local/etc/php-fpm.conf /usr/local/etc/php-fpm.d/*.conf; do
        [ -f "$f" ] && { printf '; file %s\n' "$f"; cat "$f"; }
      done; } | redact > "$OUT/php/host-$n-pools.txt"
  else
    run "php/host-$n-pools.txt" "$b" -tt
  fi
  php_eval "host $n" "$OUT/php/host-$n-i.txt" "$OUT/php/host-$n-pools.txt" fpm
done

section "host nginx"
if have nginx; then
  run nginx/host-version.txt nginx -V
  NV=$(sed -n 's#.*nginx version: [a-z]*/\([0-9.]*\).*#\1#p' "$OUT/nginx/host-version.txt" | head -n1)
  if [ "$NO_TEST" = 1 ]; then
    cat_conf_tree /etc/nginx | redact > "$OUT/nginx/host-nginx-T.txt"
  else
    run nginx/host-nginx-T.txt nginx -T
  fi
  nginx_eval "host nginx" "$OUT/nginx/host-nginx-T.txt" "$NV"
fi

# ---------------------------------------------------------------------------
# MySQL / MariaDB
# ---------------------------------------------------------------------------
Q_VARS="SHOW GLOBAL VARIABLES WHERE Variable_name IN ('version','version_comment','bind_address','local_infile','secure_file_priv','skip_name_resolve','skip_networking','require_secure_transport','have_ssl','tls_version','general_log','log_error')"
Q_USERS="SELECT user, host, plugin, IF(plugin IN ('unix_socket','auth_socket'),'socket',IF(authentication_string IS NULL OR authentication_string='','EMPTY','set')) AS pw FROM mysql.user"
Q_LIST="SELECT CONCAT(QUOTE(user),'@',QUOTE(host)) FROM mysql.user"
SYSTEM_USERS=" root mysql mysql.sys mysql.session mysql.infoschema mariadb.sys debian-sys-maint healthcheck "

# mysql_eval LABEL DIR IS_HOST
mysql_eval() {
  local label=$1 dir=$2 is_host=$3 u h pl pw v
  if [ -s "$dir/variables.txt" ]; then
    v=$(awk '$1=="local_infile" {print $2}' "$dir/variables.txt")
    [ "$v" = "ON" ] && finding WARN mysql "$label: local_infile = ON"
    awk '$1=="secure_file_priv" {print NF}' "$dir/variables.txt" | grep -qx 1 \
      && finding WARN mysql "$label: secure_file_priv is empty (FILE privilege can read/write anywhere mysqld can)"
    v=$(awk '$1=="bind_address" {print $2}' "$dir/variables.txt")
    if [ "$is_host" = 1 ]; then
      case "$v" in ''|'*'|0.0.0.0|'::') finding WARN mysql "$label: bind_address = '${v:-*}' (listens on all interfaces)" ;; esac
    fi
  fi
  if [ -s "$dir/users.txt" ]; then
    while IFS='|' read -r u h pl pw; do
      case "$u" in '#'*) continue ;; esac
      [ -z "$u" ] && finding FAIL mysql "$label: anonymous user ''@'$h'"
      # Built-in locked accounts have no password by design.
      case "$u" in mysql.sys|mysql.session|mysql.infoschema|mariadb.sys) continue ;; esac
      [ "$pw" = "EMPTY" ] && finding FAIL mysql "$label: user '$u'@'$h' has an empty password (plugin $pl)"
      if [ "$h" = "%" ]; then
        if [ "$u" = "root" ]; then finding FAIL mysql "$label: root@'%' exists"
        else finding WARN mysql "$label: '$u'@'%' accepts connections from any host"; fi
      fi
    done < <(tr '\t' '|' < "$dir/users.txt")
  fi
  if [ -s "$dir/grants.txt" ]; then
    awk -v sys="$SYSTEM_USERS" -v q="'" '
      /^== / { u = $2; sub(/@.*/, "", u); gsub(q, "", u); cur = $2; next }
      index(sys, " " u " ") { next }
      /^GRANT / {
        if ($0 ~ / ON \*\.\* / && $0 ~ /(ALL PRIVILEGES|SUPER|FILE)/) print "FAIL " cur ": " $0
        else if ($0 ~ /ALL PRIVILEGES ON/) print "WARN " cur ": " $0
      }' "$dir/grants.txt" | while read -r lvl rest; do finding "$lvl" mysql "$label: $rest"; done
  fi
}

# mysql_collect LABEL DIR IS_HOST CMD... (CMD runs one query given as last arg)
mysql_collect() {
  local label=$1 dir=$2 is_host=$3; shift 3
  mkdir -p "$dir"
  run "${dir#"$OUT"/}/variables.txt" "$@" "$Q_VARS"
  run "${dir#"$OUT"/}/users.txt" "$@" "$Q_USERS"
  {
    "$@" "$Q_LIST" 2>/dev/null | while read -r acct; do
      case "$acct" in "'"*) ;; *) continue ;; esac
      # Account names are data: anything but plain characters could inject a
      # second statement (newlines, quotes, ;), so it is listed, not queried.
      if ! printf '%s' "$acct" | grep -Eqx "'[A-Za-z0-9_.%:/-]*'@'[A-Za-z0-9_.%:/-]*'"; then
        echo "== SKIPPED account with unusual characters: $acct"
        continue
      fi
      echo "== $acct"
      "$@" "SHOW GRANTS FOR $acct" 2>&1
    done
  } | redact > "$dir/grants.txt"
  mysql_eval "$label" "$dir" "$is_host"
}

section "host mysql"
if [ "$SKIP_MYSQL" != 1 ] && { pgrep -x mysqld >/dev/null 2>&1 || pgrep -x mariadbd >/dev/null 2>&1; }; then
  MC=""
  have mariadb && MC=mariadb
  [ -z "$MC" ] && have mysql && MC=mysql
  if [ -n "$MC" ]; then
    # shellcheck disable=SC2329  # invoked indirectly via mysql_collect
    host_q() {
      if [ -r /etc/mysql/debian.cnf ]; then
        ${TO[@]+"${TO[@]}"} "$MC" --defaults-file=/etc/mysql/debian.cnf --batch --skip-column-names --connect-timeout=5 -e "$1"
      else
        ${TO[@]+"${TO[@]}"} "$MC" --batch --skip-column-names --connect-timeout=5 -e "$1"
      fi
    }
    mysql_collect "host mysql" "$OUT/mysql/host" 1 host_q
  else
    finding INFO mysql "mysqld running on host but no mysql/mariadb client found"
  fi
fi

# ===========================================================================
# 8. Docker (linux-server-hardening.md section 6)
# ===========================================================================
# Runs inside the container with sh; the password is read from the
# container's own environment and never leaves the container.
# shellcheck disable=SC2016
CTR_MYSQL='P="${MYSQL_ROOT_PASSWORD:-${MARIADB_ROOT_PASSWORD:-}}"
[ -z "$P" ] && [ -r "${MYSQL_ROOT_PASSWORD_FILE:-/nonexistent}" ] && P=$(cat "$MYSQL_ROOT_PASSWORD_FILE")
[ -z "$P" ] && [ -r "${MARIADB_ROOT_PASSWORD_FILE:-/nonexistent}" ] && P=$(cat "$MARIADB_ROOT_PASSWORD_FILE")
C=mysql; command -v mariadb >/dev/null 2>&1 && C=mariadb
MYSQL_PWD="$P" exec "$C" -uroot --batch --skip-column-names --connect-timeout=5 -e "$1"'

# shellcheck disable=SC2016
CTR_DETECT='for b in nginx php php-fpm mysqld mariadbd; do command -v "$b" >/dev/null 2>&1 && printf "%s " "$b"; done
for f in /usr/sbin/php-fpm* /usr/local/sbin/php-fpm; do [ -x "$f" ] && printf "fpm:%s " "$f"; done; true'

if [ "$SKIP_DOCKER" != 1 ] && have docker && docker info >/dev/null 2>&1; then
  section "docker"
  run docker/version.txt docker version
  run docker/info.txt docker info
  run docker/ps.txt docker ps --no-trunc --format '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
  run docker/images.txt docker images --digests --format '{{.Repository}}:{{.Tag}}\t{{.Digest}}\t{{.CreatedSince}}'
  [ -r /etc/docker/daemon.json ] && run docker/daemon.json.txt cat /etc/docker/daemon.json
  getent group docker > "$OUT/docker/docker-group.txt" 2>&1
  m=$(cut -d: -f4 "$OUT/docker/docker-group.txt")
  [ -n "$m" ] && finding INFO docker "Members of the docker group (root-equivalent): $m"

  # shellcheck disable=SC2016  # Go template, not shell
  DFMT='name={{.Name}}
image={{.Config.Image}}
privileged={{.HostConfig.Privileged}}
readonly_rootfs={{.HostConfig.ReadonlyRootfs}}
user={{.Config.User}}
cap_add={{json .HostConfig.CapAdd}}
cap_drop={{json .HostConfig.CapDrop}}
security_opt={{json .HostConfig.SecurityOpt}}
network_mode={{.HostConfig.NetworkMode}}
pid_mode={{.HostConfig.PidMode}}
ipc_mode={{.HostConfig.IpcMode}}
memory_limit={{.HostConfig.Memory}}
restart={{.HostConfig.RestartPolicy.Name}}
ports={{range $p, $b := .NetworkSettings.Ports}}{{range $b}}{{$p}}={{.HostIp}}:{{.HostPort}} {{end}}{{end}}
mounts={{range .Mounts}}{{.Source}}:{{.Destination}}:rw={{.RW}} {{end}}'

  for id in $(docker ps -q); do
    cname=$(docker inspect --format '{{.Name}}' "$id" 2>/dev/null | sed 's#^/##')
    [ -n "$cname" ] || continue
    d="docker/$cname"
    run "$d/inspect.txt" docker inspect --format "$DFMT" "$id"
    docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$id" 2>/dev/null \
      | sed 's/=.*//' > "$OUT/$d/env-names.txt"
    I="$OUT/$d/inspect.txt"
    # last match: the first one is the echoed --format template in the header
    iv() { sed -n "s/^$1=//p" "$I" | tail -n1; }
    [ "$(iv privileged)" = "true" ] && finding FAIL docker "$cname: privileged container"
    printf '%s' "$(iv cap_add)" | grep -Eq 'ALL|SYS_ADMIN|SYS_PTRACE|SYS_MODULE|NET_ADMIN|DAC_READ_SEARCH' \
      && finding FAIL docker "$cname: dangerous capability added: $(iv cap_add)"
    printf '%s' "$(iv security_opt)" | grep -q 'seccomp[:=]unconfined' && finding FAIL docker "$cname: seccomp unconfined"
    printf '%s' "$(iv security_opt)" | grep -q 'apparmor[:=]unconfined' && finding WARN docker "$cname: apparmor unconfined"
    printf '%s' "$(iv security_opt)" | grep -q 'no-new-privileges' || finding WARN docker "$cname: no-new-privileges not set"
    [ "$(iv readonly_rootfs)" = "true" ] || finding WARN docker "$cname: root filesystem is writable (read_only not set)"
    case "$(iv user)" in ''|root|0|0:0) finding WARN docker "$cname: runs as root (no user: set; check if the entrypoint drops privileges)" ;; esac
    [ "$(iv network_mode)" = "host" ] && finding WARN docker "$cname: network_mode host (published-port and firewall checks do not apply)"
    [ "$(iv pid_mode)" = "host" ] && finding FAIL docker "$cname: pid: host"
    [ "$(iv memory_limit)" = "0" ] && finding INFO docker "$cname: no memory limit"
    printf '%s' "$(iv mounts)" | grep -q 'docker.sock' && finding FAIL docker "$cname: Docker socket mounted (host root equivalent)"
    for pb in $(iv ports); do
      hp=${pb##*:}; hip=${pb#*=}; hip=${hip%:*}
      case "$hip" in
        127.*|'::1') ;;
        ''|0.0.0.0|'::') port_allowed "$hp" || finding FAIL docker "$cname: port $hp published on all interfaces ($pb); Docker bypasses UFW" ;;
        *) port_allowed "$hp" || finding WARN docker "$cname: port $hp published on $hip ($pb)" ;;
      esac
    done

    # Role detection and in-container read-only collection.
    # Container output is untrusted: keep only characters a path or role name needs.
    roles=$(${TO[@]+"${TO[@]}"} docker exec "$id" sh -c "$CTR_DETECT" 2>/dev/null | tr -cd 'A-Za-z0-9_./: -' || true)
    [ -n "$roles" ] || { finding INFO docker "$cname: no shell or no known service binaries; in-container checks skipped"; continue; }
    printf '%s\n' "$roles" > "$OUT/$d/roles.txt"
    case " $roles " in
      *" php "*)
        run "$d/php-ini.txt" docker exec "$id" php --ini
        run "$d/php-cli-i.txt" docker exec "$id" php -i
        ;;
    esac
    for r in $roles; do
      case "$r" in
        fpm:*)
          fb=${r#fpm:}; n=$(basename "$fb")
          run "$d/$n-i.txt" docker exec "$id" "$fb" -i
          if [ "$NO_TEST" = 1 ]; then
            # shellcheck disable=SC2016
            run "$d/$n-pools.txt" docker exec "$id" sh -c 'for f in /usr/local/etc/php-fpm.conf /usr/local/etc/php-fpm.d/*.conf /etc/php/*/fpm/php-fpm.conf /etc/php/*/fpm/pool.d/*.conf; do [ -f "$f" ] && { echo "; file $f"; cat "$f"; }; done'
          else
            run "$d/$n-pools.txt" docker exec "$id" "$fb" -tt
          fi
          php_eval "container $cname" "$OUT/$d/$n-i.txt" "$OUT/$d/$n-pools.txt" fpm
          ;;
      esac
    done
    if [ -s "$OUT/$d/php-cli-i.txt" ] && ! grep -q 'fpm:' "$OUT/$d/roles.txt"; then
      php_eval "container $cname" "$OUT/$d/php-cli-i.txt" "" cli
    fi
    case " $roles " in
      *" nginx "*)
        run "$d/nginx-V.txt" docker exec "$id" nginx -V
        CNV=$(sed -n 's#.*nginx version: [a-z]*/\([0-9.]*\).*#\1#p' "$OUT/$d/nginx-V.txt" | head -n1)
        if [ "$NO_TEST" = 1 ]; then
          # shellcheck disable=SC2016
          run "$d/nginx-T.txt" docker exec "$id" sh -c 'find /etc/nginx -type f \( -name "*.conf" -o -path "*/sites-enabled/*" \) | sort | while read -r f; do echo "# configuration file $f:"; cat "$f"; echo; done'
        else
          run "$d/nginx-T.txt" docker exec "$id" nginx -T
        fi
        nginx_eval "container $cname" "$OUT/$d/nginx-T.txt" "$CNV"
        ;;
    esac
    case " $roles " in
      *" mysqld "*|*" mariadbd "*)
        if [ "$SKIP_MYSQL" != 1 ]; then
          # shellcheck disable=SC2329  # invoked indirectly via mysql_collect
          ctr_q() { ${TO[@]+"${TO[@]}"} docker exec "$id" sh -c "$CTR_MYSQL" sh "$1"; }
          mysql_collect "container $cname" "$OUT/$d/mysql" 0 ctr_q
        fi
        ;;
    esac
  done
else
  [ "$SKIP_DOCKER" = 1 ] || finding INFO docker "Docker not installed or daemon not reachable"
fi

# ===========================================================================
# Summary and manifest
# ===========================================================================
section "summary"
{ grep '^FAIL' "$FINDINGS"; grep '^WARN' "$FINDINGS"; grep '^INFO' "$FINDINGS"; } > "$OUT/SUMMARY.txt"
NF_FAIL=$(grep -c '^FAIL' "$OUT/SUMMARY.txt")
NF_WARN=$(grep -c '^WARN' "$OUT/SUMMARY.txt")
NF_INFO=$(grep -c '^INFO' "$OUT/SUMMARY.txt")
if have sha256sum; then
  MAN=$(cd "$OUT" && find . -type f -print0 | sort -z | xargs -0 sha256sum)
  printf '%s\n' "$MAN" > "$OUT/MANIFEST.sha256"
fi

echo
echo "White-box collection finished: $OUT"
echo "FAIL: $NF_FAIL  WARN: $NF_WARN  INFO: $NF_INFO"
echo "--------------------------------------------------------------------"
grep -E '^(FAIL|WARN)' "$OUT/SUMMARY.txt" | head -n 60
[ "$((NF_FAIL + NF_WARN))" -gt 60 ] && echo "... see $OUT/SUMMARY.txt for the full list"
echo "--------------------------------------------------------------------"
echo "Review the files for unredacted secrets before copying them off the host."
exit 0
