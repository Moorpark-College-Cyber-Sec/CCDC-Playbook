#!/usr/bin/env bash
# Rocky Linux 9 e-commerce host hardening template.
# Run without arguments for inventory. Changes require --apply.
# Review scripts/README.md and the captured baseline before using --apply.
set -Eeuo pipefail
umask 077

APPLY=0
ZONE=""
IFACE=""
ADMIN=""
KEY_ONLY=0
DENY_ROOT_SSH=0
PRUNE_INBOUND=0
EGRESS=0
IN_SERVICES="ssh,http,https"
IN_PORTS=""
OUT_PORTS="53/udp,53/tcp,123/udp,80/tcp,443/tcp"
RUN_ROOT="/root/ccdc-hardening"

usage() {
  cat <<'EOF'
Usage: sudo bash harden-ecom.sh [options]
  --apply                    Apply baseline controls; otherwise inventory only
  --interface IFACE          Production interface; required for firewall changes
  --admin USER               Existing sudo user (required with --key-only)
  --key-only                 Disable SSH password auth after key preflight
  --deny-root-ssh            Disable root SSH after confirming root is not scored
  --in-services CSV          Allowed firewalld services (default ssh,http,https)
  --in-ports CSV             Additional inbound ports, e.g. 8443/tcp
  --prune-inbound            Remove other services/ports from selected active zone
  --enable-egress            Install HOST->ANY deny policy after dependency mapping
  --out-ports CSV            Outbound allow ports (default DNS,NTP,HTTP,HTTPS)
  --run-root DIR             Artifact root (default /root/ccdc-hardening)
  -h, --help                 Show this help

No script can infer checkout, payment, database, mail, DNS, update, or scoring
dependencies. Map them before --prune-inbound or --enable-egress. Keep a console.
EOF
}

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
note() { printf '%s\n' "$*" | tee -a "$LOG"; }
have() { command -v "$1" >/dev/null 2>&1; }
valid_csv() { [[ "$1" =~ ^[a-zA-Z0-9_+.-]+(,[a-zA-Z0-9_+.-]+)*$ ]]; }
valid_ports() { [[ -z "$1" || "$1" =~ ^[0-9]{1,5}/(tcp|udp)(,[0-9]{1,5}/(tcp|udp))*$ ]]; }
csv_lines() { tr ',' '\n' <<<"$1" | sed '/^$/d'; }
backup() {
  local path="$1" dest="$BACKUP$1"
  if [[ -e "$path" ]]; then
    install -d -m 700 "$(dirname "$dest")"
    cp -a -- "$path" "$dest"
  fi
}
capture() { local name="$1"; shift; "$@" >"$BASE/$name" 2>&1 || true; }
safe_write() {
  local path="$1" content="$2" tmp
  backup "$path"
  tmp="$(mktemp "${path}.XXXXXX")"
  printf '%s\n' "$content" >"$tmp"
  chmod 600 "$tmp"
  mv -f -- "$tmp" "$path"
}

while (($#)); do
  case "$1" in
    --apply) APPLY=1;;
    --interface|--admin|--in-services|--in-ports|--out-ports|--run-root)
      (($# >= 2)) || die "missing value for $1"
      case "$1" in
        --interface) IFACE="$2";; --admin) ADMIN="$2";;
        --in-services) IN_SERVICES="$2";; --in-ports) IN_PORTS="$2";;
        --out-ports) OUT_PORTS="$2";; --run-root) RUN_ROOT="$2";;
      esac
      shift;;
    --key-only) KEY_ONLY=1;;
    --deny-root-ssh) DENY_ROOT_SSH=1;;
    --prune-inbound) PRUNE_INBOUND=1;;
    --enable-egress) EGRESS=1;;
    -h|--help) usage; exit 0;;
    *) die "unknown argument: $1";;
  esac
  shift
done

((EUID == 0)) || die 'run as root'
[[ -r /etc/os-release ]] || die 'missing /etc/os-release'
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == rocky ]] || die "Rocky Linux only (found ${ID:-unknown})"
[[ "${VERSION_ID%%.*}" == 9 ]] || die "this profile supports Rocky Linux 9; found ${VERSION_ID:-unknown}"
valid_csv "$IN_SERVICES" || die 'invalid --in-services CSV'
valid_ports "$IN_PORTS" || die 'invalid --in-ports CSV'
valid_ports "$OUT_PORTS" || die 'invalid --out-ports CSV'
[[ "$RUN_ROOT" == /* && "$RUN_ROOT" != / && "$RUN_ROOT" != /root ]] || die 'use a dedicated absolute --run-root'
[[ "$IFACE" == "" || "$IFACE" =~ ^[a-zA-Z0-9_.:-]+$ ]] || die 'invalid interface name'
[[ "$ADMIN" == "" || "$ADMIN" =~ ^[a-z_][a-z0-9_-]*$ ]] || die 'invalid admin name'
if ((KEY_ONLY)); then
  [[ -n "$ADMIN" ]] || die '--key-only requires --admin'
  getent passwd "$ADMIN" >/dev/null || die "admin $ADMIN does not exist"
  id -nG "$ADMIN" | grep -qw wheel || die "admin $ADMIN is not in wheel"
  admin_home="$(getent passwd "$ADMIN" | cut -d: -f6)"
  [[ -s "$admin_home/.ssh/authorized_keys" ]] || die "no authorized_keys for $ADMIN"
  have sshd || die 'sshd is required for --key-only'
  ssh-keygen -lf "$admin_home/.ssh/authorized_keys" >/dev/null 2>&1 || die "no parseable public key for $ADMIN"
fi
if ((PRUNE_INBOUND || EGRESS)) && [[ -z "$IFACE" ]]; then
  die '--prune-inbound and --enable-egress require --interface'
fi

RUN="${RUN_ROOT}/$(date -u +%Y%m%dT%H%M%SZ)-$$"
BASE="$RUN/baseline"
BACKUP="$RUN/backup"
install -d -m 700 "$BASE" "$BACKUP"
LOG="$RUN/run.log"
touch "$LOG"
note "Run: $RUN | Rocky ${VERSION_ID} | mode: $([[ $APPLY == 1 ]] && echo APPLY || echo INVENTORY)"

# Inventory is read-only and captures evidence before changing services or files.
capture os-release cat /etc/os-release
capture packages rpm -qa --last
capture listening ss -tulpn
capture established ss -tnp state established
capture processes ps auxww
capture users getent passwd
capture groups getent group
capture uid-zero awk -F: '$3 == 0 {print $1 ":" $3 ":" $6 ":" $7}' /etc/passwd
capture privileged-groups getent group wheel
capture root-cron crontab -l -u root
capture login-history last -F -n 50
capture sudoers sh -c 'ls -la /etc/sudoers /etc/sudoers.d 2>/dev/null'
capture systemd-units systemctl list-unit-files --type=service --no-pager
capture timers systemctl list-timers --all --no-pager
capture network ip -br address
capture routes ip route show table all
capture firewall-runtime firewall-cmd --list-all-zones
capture firewall-permanent firewall-cmd --permanent --list-all-zones
capture firewall-policies firewall-cmd --list-all-policies
capture icmp-blocks firewall-cmd --list-icmp-blocks
capture icmp-block-inversion firewall-cmd --query-icmp-block-inversion
capture selinux getenforce
capture selinux-booleans getsebool -a
capture ssh-effective sshd -T
capture crypto-policy update-crypto-policies --show
capture audit-status auditctl -s
capture web-services systemctl --no-pager --plain status httpd nginx php-fpm mariadb mysqld postgresql
capture web-labels ls -ldZ /var/www /var/www/html /srv /srv/www
capture suspicious-php sh -c 'if [ -d /var/www ]; then grep -RIlE --include="*.php" "(eval[[:space:]]*\(|base64_decode[[:space:]]*\(|shell_exec[[:space:]]*\()" /var/www 2>/dev/null; fi'
capture scheduled-jobs sh -c 'find /etc/cron* /var/spool/cron /etc/systemd/system -maxdepth 2 -type f -printf "%TY-%Tm-%Td %TH:%TM %p\n" 2>/dev/null'
capture ssh-keys sh -c 'find /root /home -xdev -name authorized_keys -type f -print -exec ssh-keygen -lf {} \; 2>/dev/null'
capture privileged-files sh -c 'find /usr /etc /var /home /root -xdev -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null'
capture integrity rpm -Va
note 'Baseline captured. Review listeners, accounts, keys, RPM verification, zone, and app dependencies.'
if ((APPLY == 0)); then
  note 'Inventory only. No host configuration changed.'
  exit 0
fi

have firewall-cmd || die 'firewalld is required for apply'
systemctl is-active --quiet firewalld || die 'firewalld must already be active; start from console after reviewing existing rules'
[[ -n "$IFACE" ]] || die '--apply requires --interface so the active zone is explicit'
ZONE="$(firewall-cmd --get-zone-of-interface="$IFACE" 2>/dev/null || true)"
[[ -n "$ZONE" && "$ZONE" != no ]] || die "no active firewalld zone for $IFACE"
note "Active interface $IFACE is in zone $ZONE"
if [[ -n "$(firewall-cmd --zone="$ZONE" --list-icmp-blocks)" ]]; then
  note 'WARNING: active zone blocks ICMP types. Check required ping reachability.'
fi
if firewall-cmd --zone="$ZONE" --query-icmp-block-inversion >/dev/null 2>&1; then
  note 'WARNING: ICMP block inversion is active; confirm ping from another host.'
fi
firewall-cmd --permanent --check-config >/dev/null || die 'existing permanent firewalld config is invalid'
if ((PRUNE_INBOUND)) && [[ "$(firewall-cmd --permanent --zone="$ZONE" --get-target)" == ACCEPT ]]; then
  die "zone $ZONE has target ACCEPT; pruning ports would not close inbound traffic"
fi
backup "/etc/firewalld/zones/${ZONE}.xml"
backup /etc/ssh/sshd_config.d/01-ccdc-ecom.conf
backup /etc/sysctl.d/60-ccdc-ecom.conf
backup /etc/audit/rules.d/50-ccdc-ecom.rules
capture pre-zone firewall-cmd --zone="$ZONE" --list-all
capture pre-policy firewall-cmd --permanent --list-all-policies

# SSH: retain password authentication by default. A verified key-only switch is explicit.
if have sshd && [[ -d /etc/ssh/sshd_config.d ]] && grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/' /etc/ssh/sshd_config; then
  ssh_cfg=$'PermitEmptyPasswords no\nMaxAuthTries 3\nLoginGraceTime 30\nX11Forwarding no\nAllowAgentForwarding no'
  if ((DENY_ROOT_SSH)); then
    ssh_cfg+=$'\nPermitRootLogin no'
  fi
  if ((KEY_ONLY)); then
    ssh_cfg+=$'\nPasswordAuthentication no\nKbdInteractiveAuthentication no'
  fi
  safe_write /etc/ssh/sshd_config.d/01-ccdc-ecom.conf "$ssh_cfg"
  if sshd -t >>"$LOG" 2>&1; then
    effective_root=""
    effective_password=""
    effective_kbd=""
    if ((DENY_ROOT_SSH)); then
      effective_root="$(sshd -T -C 'user=root,host=localhost,addr=127.0.0.1' 2>>"$LOG" | awk '/^permitrootlogin / {print $2; exit}' || true)"
    fi
    if ((KEY_ONLY)); then
      effective_password="$(sshd -T -C "user=$ADMIN,host=localhost,addr=127.0.0.1" 2>>"$LOG" | awk '/^passwordauthentication / {print $2; exit}' || true)"
      effective_kbd="$(sshd -T -C "user=$ADMIN,host=localhost,addr=127.0.0.1" 2>>"$LOG" | awk '/^kbdinteractiveauthentication / {print $2; exit}' || true)"
    fi
    if { ((DENY_ROOT_SSH)) && [[ "$effective_root" != no ]]; } || { ((KEY_ONLY)) && { [[ "$effective_password" != no ]] || [[ "$effective_kbd" != no ]]; }; }; then
      if [[ -f "$BACKUP/etc/ssh/sshd_config.d/01-ccdc-ecom.conf" ]]; then
        cp -a "$BACKUP/etc/ssh/sshd_config.d/01-ccdc-ecom.conf" /etc/ssh/sshd_config.d/01-ccdc-ecom.conf
      else
        rm -f /etc/ssh/sshd_config.d/01-ccdc-ecom.conf
      fi
      die 'effective sshd settings were overridden; restored SSH drop-in'
    fi
    systemctl reload sshd || die 'sshd reload failed; inspect config from console'
    note 'SSH syntax and effective settings verified; sshd reloaded.'
  else
    if [[ -f "$BACKUP/etc/ssh/sshd_config.d/01-ccdc-ecom.conf" ]]; then
      cp -a "$BACKUP/etc/ssh/sshd_config.d/01-ccdc-ecom.conf" /etc/ssh/sshd_config.d/01-ccdc-ecom.conf
    else
      rm -f /etc/ssh/sshd_config.d/01-ccdc-ecom.conf
    fi
    die 'sshd -t failed; restored SSH drop-in'
  fi
else
  note 'SSH include not found; SSH changes skipped. Inspect sshd_config manually.'
fi

# Kernel network hygiene. Do not force rp_filter=1: asymmetric CCDC paths can break.
sysctl_cfg=$'net.ipv4.conf.all.accept_source_route = 0\nnet.ipv4.conf.default.accept_source_route = 0\nnet.ipv4.conf.all.accept_redirects = 0\nnet.ipv4.conf.default.accept_redirects = 0\nnet.ipv4.conf.all.send_redirects = 0\nnet.ipv4.conf.default.send_redirects = 0\nnet.ipv4.icmp_echo_ignore_broadcasts = 1\nnet.ipv4.tcp_syncookies = 1\nnet.ipv6.conf.all.accept_redirects = 0\nnet.ipv6.conf.default.accept_redirects = 0\nfs.protected_hardlinks = 1\nfs.protected_symlinks = 1\nkernel.kptr_restrict = 2\nkernel.dmesg_restrict = 1'
safe_write /etc/sysctl.d/60-ccdc-ecom.conf "$sysctl_cfg"
sysctl -p /etc/sysctl.d/60-ccdc-ecom.conf >>"$LOG" 2>&1 || note 'WARNING: some sysctls failed; inspect run.log'

# Inbound: add scored services first. Removing other openings is separate opt-in.
while IFS= read -r svc; do
  firewall-cmd --get-services | tr ' ' '\n' | grep -Fxq "$svc" || die "unknown firewalld service: $svc"
  firewall-cmd --permanent --zone="$ZONE" --add-service="$svc" >>"$LOG"
done < <(csv_lines "$IN_SERVICES")
while IFS= read -r port; do
  firewall-cmd --permanent --zone="$ZONE" --add-port="$port" >>"$LOG"
done < <(csv_lines "$IN_PORTS")
if ((PRUNE_INBOUND)); then
  for svc in $(firewall-cmd --permanent --zone="$ZONE" --list-services); do
    if ! csv_lines "$IN_SERVICES" | grep -Fxq "$svc"; then
      firewall-cmd --permanent --zone="$ZONE" --remove-service="$svc" >>"$LOG"
    fi
  done
  for port in $(firewall-cmd --permanent --zone="$ZONE" --list-ports); do
    if ! csv_lines "$IN_PORTS" | grep -Fxq "$port"; then
      firewall-cmd --permanent --zone="$ZONE" --remove-port="$port" >>"$LOG"
    fi
  done
  note 'Extra services and ports pruned from selected zone. Review rich rules and forwarding separately.'
fi

# Egress policy uses firewalld's HOST->ANY policy object, never deprecated --direct.
if ((EGRESS)); then
  POLICY=ccdc_ecom_egress
  backup "/etc/firewalld/policies/${POLICY}.xml"
  if firewall-cmd --permanent --get-policies | tr ' ' '\n' | grep -Fxq "$POLICY"; then
    [[ -z "$(firewall-cmd --permanent --policy="$POLICY" --list-services)" ]] || die 'existing egress policy has services; inspect before reusing'
    [[ -z "$(firewall-cmd --permanent --policy="$POLICY" --list-rich-rules)" ]] || die 'existing egress policy has rich rules; inspect before reusing'
  else
    firewall-cmd --permanent --new-policy="$POLICY" >>"$LOG"
  fi
  if ! firewall-cmd --permanent --policy="$POLICY" --list-ingress-zones | tr ' ' '\n' | grep -Fxq HOST; then
    firewall-cmd --permanent --policy="$POLICY" --add-ingress-zone=HOST >>"$LOG"
  fi
  if ! firewall-cmd --permanent --policy="$POLICY" --list-egress-zones | tr ' ' '\n' | grep -Fxq ANY; then
    firewall-cmd --permanent --policy="$POLICY" --add-egress-zone=ANY >>"$LOG"
  fi
  firewall-cmd --permanent --policy="$POLICY" --set-priority=-500 >>"$LOG"
  for old in $(firewall-cmd --permanent --policy="$POLICY" --list-ports); do
    firewall-cmd --permanent --policy="$POLICY" --remove-port="$old" >>"$LOG"
  done
  for old in $(firewall-cmd --permanent --policy="$POLICY" --list-protocols); do
    firewall-cmd --permanent --policy="$POLICY" --remove-protocol="$old" >>"$LOG"
  done
  while IFS= read -r port; do
    firewall-cmd --permanent --policy="$POLICY" --add-port="$port" >>"$LOG"
  done < <(csv_lines "$OUT_PORTS")
  # Preserve network diagnostics and IPv6 control traffic (including ND/RA).
  firewall-cmd --permanent --policy="$POLICY" --add-protocol=icmp >>"$LOG"
  firewall-cmd --permanent --policy="$POLICY" --add-protocol=ipv6-icmp >>"$LOG"
  firewall-cmd --permanent --policy="$POLICY" --set-target=DROP >>"$LOG"
  note 'Egress policy staged. Confirm DNS, NTP, DB, payment, mail, logging, and update destinations.'
fi

firewall-cmd --permanent --check-config >/dev/null || die 'new firewalld config invalid; restore files from backup before reload'
firewall-cmd --reload || die 'firewalld reload failed; inspect from console'
capture post-zone firewall-cmd --zone="$ZONE" --list-all
capture post-policy firewall-cmd --list-all-policies
note 'firewalld reloaded. Check remote SSH and all required store flows now.'

# MAC: report and preserve application-specific booleans; do not toggle them blindly.
if have getenforce; then
  note "SELinux: $(getenforce)"
  [[ "$(getenforce)" == Enforcing ]] || note 'ACTION: investigate permissive/disabled SELinux and AVCs before enabling.'
fi

# Audit rules watch persistence and web configuration, not high-volume request data.
if have augenrules && [[ -d /etc/audit/rules.d ]]; then
  audit_rules=$'-w /etc/passwd -p wa -k ccdc_identity\n-w /etc/shadow -p wa -k ccdc_identity\n-w /etc/sudoers -p wa -k ccdc_privilege\n-w /etc/sudoers.d/ -p wa -k ccdc_privilege\n-w /etc/ssh/ -p wa -k ccdc_ssh\n-w /etc/systemd/system/ -p wa -k ccdc_units\n-w /etc/cron.d/ -p wa -k ccdc_cron'
  [[ ! -d /etc/httpd ]] || audit_rules+=$'\n-w /etc/httpd/ -p wa -k ccdc_web_config'
  [[ ! -d /etc/nginx ]] || audit_rules+=$'\n-w /etc/nginx/ -p wa -k ccdc_web_config'
  safe_write /etc/audit/rules.d/50-ccdc-ecom.rules "$audit_rules"
  if ! augenrules --load >>"$LOG" 2>&1; then
    note 'WARNING: audit rules did not load; inspect paths and audit status.'
  fi
else
  note 'auditd tooling unavailable; install/enable audit before adding rules.'
fi

capture final-listening ss -tulpn
capture final-selinux getenforce
capture final-firewall firewall-cmd --zone="$ZONE" --list-all
note "Finished. Backup and before/after evidence: $RUN"
note 'Next: verify scoring and checkout, inspect alerts, then deploy IDS on a separate mirrored sensor.'
