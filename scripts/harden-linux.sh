#!/usr/bin/env bash
# harden-linux.sh — portable CCDC hardening + persistence-hunt playbook
#
# Families: RHEL (Rocky/Alma/CentOS/RHEL/Fedora), Debian (Debian/Ubuntu/Mint/Kali), Arch (Arch/Manjaro)
# Safe by default: reports only. Nothing is changed unless --apply is passed.
# The generic apply path can disrupt application dependencies. It requires
# --ack-generic-apply after mapping the host's services and rollback path.
#
# Scoring-safety contract (CCDC):
#   * inbound scored services are NEVER filtered by source  (rule 9: no knife-edge filtering)
#   * ICMP echo request/reply is NEVER blocked               (rule 12: boxes must stay pingable)
#   * every file touched is copied to the backup dir first
#
# Usage:
#   sudo ./harden-linux.sh                                   # dry run: hunt + report, change nothing
#   sudo ./harden-linux.sh --hunt-only                       # hunt only, skip the harden report
#   sudo ./harden-linux.sh --apply --ack-generic-apply          # broad, host-reviewed changes
#   sudo ./harden-linux.sh --apply --ack-generic-apply --ssh-key "ssh-ed25519 AAAA... you@team"
#   sudo ./harden-linux.sh --apply --ack-generic-apply --force-family debian
#   sudo ./harden-linux.sh --apply --ack-generic-apply --enable-egress --out-ports 53/udp,53/tcp,123/udp,80/tcp,443/tcp
#   sudo ./harden-linux.sh --apply --ack-generic-apply --php-disable-functions
#
set -uo pipefail

VERSION="1.0.0"

# ---------------------------------------------------------------------------
# state
# ---------------------------------------------------------------------------
APPLY=0            # 0 = dry run (default), 1 = make changes
GENERIC_ACK=0      # 1 = operator acknowledged generic apply risks
HUNT_ONLY=0        # 1 = skip the harden phase entirely
SSH_KEY=""         # public key installed for root+sudoers before password auth is killed
FORCE_FAMILY=""    # rhel|debian|arch — bypass os-release detection
ENABLE_EGRESS=0    # opt-in outbound deny
PHP_DISABLE_FUNCTIONS=0 # opt-in PHP configuration changes
ENABLE_MAC=0       # opt-in MAC policy changes
OUT_PORTS="53/udp,53/tcp,123/udp,80/tcp,443/tcp"
EGRESS_TCP_PORTS=()
EGRESS_UDP_PORTS=()

TS="$(date +%Y%m%d-%H%M%S)"
WORKDIR="/root/ccdc-harden-${TS}"
BACKUP="${WORKDIR}/backup"
REPORT="${WORKDIR}/report.txt"

# filled in by detect_platform()
FAMILY=""          # rhel | debian | arch | unknown
DISTRO=""          # ID from /etc/os-release
PKG=""             # dnf | apt-get | pacman
SUDO_GROUP=""      # wheel | sudo
SSHD_UNIT=""       # sshd | ssh
WEB_UNITS=""       # candidate web/php units to restart
MAC=""             # selinux | apparmor | none
FW=""              # firewalld | ufw | nftables | iptables | none

# The egress allowlist is parsed from --out-ports before any host changes.

# ---------------------------------------------------------------------------
# output helpers
# ---------------------------------------------------------------------------
C_RED=$'\033[31m'; C_YEL=$'\033[33m'; C_GRN=$'\033[32m'; C_CYN=$'\033[36m'; C_OFF=$'\033[0m'

_emit() { printf '%s\n' "$*" | tee -a "$REPORT" >/dev/null; printf '%s\n' "$*"; }
log()   { _emit "${C_CYN}[*]${C_OFF} $*"; }
ok()    { _emit "${C_GRN}[+]${C_OFF} $*"; }
warn()  { _emit "${C_YEL}[!]${C_OFF} $*"; }
bad()   { _emit "${C_RED}[x]${C_OFF} $*"; }
head2() { _emit ""; _emit "=== $* ==="; }
die()   { printf '%s[x]%s %s\n' "$C_RED" "$C_OFF" "$*" >&2; exit 1; }

# run CMD — executes only under --apply, otherwise just prints what would happen.
run() {
  if [[ $APPLY -eq 1 ]]; then
    "$@" >>"${WORKDIR}/actions.log" 2>&1 \
      || warn "command returned non-zero: $*"
  else
    _emit "    would run: $*"
  fi
}

# backup_file PATH — copy a file into the backup tree, preserving its full path,
# so every change is reversible with a straight cp back.
backup_file() {
  local f="$1"
  [[ -e "$f" ]] || return 0
  if [[ $APPLY -eq 1 ]]; then
    install -D -m 0600 "$f" "${BACKUP}${f}" 2>/dev/null \
      || warn "could not back up $f"
  else
    _emit "    would back up: $f -> ${BACKUP}${f}"
  fi
}

usage() {
  sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --apply)         APPLY=1 ;;                       # commit changes instead of reporting
      --ack-generic-apply) GENERIC_ACK=1 ;;             # explicit gate for broad changes
      --hunt-only)     HUNT_ONLY=1 ;;                   # persistence hunt, no harden phase
      --ssh-key)       SSH_KEY="${2:-}"; shift ;;        # pubkey to install before killing passwords
      --force-family)  FORCE_FAMILY="${2:-}"; shift ;;   # rhel|debian|arch
      --enable-egress) ENABLE_EGRESS=1 ;;
      --out-ports)    [[ $# -ge 2 ]] || die "--out-ports needs a CSV value"; OUT_PORTS="$2"; shift ;;
      --php-disable-functions) PHP_DISABLE_FUNCTIONS=1 ;;
      --enable-mac)   ENABLE_MAC=1 ;;
      -h|--help)       usage ;;
      *)               die "unknown argument: $1 (try --help)" ;;
    esac
    shift
  done

  if [[ -n "$FORCE_FAMILY" && ! "$FORCE_FAMILY" =~ ^(rhel|debian|arch)$ ]]; then
    die "--force-family must be one of: rhel debian arch"
  fi

  local entry port proto
  local -a entries
  [[ "$OUT_PORTS" =~ ^[0-9]{1,5}/(tcp|udp)(,[0-9]{1,5}/(tcp|udp))*$ ]] \
    || die "--out-ports must be comma-separated PORT/tcp or PORT/udp entries"
  IFS=, read -r -a entries <<<"$OUT_PORTS"
  for entry in "${entries[@]}"; do
    [[ "$entry" =~ ^([0-9]{1,5})/(tcp|udp)$ ]] || die "invalid outbound port: $entry"
    port="${BASH_REMATCH[1]}"; proto="${BASH_REMATCH[2]}"
    ((10#$port >= 1 && 10#$port <= 65535)) || die "outbound port out of range: $entry"
    if [[ "$proto" == tcp ]]; then
      EGRESS_TCP_PORTS+=("$((10#$port))")
    else
      EGRESS_UDP_PORTS+=("$((10#$port))")
    fi
  done
}

need_root() {
  # EUID is the effective uid; 0 means we are root. Everything below writes to
  # /etc and queries other users' files, so there is no useful non-root mode.
  [[ ${EUID} -eq 0 ]] || die "run as root (sudo $0 ...)"
}

# ---------------------------------------------------------------------------
# platform detection
# ---------------------------------------------------------------------------
detect_platform() {
  head2 "platform"

  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO="${ID:-unknown}"
    local idlike="${ID_LIKE:-}"
  else
    DISTRO="unknown"; local idlike=""
    warn "/etc/os-release missing — relying on --force-family or package-manager probe"
  fi

  if [[ -n "$FORCE_FAMILY" ]]; then
    FAMILY="$FORCE_FAMILY"
    warn "family forced to '${FAMILY}' (detection bypassed)"
  else
    case " ${DISTRO} ${idlike} " in
      *" rhel "*|*" fedora "*|*" centos "*|*rocky*|*almalinux*) FAMILY="rhel" ;;
      *" debian "*|*" ubuntu "*|*kali*|*linuxmint*)             FAMILY="debian" ;;
      *" arch "*|*archlinux*|*manjaro*)                         FAMILY="arch" ;;
      *)
        # os-release was unhelpful — fall back to whichever package manager exists
        if   command -v dnf    >/dev/null 2>&1; then FAMILY="rhel"
        elif command -v apt-get >/dev/null 2>&1; then FAMILY="debian"
        elif command -v pacman  >/dev/null 2>&1; then FAMILY="arch"
        else FAMILY="unknown"
        fi
        ;;
    esac
  fi

  case "$FAMILY" in
    rhel)   PKG="dnf";     SUDO_GROUP="wheel"; SSHD_UNIT="sshd" ;;
    debian) PKG="apt-get"; SUDO_GROUP="sudo";  SSHD_UNIT="ssh"  ;;
    arch)   PKG="pacman";  SUDO_GROUP="wheel"; SSHD_UNIT="sshd" ;;
    *)      PKG="";        SUDO_GROUP="wheel"; SSHD_UNIT="sshd"
            warn "unknown family — the hunt still runs in full; harden steps needing a known toolchain will skip" ;;
  esac

  # systemd is universal on all three families now, so unit names are the only variance.
  WEB_UNITS="httpd apache2 nginx php-fpm"

  # MAC layer: whichever is actually present
  if   command -v getenforce >/dev/null 2>&1; then MAC="selinux"
  elif command -v aa-status  >/dev/null 2>&1; then MAC="apparmor"
  else MAC="none"
  fi

  # Firewall backend: prefer the managed front-ends, fall back to raw tables
  if   systemctl is-active --quiet firewalld 2>/dev/null; then FW="firewalld"
  elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then FW="ufw"
  elif command -v nft >/dev/null 2>&1; then FW="nftables"
  elif command -v iptables >/dev/null 2>&1; then FW="iptables"
  else FW="none"
  fi

  ok "distro=${DISTRO} family=${FAMILY} pkg=${PKG:-none} mac=${MAC} firewall=${FW} sshd-unit=${SSHD_UNIT}"
}

# ---------------------------------------------------------------------------
# persistence hunt — reports only, never deletes. You decide what dies.
# ---------------------------------------------------------------------------
hunt_accounts() {
  head2 "hunt: accounts"

  # Any uid 0 other than root is a backdoor account, full stop.
  # -F: sets ':' as the field separator; $3 is the uid field in /etc/passwd.
  awk -F: '$3 == 0 && $1 != "root" { print $1 }' /etc/passwd | while read -r u; do
    bad "UID 0 account that is not root: ${u}"
  done

  # Accounts with a real login shell — compare against what you expect on the box.
  awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ { print "  " $1 " uid=" $3 " shell=" $7 }' /etc/passwd \
    | tee -a "$REPORT"

  # Empty password field in /etc/shadow ($2 empty) = passwordless login.
  awk -F: '$2 == "" { print $1 }' /etc/shadow 2>/dev/null | while read -r u; do
    bad "account with EMPTY password: ${u}"
  done

  # Who can sudo
  log "members of sudo group '${SUDO_GROUP}':"
  getent group "$SUDO_GROUP" | cut -d: -f4 | tr ',' '\n' | sed '/^$/d;s/^/    /' | tee -a "$REPORT"

  # NOPASSWD sudo rules are a classic quiet privesc plant.
  # -r: recursive, -n: show line numbers, -s: silence unreadable-file noise.
  grep -rns 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | while read -r line; do
    warn "NOPASSWD sudo rule: ${line}"
  done
}

hunt_ssh_keys() {
  head2 "hunt: authorized_keys"

  # Walk every account's home from /etc/passwd ($6) and fingerprint each key,
  # so you can eyeball what belongs and what does not.
  awk -F: '{ print $1 ":" $6 }' /etc/passwd | while IFS=: read -r user home; do
    [[ -d "$home" ]] || continue
    for akf in "$home"/.ssh/authorized_keys "$home"/.ssh/authorized_keys2; do
      [[ -s "$akf" ]] || continue
      warn "keys for ${user} in ${akf}:"
      # ssh-keygen -l -f -  reads keys on stdin and prints their fingerprints.
      while read -r key; do
        [[ -n "$key" ]] || continue
        printf '%s\n' "$key" | ssh-keygen -l -f - 2>/dev/null | sed 's/^/      /' | tee -a "$REPORT"
      done < "$akf"
    done
  done

  # Keys parked outside a home directory — sshd can be pointed at these via
  # AuthorizedKeysFile, and they are easy to miss.
  grep -rsin '^[[:space:]]*AuthorizedKeysFile' /etc/ssh/ 2>/dev/null | sed 's/^/    /' | tee -a "$REPORT"
}

hunt_scheduled() {
  head2 "hunt: cron + systemd timers"

  # Per-user crontabs live under one of these two paths depending on family.
  for d in /var/spool/cron /var/spool/cron/crontabs; do
    [[ -d "$d" ]] || continue
    find "$d" -type f -printf '  %p (%s bytes, mtime %TF %TT)\n' 2>/dev/null | tee -a "$REPORT"
  done

  # System cron drop-ins
  for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    [[ -d "$d" ]] || continue
    find "$d" -type f -newermt '-30 days' -printf '  recently modified: %p (%TF)\n' 2>/dev/null | tee -a "$REPORT"
  done
  [[ -f /etc/crontab ]] && grep -vE '^\s*(#|$)' /etc/crontab | sed 's/^/    /' | tee -a "$REPORT"

  # at/batch jobs
  command -v atq >/dev/null 2>&1 && atq 2>/dev/null | sed 's/^/    at job: /' | tee -a "$REPORT"

  # Timers are the modern cron and get overlooked. --all shows inactive ones too.
  log "systemd timers:"
  systemctl list-timers --all --no-pager --no-legend 2>/dev/null | sed 's/^/    /' | tee -a "$REPORT"

  # Units written outside package management are suspicious: packaged units live
  # in /usr/lib/systemd, admin/attacker units land in /etc/systemd.
  find /etc/systemd/system -name '*.service' -o -name '*.timer' 2>/dev/null \
    | while read -r unit; do
        # ExecStart lines that pipe to a shell or call an interpreter are the tell.
        if grep -qsE 'ExecStart=.*(bash|sh|nc|ncat|socat|python|perl|curl|wget)' "$unit"; then
          bad "unit with interpreter/network ExecStart: ${unit}"
          grep -sE '^(ExecStart|ExecStartPre)' "$unit" | sed 's/^/        /' | tee -a "$REPORT"
        fi
      done
}

hunt_shell_rc() {
  head2 "hunt: shell startup files"

  # Reverse-shell one-liners get appended to rc files so they fire on every login.
  local pat='(bash -i|/dev/tcp/|nc +-[a-z]*e|ncat .*-e|socat .*exec|python.? +-c|curl .*\| *(ba)?sh|wget .*\| *(ba)?sh|base64 +-d)'
  local files=(/etc/profile /etc/bash.bashrc /etc/bashrc)
  while IFS=: read -r _ home; do
    for f in .bashrc .bash_profile .profile .zshrc .bash_logout; do
      [[ -f "${home}/${f}" ]] && files+=("${home}/${f}")
    done
  done < <(awk -F: '{ print $1 ":" $6 }' /etc/passwd)
  [[ -d /etc/profile.d ]] && while read -r f; do files+=("$f"); done < <(find /etc/profile.d -type f 2>/dev/null)

  # -E extended regex, -n line numbers, -H always show filename, -I skip binaries
  for f in "${files[@]}"; do
    [[ -f "$f" ]] || continue
    grep -EnHI "$pat" "$f" 2>/dev/null | while read -r hit; do bad "rc-file payload: ${hit}"; done
  done
}

hunt_suid_caps() {
  head2 "hunt: SUID binaries + file capabilities"

  # SUID outside the standard bin dirs is almost always planted.
  # -perm -4000: setuid bit set. -prune skips virtual/remote filesystems.
  find / -xdev \( -path /proc -o -path /sys -o -path /run \) -prune -o \
       -type f -perm -4000 -print 2>/dev/null \
    | grep -vE '^/(usr/)?(bin|sbin|lib|lib64|libexec)/' \
    | while read -r f; do bad "SUID in a non-standard location: ${f}"; done

  # File capabilities are the stealthier cousin of SUID — no setuid bit to spot.
  if command -v getcap >/dev/null 2>&1; then
    getcap -r / 2>/dev/null | grep -vE '^/(usr/)?(bin|sbin|lib|lib64)/' \
      | while read -r line; do warn "file capability: ${line}"; done
  fi
}

hunt_listeners() {
  head2 "hunt: listening sockets + recent packages"

  # ss flags: -t TCP, -u UDP, -l listening only, -n numeric ports, -p owning process
  if command -v ss >/dev/null 2>&1; then
    ss -tulnp 2>/dev/null | sed 's/^/    /' | tee -a "$REPORT"
  else
    netstat -tulnp 2>/dev/null | sed 's/^/    /' | tee -a "$REPORT"
  fi

  # Anything installed in the last 7 days during a competition is worth a look.
  log "recently installed packages:"
  case "$FAMILY" in
    rhel)   rpm -qa --last 2>/dev/null | head -25 | sed 's/^/    /' | tee -a "$REPORT" ;;
    debian) grep -h ' install ' /var/log/dpkg.log /var/log/dpkg.log.1 2>/dev/null \
              | tail -25 | sed 's/^/    /' | tee -a "$REPORT" ;;
    arch)   grep -h '\[ALPM\] installed' /var/log/pacman.log 2>/dev/null \
              | tail -25 | sed 's/^/    /' | tee -a "$REPORT" ;;
    *)      warn "unknown family — skipping package history" ;;
  esac
}

hunt_webshells() {
  head2 "hunt: webroot"

  local roots=()
  for r in /var/www /var/www/html /srv/http /usr/share/nginx/html; do
    [[ -d "$r" ]] && roots+=("$r")
  done
  [[ ${#roots[@]} -eq 0 ]] && { log "no webroot found — skipping"; return 0; }

  # Classic PHP webshell primitives. Finding one of these in a webroot is
  # not proof, but every one of them deserves an eyeball.
  local pat='(eval *\(|assert *\(|system *\(|shell_exec|passthru|popen|proc_open|base64_decode *\(|\$_(GET|POST|REQUEST|COOKIE)\s*\[)'
  for r in "${roots[@]}"; do
    grep -rEnHI --include='*.php' --include='*.phtml' --include='*.inc' "$pat" "$r" 2>/dev/null \
      | head -60 | while read -r hit; do bad "webshell pattern: ${hit}"; done
    # Files written in the last 2 days in a webroot that nobody deployed to.
    find "$r" -type f -newermt '-2 days' -printf '  recently written: %p (%TF %TT)\n' 2>/dev/null | tee -a "$REPORT"
  done
}

# ---------------------------------------------------------------------------
# harden phase
# ---------------------------------------------------------------------------
harden_ssh() {
  head2 "harden: ssh"

  # On Rocky 9 / modern OpenSSH, /etc/ssh/sshd_config.d/*.conf is read in
  # lexical order and the FIRST value for a keyword wins. So hardening goes in
  # a 01- prefixed file to out-rank anything the distro (or an attacker) drops.
  local dropin=/etc/ssh/sshd_config.d/01-ccdc-harden.conf
  local keyline=""

  if [[ -n "$SSH_KEY" ]]; then
    # Install the key FIRST, then disable passwords — order matters or you lock out.
    for u in root; do
      local home; home="$(getent passwd "$u" | cut -d: -f6)"
      [[ -n "$home" ]] || continue
      backup_file "${home}/.ssh/authorized_keys"
      if [[ $APPLY -eq 1 ]]; then
        install -d -m 0700 -o "$u" -g "$u" "${home}/.ssh"
        # grep -qxF: quiet, whole-line, fixed-string — makes this idempotent.
        grep -qxF "$SSH_KEY" "${home}/.ssh/authorized_keys" 2>/dev/null \
          || printf '%s\n' "$SSH_KEY" >> "${home}/.ssh/authorized_keys"
        chmod 0600 "${home}/.ssh/authorized_keys"; chown "${u}:${u}" "${home}/.ssh/authorized_keys"
      else
        _emit "    would install provided key into ${home}/.ssh/authorized_keys"
      fi
    done
    keyline="PasswordAuthentication no"
    if [[ $APPLY -eq 1 ]]; then
      ok "key installed — password auth will be disabled"
    else
      _emit "    would disable password auth after installing the provided key"
    fi
  else
    # No key given: deliberately leave passwords on rather than lock you out.
    keyline="PasswordAuthentication yes"
    if [[ $APPLY -eq 1 ]]; then
      warn "no --ssh-key given: setting PasswordAuthentication yes; verify the scored SSH path"
    else
      _emit "    without --ssh-key, apply would set PasswordAuthentication yes"
    fi
  fi

  backup_file "$dropin"
  if [[ $APPLY -eq 1 ]]; then
    cat > "$dropin" <<CONF
# CCDC hardening — first-match-wins drop-in, keep the 01- prefix
PermitRootLogin prohibit-password
${keyline}
PermitEmptyPasswords no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
AuthorizedKeysFile .ssh/authorized_keys
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
CONF
    chmod 0600 "$dropin"
    # -t: test the config. Never reload a config that does not parse.
    if sshd -t 2>>"${WORKDIR}/actions.log"; then
      run systemctl reload "$SSHD_UNIT"
      ok "sshd hardened and reloaded"
    else
      bad "sshd -t FAILED — drop-in left in place but NOT reloaded; check ${WORKDIR}/actions.log"
    fi
  else
    _emit "    would write ${dropin} (PermitRootLogin prohibit-password, ${keyline}, MaxAuthTries 3, no forwarding)"
    _emit "    would run: sshd -t && systemctl reload ${SSHD_UNIT}"
  fi
}

harden_kernel() {
  head2 "harden: kernel / sysctl"

  local f=/etc/sysctl.d/99-ccdc-harden.conf
  backup_file "$f"
  if [[ $APPLY -eq 1 ]]; then
    cat > "$f" <<'CONF'
# anti-spoof / routing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.ip_forward = 0
# NOTE: icmp_echo_ignore_all is deliberately 0 — the box MUST stay pingable (rule 12)
net.ipv4.icmp_echo_ignore_all = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
# process hardening
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
CONF
    # --system reloads every /etc/sysctl.d file in order
    run sysctl --system
    ok "sysctl hardening applied (ICMP echo left enabled on purpose)"
  else
    _emit "    would write ${f} (rp_filter, no redirects, syncookies, ASLR; ICMP echo stays ON)"
  fi
}

harden_mac() {
  head2 "harden: mandatory access control (${MAC})"

  if [[ $ENABLE_MAC -eq 0 ]]; then
    log "MAC settings unchanged; use --enable-mac after checking application policy"
    if [[ "$MAC" == selinux ]]; then
      _emit "    SELinux: $(getenforce 2>/dev/null || echo unknown)"
      for b in httpd_can_network_connect httpd_can_network_connect_db \
               httpd_can_network_relay httpd_execmem httpd_enable_cgi; do
        getsebool "$b" 2>/dev/null | tee -a "$REPORT" || :
      done
    fi
    return 0
  fi

  case "$MAC" in
    selinux)
      # setenforce 1 = enforcing now; the config file makes it survive reboot.
      run setenforce 1
      backup_file /etc/selinux/config
      [[ $APPLY -eq 1 ]] && sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config \
        || _emit "    would set SELINUX=enforcing in /etc/selinux/config"
      # These application booleans are independent of the firewall and require
      # separate dependency review before --enable-mac is selected.
      for b in httpd_can_network_connect httpd_can_network_connect_db \
               httpd_can_network_relay httpd_execmem httpd_enable_cgi; do
        # setsebool -P: persist across reboot
        run setsebool -P "$b" off
      done
      if [[ $APPLY -eq 1 ]]; then
        ok "SELinux enforcement and web boolean changes requested; verify effective state"
      else
        _emit "    would enforce SELinux and turn off selected httpd booleans"
      fi
      ;;
    apparmor)
      run systemctl enable --now apparmor
      if [[ $APPLY -eq 1 ]]; then
        # aa-enforce flips a profile from complain to enforce mode.
        find /etc/apparmor.d -maxdepth 1 -type f -print0 2>/dev/null \
          | xargs -0 -r aa-enforce >>"${WORKDIR}/actions.log" 2>&1 || warn "some profiles would not enforce"
      else
        _emit "    would run: systemctl enable --now apparmor && aa-enforce /etc/apparmor.d/*"
      fi
      if [[ $APPLY -eq 1 ]]; then
        ok "AppArmor enforcement requested; verify profile state"
      else
        _emit "    would enable AppArmor and enforce available profiles"
      fi
      ;;
    *)
      warn "no MAC layer present (normal on Arch); review application policy separately"
      ;;
  esac
}

harden_egress() {
  head2 "harden: egress policy (backend: ${FW})"
  log "outbound allowlist: ${OUT_PORTS}"

  # Outbound becomes default-deny with the supplied allowlist. Review every
  # application dependency before enabling it; backend behavior varies.
  case "$FW" in
    firewalld)
      # firewalld's backend is nftables on modern RHEL, but direct rules are
      # still translated faithfully, which keeps this portable.
      for p in "${EGRESS_TCP_PORTS[@]}"; do
        run firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 10 -p tcp --dport "$p" -j ACCEPT
      done
      for p in "${EGRESS_UDP_PORTS[@]}"; do
        run firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 10 -p udp --dport "$p" -j ACCEPT
      done
      # established/related so inbound scored connections can reply
      run firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 5 -m state --state ESTABLISHED,RELATED -j ACCEPT
      run firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 5 -o lo -j ACCEPT
      run firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 6 -p icmp -j ACCEPT
      run firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 98 -j LOG --log-prefix "EGRESS-DROP: " --log-level 4
      run firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 99 -j DROP
      run firewall-cmd --reload
      warn "firewalld direct rules here cover IPv4 only; inspect IPv6 egress separately"
      ;;
    ufw)
      run ufw --force default deny outgoing      # the default-deny switch
      for p in "${EGRESS_TCP_PORTS[@]}"; do run ufw allow out "${p}/tcp"; done
      for p in "${EGRESS_UDP_PORTS[@]}"; do run ufw allow out "${p}/udp"; done
      warn "ufw does not log drops by prefix — run 'ufw logging medium' if you want EGRESS-DROP visibility"
      warn "check UFW's IPv6 setting and existing inbound policy separately"
      ;;
    nftables)
      local tcp_set udp_set tcp_rule="" udp_rule=""
      tcp_set="$(IFS=,; echo "${EGRESS_TCP_PORTS[*]}")"
      udp_set="$(IFS=,; echo "${EGRESS_UDP_PORTS[*]}")"
      [[ -z "$tcp_set" ]] || tcp_rule="    tcp dport { ${tcp_set} } accept"
      [[ -z "$udp_set" ]] || udp_rule="    udp dport { ${udp_set} } accept"
      if [[ $APPLY -eq 1 ]]; then
        # A dedicated table so we never clobber whatever else manages nftables.
        nft -f - >>"${WORKDIR}/actions.log" 2>&1 <<NFT || die "nftables egress policy failed; inspect ${WORKDIR}/actions.log"
table inet harden {
  chain output {
    type filter hook output priority 0; policy drop;
    ct state established,related accept
    oif "lo" accept
    meta l4proto { icmp, icmpv6 } accept
${tcp_rule}
${udp_rule}
    log prefix "EGRESS-DROP: " level warn
  }
}
NFT
        ok "nftables table 'inet harden' installed (policy drop on output)"
      else
        _emit "    would install nftables table 'inet harden' with policy drop on output, ports ${OUT_PORTS}, and EGRESS-DROP logging"
      fi
      ;;
    iptables)
      run iptables -A OUTPUT -o lo -j ACCEPT
      run iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
      run iptables -A OUTPUT -p icmp -j ACCEPT
      for p in "${EGRESS_TCP_PORTS[@]}"; do run iptables -A OUTPUT -p tcp --dport "$p" -j ACCEPT; done
      for p in "${EGRESS_UDP_PORTS[@]}"; do run iptables -A OUTPUT -p udp --dport "$p" -j ACCEPT; done
      run iptables -A OUTPUT -j LOG --log-prefix "EGRESS-DROP: " --log-level 4
      run iptables -A OUTPUT -j DROP
      warn "iptables rules are not persistent by default — save them (iptables-save) before you rely on this"
      warn "iptables rules here cover IPv4 only; inspect IPv6 egress separately"
      ;;
    *)
      bad "no firewall backend found — egress is UNFILTERED; install firewalld, ufw, or nftables"
      ;;
  esac
  log "egress phase added no inbound source filters; verify ICMP and application flows"
}

harden_passwords() {
  head2 "harden: password policy"

  local f=/etc/security/pwquality.conf.d/99-ccdc.conf
  [[ -d /etc/security/pwquality.conf.d ]] || f=/etc/security/pwquality.conf
  backup_file "$f"
  if [[ $APPLY -eq 1 ]]; then
    install -D -m 0644 /dev/null "$f"
    cat > "$f" <<'CONF'
minlen = 14
minclass = 3
maxrepeat = 3
dictcheck = 1
usercheck = 1
enforce_for_root
CONF
    ok "pwquality policy written to ${f}"
  else
    _emit "    would write ${f} (minlen 14, minclass 3, dictcheck)"
  fi

  # Lock accounts after repeated failures. faillock is RHEL/Arch; Debian uses tally2/faillock too on newer releases.
  if [[ -d /etc/security ]] && command -v faillock >/dev/null 2>&1; then
    local ff=/etc/security/faillock.conf
    backup_file "$ff"
    if [[ $APPLY -eq 1 ]]; then
      cat > "$ff" <<'CONF'
deny = 5
unlock_time = 900
fail_interval = 900
even_deny_root
CONF
      ok "faillock: 5 failures -> 15 minute lockout"
    else
      _emit "    would write ${ff} (deny 5, unlock_time 900)"
    fi
  fi
}

harden_web_php() {
  head2 "harden: web / PHP"

  command -v php >/dev/null 2>&1 || { log "php not installed — skipping"; return 0; }

  # php --ini identifies the CLI primary ini. Debian also has per-SAPI php.ini
  # files; verify the actual web SAPI separately before changing its settings.
  local inis=()
  while read -r p; do [[ -f "$p" ]] && inis+=("$p"); done < <(
    php --ini 2>/dev/null | sed -n 's/^Loaded Configuration File: *//p'
    find /etc/php -name php.ini 2>/dev/null
  )
  [[ ${#inis[@]} -eq 0 ]] && { warn "no php.ini found"; return 0; }

  for ini in "${inis[@]}"; do
    _emit "    PHP ini: ${ini}"
    grep -nE '^[[:space:]]*disable_functions[[:space:]]*=' "$ini" \
      | sed 's/^/      /' | tee -a "$REPORT" \
      || _emit "      no active disable_functions declaration found"
    if [[ $PHP_DISABLE_FUNCTIONS -eq 0 ]]; then
      continue
    fi
    backup_file "$ini"
    if [[ $APPLY -eq 1 ]]; then
      printf '\n; CCDC opt-in function restriction\ndisable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,pcntl_exec,dl\n' >> "$ini"
      ok "appended disable_functions to ${ini}; validate the web SAPI before restarting it"
    else
      _emit "    would append disable_functions to ${ini}"
    fi
  done

  if [[ $PHP_DISABLE_FUNCTIONS -eq 1 ]]; then
    warn "If applied, PHP changes need a staged reload/restart of the actual web SAPI; test required pages and rollback if needed"
  fi
  return 0
}

harden_audit() {
  head2 "harden: auditd watches"

  command -v auditctl >/dev/null 2>&1 || { warn "auditd not installed — skipping (install audit/auditd)"; return 0; }

  local f=/etc/audit/rules.d/99-ccdc.rules
  backup_file "$f"
  if [[ $APPLY -eq 1 ]]; then
    install -D -m 0640 /dev/null "$f"
    # -w watch a path, -p wa = permission changes to watch: write + attribute
    # -k tags the rule so you can filter with ausearch -k <key>
    cat > "$f" <<'CONF'
-w /etc/passwd -p wa -k ccdc_identity
-w /etc/shadow -p wa -k ccdc_identity
-w /etc/group  -p wa -k ccdc_identity
-w /etc/sudoers -p wa -k ccdc_privesc
-w /etc/sudoers.d/ -p wa -k ccdc_privesc
-w /etc/ssh/ -p wa -k ccdc_ssh
-w /root/.ssh/ -p wa -k ccdc_ssh
-w /etc/systemd/system/ -p wa -k ccdc_persist
-w /etc/cron.d/ -p wa -k ccdc_persist
-w /var/spool/cron/ -p wa -k ccdc_persist
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=-1 -k ccdc_rootexec
CONF
    # augenrules compiles rules.d/* into the live ruleset
    run augenrules --load
    ok "audit watches loaded (filter with: ausearch -k ccdc_persist)"
  else
    _emit "    would write ${f} (watches on passwd/shadow/sudoers/ssh/systemd/cron + root execve)"
  fi
}

install_tripwire() {
  head2 "harden: ccdc-watch tripwire (5 minute diff)"

  # Snapshots the things red teams re-plant and logs any change to syslog, so a
  # re-plant shows up within 5 minutes instead of at the end of the round.
  local script=/usr/local/sbin/ccdc-watch
  if [[ $APPLY -eq 1 ]]; then
    install -D -m 0700 /dev/null "$script"
    cat > "$script" <<'WATCH'
#!/usr/bin/env bash
# ccdc-watch — diff the persistence surface against the last snapshot.
set -uo pipefail
STATE=/var/lib/ccdc-watch
mkdir -p "$STATE"
snap() { # snap NAME COMMAND...
  local name="$1"; shift
  local new="${STATE}/${name}.new" cur="${STATE}/${name}"
  "$@" > "$new" 2>/dev/null
  if [[ -f "$cur" ]] && ! diff -q "$cur" "$new" >/dev/null 2>&1; then
    # logger -t tags the syslog entry; -p sets facility.priority
    logger -t ccdc-watch -p auth.warning "CHANGE in ${name}:"
    diff "$cur" "$new" | logger -t ccdc-watch -p auth.warning
  fi
  mv -f "$new" "$cur"
}
snap passwd   cat /etc/passwd
snap shadow_t awk -F: '{print $1":"length($2)}' /etc/shadow
snap sudoers  cat /etc/sudoers
snap keys     bash -c 'awk -F: "{print \$6}" /etc/passwd | while read -r h; do [[ -f "$h/.ssh/authorized_keys" ]] && sha256sum "$h/.ssh/authorized_keys"; done'
snap crond    bash -c 'ls -la /etc/cron.d /var/spool/cron /var/spool/cron/crontabs 2>/dev/null'
snap units    bash -c 'ls -la /etc/systemd/system'
snap listen   bash -c 'ss -tulnp 2>/dev/null | sort'
WATCH
    cat > /etc/systemd/system/ccdc-watch.service <<'UNIT'
[Unit]
Description=CCDC persistence-surface diff
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/ccdc-watch
UNIT
    cat > /etc/systemd/system/ccdc-watch.timer <<'UNIT'
[Unit]
Description=Run ccdc-watch every 5 minutes
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s
[Install]
WantedBy=timers.target
UNIT
    run systemctl daemon-reload
    run systemctl enable --now ccdc-watch.timer
    ok "ccdc-watch.timer armed — changes land in syslog tagged 'ccdc-watch'"
  else
    _emit "    would install /usr/local/sbin/ccdc-watch + ccdc-watch.{service,timer} (5 min interval)"
  fi
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
main() {
  parse_args "$@"
  if [[ $APPLY -eq 1 && $HUNT_ONLY -eq 0 && $GENERIC_ACK -eq 0 ]]; then
    die "generic --apply changes SSH, kernel, passwords and audit settings; add --ack-generic-apply after host-specific review"
  fi
  need_root

  mkdir -p "$BACKUP"
  : > "$REPORT"

  _emit "harden-linux.sh v${VERSION}  —  $(date -Is)"
  _emit "mode: $([[ $APPLY -eq 1 ]] && echo 'APPLY (changes will be made)' || echo 'DRY RUN (nothing will change)')"
  _emit "workdir: ${WORKDIR}"

  detect_platform

  # --- hunt: always runs, in full, on every family ---
  hunt_accounts
  hunt_ssh_keys
  hunt_scheduled
  hunt_shell_rc
  hunt_suid_caps
  hunt_listeners
  hunt_webshells

  if [[ $HUNT_ONLY -eq 1 ]]; then
    head2 "done (hunt only)"
    _emit "report: ${REPORT}"
    return 0
  fi

  # --- harden ---
  harden_ssh
  harden_kernel
  harden_mac
  if [[ $ENABLE_EGRESS -eq 1 ]]; then
    harden_egress
  else
    head2 "harden: egress policy"
    log "outbound firewall rules unchanged; use --enable-egress after mapping dependencies"
  fi
  harden_passwords
  harden_web_php
  harden_audit
  install_tripwire

  head2 "done"
  _emit "report:  ${REPORT}"
  _emit "backups: ${BACKUP}  (restore with: cp -a ${BACKUP}/<path> /<path>)"
  if [[ $APPLY -eq 0 ]]; then
    _emit ""
    _emit "This was a DRY RUN. After host-specific review, re-run with --apply --ack-generic-apply and pass"
    _emit "  --ssh-key \"ssh-ed25519 AAAA... you@team\"  to go key-only without locking yourself out."
  else
    _emit ""
    _emit "Now hit every scored service and confirm it is still green."
    _emit "Verify every scored service. Egress, PHP function restrictions and MAC changes"
    _emit "were applied only if their corresponding flags were selected."
  fi
}

main "$@"
