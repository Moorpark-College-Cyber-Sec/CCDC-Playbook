# Detect pre-planted persistence on an inherited host

Use this procedure during the first minutes on an authorized competition host,
before you trust any local baseline. In CCDC the red team prepares the image
ahead of time, so the box may arrive with backdoors already in place. A hash
baseline captured now would record that implant as "known-good", so run this
triage first, remediate, and capture the integrity baseline (`scripts/fim.sh
--baseline`) only after the host is clean.

It is written for Rocky Linux 9 with systemd, Cronie, and RPM; Debian notes are
included where the command differs. Everything here is read-only evidence
collection — it changes no host settings. A finding is a lead to investigate,
not proof of compromise: record the file, owner, package, and dependency before
you act, and preserve evidence if compromise is suspected. Review every artifact
for credentials or tokens before sharing it.

## 1. Capture a private evidence directory

Keep this root shell open so `$run` stays set.

```bash
sudo -i
run="/root/triage/$(date -u +%Y%m%dT%H%M%SZ)"   # UTC-stamped, unique per run
install -d -m 700 "$run"                          # root-only; evidence may hold secrets
```

## 2. Verify packaged files against the distribution (no baseline needed)

This is the highest-value check on an inherited box: the distribution already
published a checksum for every packaged file, so you can detect a swapped or
trojaned binary without a baseline of your own.

```bash
# Rocky/RHEL: verify every installed package. Output columns are S M 5 D L U G T.
#   S = size changed   5 = MD5/checksum changed   M = mode/permissions changed
# A '5' or 'S' on a BINARY (not a 'c' config file) means the file was altered.
rpm -Va 2>/dev/null | tee "$run/rpm-verify.txt" | awk '$2 != "c" && $1 ~ /5|S/ {print}'
```

```bash
# Debian/Ubuntu equivalent (install first if absent: apt-get install -y debsums):
debsums -ca 2>/dev/null | tee "$run/debsums.txt"   # -c changed only, -a include config
```

A modified `/usr/bin/sshd`, `/bin/ls`, `/usr/bin/ps`, or a PAM module is a strong
rootkit indicator. Confirm against a second source before replacing a binary.

## 3. Find processes whose on-disk binary is gone

A process still running from a deleted executable is a classic in-memory implant
(the attacker unlinks the file to hide it).

```bash
# List running PIDs whose /proc/<pid>/exe target was deleted from disk.
ls -l /proc/*/exe 2>/dev/null | grep '(deleted)' | tee "$run/deleted-exe.txt"
# For each hit, capture the full context before killing anything:
#   ps -fp <pid> ; ls -l /proc/<pid>/cwd ; cat /proc/<pid>/cmdline | tr '\0' ' '
```

## 4. Attribute every listening port to a process and package

Reduce attack surface without breaking scored services: map each listener to its
binary and owning package, then disable only what is unowned or unneeded.

```bash
# For each listening socket, resolve PID -> real binary -> owning package.
ss -tulpnH 2>/dev/null | tee "$run/listeners.txt" \
  | grep -oP 'pid=\K[0-9]+' | sort -u | while read -r pid; do
    exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)                 # real binary behind the socket
    pkg=$(rpm -qf "$exe" 2>/dev/null || dpkg -S "$exe" 2>/dev/null) # package that owns it
    printf 'pid=%-7s exe=%-40s pkg=%s\n' "$pid" "$exe" "${pkg:-<<UNPACKAGED - INVESTIGATE>>}"
  done | tee "$run/port-attribution.txt"
```

Any listener whose binary belongs to no package is a priority lead. Confirm it is
not a legitimate local build before you stop it.

## 5. Sweep the long-tail persistence locations

The obvious spots (user crontabs, `authorized_keys`, enabled services) are worth
checking, but pre-planted persistence usually hides in the places a quick
checklist skips. Capture them all for review.

```bash
# 5a. Non-service systemd activation: timers, paths, sockets, and generators.
systemctl list-units --type=timer,path,socket --all --no-pager > "$run/systemd-activation.txt"
# Drop-in overrides and freshly written units are common hiding spots:
find /etc/systemd/system /run/systemd/system /usr/lib/systemd/system \
  -name '*.service' -o -name '*.timer' -o -name '*.path' 2>/dev/null \
  | xargs -r ls -la --time-style=+%Y-%m-%dT%H:%M 2>/dev/null > "$run/systemd-units.txt"

# 5b. 'at' one-shot jobs (frequently missed by cron-only reviews).
atq 2>/dev/null > "$run/at-jobs.txt"; for j in $(atq 2>/dev/null | cut -f1); do
  printf '\n### at job %s\n' "$j"; at -c "$j" 2>/dev/null; done >> "$run/at-jobs.txt"

# 5c. Cron everywhere, including @reboot lines and system drop-ins.
{ for u in $(cut -d: -f1 /etc/passwd); do
    c=$(crontab -l -u "$u" 2>/dev/null) && [ -n "$c" ] && printf '## %s\n%s\n' "$u" "$c"; done
  echo '## system cron'; cat /etc/crontab 2>/dev/null
  find /etc/cron.* /var/spool/cron -type f 2>/dev/null -exec echo '# {}' \; -exec cat {} \;
} > "$run/cron-all.txt"

# 5d. Auth-time backdoors: PAM modules that exec arbitrary commands.
grep -rE 'pam_exec|pam_python|pam_script' /etc/pam.d/ 2>/dev/null > "$run/pam-hooks.txt"

# 5e. Shell + login init: profile scripts, environment, SSH rc hooks.
ls -la /etc/profile.d /etc/update-motd.d 2>/dev/null > "$run/init-dirs.txt"
grep -rnE 'bash -i|/dev/tcp/|curl .*\|.*sh|wget .*\|.*sh|nc |ncat |python[0-9]* -c' \
  /etc/profile /etc/profile.d /etc/bashrc /etc/bash.bashrc /etc/environment \
  /root/.bashrc /root/.bash_profile /home/*/.bashrc /home/*/.profile \
  /etc/ssh/sshrc /root/.ssh/rc /home/*/.ssh/rc 2>/dev/null > "$run/init-reverse-shells.txt"

# 5f. Event-driven scripts: udev RUN+=, NetworkManager dispatcher, rc.local.
grep -rnE 'RUN\+?=' /etc/udev/rules.d /lib/udev/rules.d 2>/dev/null > "$run/udev-run.txt"
ls -la /etc/NetworkManager/dispatcher.d /etc/rc.d /etc/init.d 2>/dev/null > "$run/event-scripts.txt"
cat /etc/rc.local 2>/dev/null > "$run/rc-local.txt"

# 5g. Loader hijacks: preload file and library search paths.
cat /etc/ld.so.preload 2>/dev/null > "$run/ld-preload.txt"   # should normally be EMPTY/absent
cat /etc/ld.so.conf /etc/ld.so.conf.d/* 2>/dev/null > "$run/ld-conf.txt"

# 5h. Package-manager hooks (persistence that re-fires on every update).
ls -la /etc/dnf/plugins /etc/yum/pluginconf.d 2>/dev/null > "$run/pkg-hooks.txt"   # Rocky/RHEL
ls -la /etc/apt/apt.conf.d 2>/dev/null >> "$run/pkg-hooks.txt"                      # Debian
```

## 6. Rogue accounts and standing SSH access

```bash
# Duplicate UID 0 (only root should be 0); accounts with empty password fields.
awk -F: '$3==0{print "UID0: "$1}' /etc/passwd            | tee "$run/accounts.txt"
awk -F: '$2==""{print "EMPTY-PW: "$1}' /etc/shadow       | tee -a "$run/accounts.txt"
# NOPASSWD sudoers and every authorized_keys with its key fingerprints.
grep -rnE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | tee -a "$run/accounts.txt"
for k in /root/.ssh/authorized_keys* /home/*/.ssh/authorized_keys*; do
  [ -f "$k" ] || continue; printf '\n### %s\n' "$k"
  ssh-keygen -lf "$k" 2>/dev/null   # fingerprint + comment of each key, to eyeball unknowns
done | tee -a "$run/accounts.txt"
```

## 7. Webshells and obfuscated scripts in content roots

```bash
# PHP modified in the last 7 days containing obfuscation/exec primitives = prime leads.
find /var/www /srv/www /usr/share/nginx/html -name '*.php' -mtime -7 2>/dev/null \
  -exec grep -lE 'eval|base64_decode|gzinflate|str_rot13|assert|preg_replace.*/e|\$_(GET|POST|REQUEST)\[' {} + \
  | tee "$run/webshell-candidates.txt"
# Files whose content timestamp was back-dated to hide them (mtime older than ctime):
find /var/www -type f -newerct '1 hour ago' 2>/dev/null > "$run/recently-changed-web.txt"
```

## 8. Triage the output and decide

Work the leads in priority order: altered packaged binaries (step 2), deleted
running executables (step 3), and unowned listeners (step 4) first, because those
need no baseline and rarely produce false positives. For each confirmed finding,
record the evidence, stop or remove the mechanism with one change at a time, and
re-test the required service and remote access path. Kernel-level implants
(modified loadable modules, `ld.so.preload`) may require rebuilding the host
rather than cleaning it — escalate per your team's rules of engagement.

Only once triage is complete and the host is believed clean should you capture
the integrity baseline:

```bash
# After remediation, bless the clean state and start continuous drift alerts.
sudo bash scripts/fim.sh --baseline
sudo bash scripts/fim.sh --install
```

## Validation

These commands are read-only and safe to run on a live host. Confirm each one on
a representative Rocky 9 lab image first so you recognize the normal output, and
keep the `$run` evidence directory for your incident report.
