# Retire unneeded cron jobs, services, and ports

Use this procedure on an authorized Linux host after identifying the services
that must remain available. It is written for Rocky Linux 9 with systemd,
Cronie, and firewalld. Apply one change at a time from a console or a second
working session. Test the required application and remote access path after
each change.

An unfamiliar job or listener is a lead to investigate, not proof that it is
unneeded or malicious. Record its owner, command, schedule or trigger, network
binding, package, and application dependency before changing it. Preserve
evidence if compromise is suspected.

## 1. Capture a private baseline

Start a root shell and keep it open so `$run` remains set. Save the current
state in a root-only directory. The commands below capture evidence without
changing service configuration.
Review the output for credentials or tokens before sharing any artifact.

```bash
sudo -i
run="/root/service-review/$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 700 "$run"

ss -lntup > "$run/listeners.txt"
systemctl list-units --type=service --state=running --no-pager > "$run/running-services.txt"
systemctl list-unit-files --type=service --no-pager > "$run/service-unit-files.txt"
systemctl list-sockets --all --no-pager > "$run/sockets.txt"
systemctl list-timers --all --no-pager > "$run/timers.txt"
firewall-cmd --get-active-zones > "$run/active-zones.txt"
firewall-cmd --list-all-zones > "$run/firewall-runtime.txt"
firewall-cmd --permanent --list-all-zones > "$run/firewall-permanent.txt"

for account in $(getent passwd | cut -d: -f1); do
  printf '\n### %s\n' "$account"
  crontab -u "$account" -l 2>/dev/null || :
done > "$run/user-crontabs.txt"
find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly \
  /etc/cron.monthly -maxdepth 1 -type f -print 2>/dev/null \
  > "$run/system-cron-files.txt"
cp -a /etc/crontab "$run/system-crontab"
```

If firewalld is inactive, record the actual firewall backend (`nft list
ruleset`, for example) and use its own documented rollback procedure. A
firewall opening and a listening process are different: closing one does not
necessarily remove the other.

For each candidate, write down its original state and a way to verify that
required traffic still works:

| Candidate | Owner and purpose | Trigger or unit | Port and zone | Required path to test | Undo |
| --- | --- | --- | --- | --- | --- |
| Fill in before changing | | | | | |

## 2. Retire one scheduled task

Check user crontabs, `/etc/crontab`, `/etc/cron.d/`, the periodic cron
directories, and systemd timers. A timer can run a service even when no cron
entry exists. Cronie manages user crontabs through `crontab`; do not edit its
spool files directly ([Cronie `crontab(1)`](https://man7.org/linux/man-pages/man1/crontab.1.html)).

For a **user crontab**, substitute the account name, save its entire table,
then edit only the candidate line. Comment the line with a reason and time.

```bash
account=ACCOUNT_NAME
crontab -u "$account" -l > "$run/${account}.crontab"
crontab -u "$account" -e
crontab -u "$account" -l
```

Undo by reinstalling the saved table, after confirming it does not overwrite
legitimate changes made since the backup:

```bash
crontab -u "$account" "$run/${account}.crontab"
```

For a **single file in `/etc/cron.d/` or a periodic cron directory**, inspect
its content and package owner first. Move only that file to the root-only
quarantine; keep its name and metadata for rollback. Replace the example path
with the exact file selected during review.

```bash
job=/etc/cron.d/EXAMPLE_JOB
quarantine="$run/quarantine$job"
cat "$job"
rpm -qf "$job" || :
install -d -m 700 "$(dirname "$quarantine")"
mv -- "$job" "$quarantine"
```

Undo by moving the quarantined file back and restoring its SELinux context:

```bash
mv -- "$quarantine" "$job"
restorecon -v "$job"
```

A package update may reinstall a packaged cron file. Recheck it after updates.

For an entry in `/etc/crontab`, back up the file and comment only the selected
line in an editor; preserve the file's format and ownership. Do not shut down
`crond` to suppress one job. Avoid `crontab -r`, which removes the entire user
table ([Cronie `crontab(1)`](https://man7.org/linux/man-pages/man1/crontab.1.html)).

For a **systemd timer**, inspect both the timer and the service it activates.
Replace `EXAMPLE.service` with the unit shown in the timer's `ACTIVATES` column.
Stop the timer first, verify the application path, then disable it if the
change should persist. A service already running may need a separate decision.

```bash
systemctl cat EXAMPLE.timer
systemctl status EXAMPLE.timer EXAMPLE.service --no-pager
systemctl stop EXAMPLE.timer
systemctl list-timers --all --no-pager
```

After the required paths still work and the timer is confirmed unneeded,
disable its next-boot activation:

```bash
systemctl disable EXAMPLE.timer
```

Undo with `systemctl enable --now EXAMPLE.timer` only if it was originally
enabled; otherwise use `systemctl start EXAMPLE.timer`. See the
[systemd unit controls](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/configuring_basic_system_settings/managing-systemd_configuring-basic-system-settings).

## 3. Stop one unneeded service

Map the listener to its process and unit. Inspect the unit definition, logs,
dependencies, sockets, and timers before stopping it. A socket unit can
reactivate a service, so include it in the review
([`systemctl` reference](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html)).

```bash
ss -lntup
systemctl status EXAMPLE.service --no-pager
systemctl cat EXAMPLE.service
systemctl list-dependencies --reverse EXAMPLE.service --no-pager
systemctl list-sockets --all --no-pager
systemctl list-timers --all --no-pager
```

Record `systemctl is-enabled EXAMPLE.service` before changing it. Stop the
service for the current session, test from another host, and only then disable
startup. If an associated socket is confirmed unneeded, stop and disable that
socket separately. `disable` alone does not stop a running unit; `mask` is a
stronger block and is not part of this routine procedure
([RHEL 9 systemd guide](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/configuring_basic_system_settings/managing-systemd_configuring-basic-system-settings)).

```bash
systemctl is-enabled EXAMPLE.service
systemctl stop EXAMPLE.service
ss -lntup
```

After external checks pass, disable the service at startup:

```bash
systemctl disable EXAMPLE.service
```

Undo the immediate stop with `systemctl start EXAMPLE.service`. Re-enable it
only if it was enabled before the change. Inspect and restore any associated
socket or timer in the same way. Treat remote access, network management,
logging, time synchronization, web, and database services as required until
their actual dependencies are known.

## 4. Close one unneeded firewalld opening

Identify the production interface and its zone. Check whether the zone is
shared by other interfaces or sources. Review runtime and permanent services,
ports, rich rules, and policies; a named service and a raw port can both admit
traffic ([firewalld CLI](https://firewalld.org/documentation/utilities/firewall-cmd.html)).

```bash
iface=YOUR_INTERFACE
zone=$(firewall-cmd --get-zone-of-interface="$iface")
firewall-cmd --get-active-zones
firewall-cmd --zone="$zone" --list-all
firewall-cmd --permanent --zone="$zone" --list-all
firewall-cmd --list-all-policies
```

If the interface has no active zone, or the zone also carries traffic for
another interface or source, resolve that mapping before removing an opening.

Test a **service opening** in runtime first. Substitute a service name shown
in the chosen zone. Verify required traffic from another host. If anything
fails, restore the runtime opening immediately. Once the change is proven,
apply it to permanent configuration and reload, then test again.

```bash
svc=UNNEEDED_FIREWALLD_SERVICE
firewall-cmd --zone="$zone" --remove-service="$svc"
```

Test required paths from another host. If a path fails, restore the runtime
opening and investigate:

```bash
firewall-cmd --zone="$zone" --add-service="$svc"
```

If the tests pass, save the removal and reload:

```bash
firewall-cmd --permanent --zone="$zone" --remove-service="$svc"
firewall-cmd --reload
firewall-cmd --zone="$zone" --list-all
```

For a raw port opening, use the same sequence with `--remove-port=PORT/PROTO`
and `--add-port=PORT/PROTO`. Record the original service or port entry before
changing it. After a permanent removal, restore the opening with
`--permanent --add-service` or `--permanent --add-port`, followed by
`firewall-cmd --reload`; this also restores runtime. Runtime rules disappear
at reload; permanent rules then become effective
([firewalld runtime versus permanent](https://firewalld.org/documentation/configuration/runtime-versus-permanent.html)).

Do not close a port merely because it is unfamiliar. Confirm the scoring and
application requirements first. This procedure does not add source-only
allowlists or disable ICMP echo.

## 5. Confirm the result and keep rollback ready

After each change, compare `ss -lntup`, unit and timer state, the selected zone,
and application logs with the baseline. Test remote login, required web
content, application transactions, DNS and time dependencies, and any scored
checks from a separate host. Observe at least one normal schedule interval
before treating a retired job as safe. Keep the root-only evidence and exact
undo command with the change record.

```bash
ss -lntup
systemctl --failed --no-pager
systemctl list-timers --all --no-pager
firewall-cmd --zone="$zone" --list-all
```
