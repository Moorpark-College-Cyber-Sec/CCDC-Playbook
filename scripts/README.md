# Linux hardening playbook

These scripts are templates for authorized CCDC blue-team work. Inventory first,
map dependencies, keep console access, and verify the required service paths
after every change. Neither script has been validated against a live competition
image.

For manual cleanup of cron jobs, services, and firewall openings, use the
[staged retirement guide](../guides/retire-unneeded-jobs-services-ports.md).

| Script | Scope |
| --- | --- |
| [`harden-ecom.sh`](harden-ecom.sh) | Rocky Linux 9 store host. Captures an inventory by default and makes higher-risk controls opt-in. |
| [`harden-linux.sh`](harden-linux.sh) | Portable persistence hunt and broad hardening for other Linux hosts. Generic `--apply` requires `--ack-generic-apply` after host-specific review. |

## What changed from Claude's original draft

The earlier e-commerce profile invoked the portable script's full `--apply`
path before changing the web and database services. This version gives the
Rocky profile its own inventory and apply sequence.

| Earlier behavior | Revised Rocky profile |
| --- | --- |
| Generic SSH, kernel, firewall, PHP, and MAC changes ran first. | Baseline is scoped to Rocky 9 and requires an explicit active firewalld interface and zone. |
| Outbound traffic became default deny with a small allowlist. | Outbound deny is opt-in with `--enable-egress` after mapping DNS, time, updates, payment, mail, database, and logging flows. |
| PHP functions and SELinux web booleans were changed globally. | Current settings are recorded for review; the script does not toggle them wholesale. |
| Apache was restarted and webroot permissions changed recursively. | No web service restart or webroot mutation. |
| Database bind address, grants, and service state were changed. | No automatic database changes. |
| Password and root SSH behavior followed the generic script. | `--key-only` requires a preflighted admin key; `--deny-root-ssh` is separate. The baseline preserves existing password and root login settings. |
| Broad inbound and reverse-path filtering could affect availability. | Required inbound services are added without source filters; pruning is opt-in. Strict `rp_filter` is not forced and ICMP echo is not blocked. |

The portable script remains available for investigation. Its apply path is
broad: it can change SSH, egress, PHP, SELinux/AppArmor, password policy, and
services. Review its full output and test on a matching lab host before using
`--ack-generic-apply`.

## Rocky workflow

Run these commands from the repository root on the Rocky host. Inventory writes
private evidence under `/root/ccdc-hardening/` without changing host settings.

```bash
sudo bash scripts/harden-ecom.sh
sudo ls -dt /root/ccdc-hardening/* | head
ip -br address
sudo firewall-cmd --get-active-zones
```

Review listeners, accounts, keys, firewall state, SELinux booleans, and store
dependencies. Once the production interface is identified, apply the baseline:

```bash
sudo bash scripts/harden-ecom.sh --apply --interface <interface>
```

The default inbound services are `ssh,http,https`. Add any other required
service or port through `--in-services` and `--in-ports`. Test remote SSH,
HTTP/HTTPS content, ping, and the full store workflow immediately after apply.

| Optional flag | Use only after |
| --- | --- |
| `--admin USER --key-only` | A working second SSH session proves key login, and password login is not required. |
| `--deny-root-ssh` | Root SSH is not required for operations or service checks. |
| `--prune-inbound` | Every required inbound service has been mapped and listed. |
| `--enable-egress --out-ports CSV` | All outbound application dependencies are mapped and tested, including IPv6. |

Each run records a baseline, run log, after-state, and backups of overwritten
files. A newly created file has no previous copy; remove it to undo that file.
Firewalld changes also require inspecting the saved zone and policy state before
rollback.

## IDS, IPS, decoys, and packet visibility

Start web and host detection in alert-only mode. Review alerts against normal
store traffic and service checks before enabling any block rule. Keep decoys on
non-required ports and paths. Packet mirroring needs control of an existing
network device or sensor path; this host script does not configure a switch or
create a sensor VM. Use scoped host logs or a short authorized packet capture
when a mirror is unavailable.

## Validation

```bash
bash -n scripts/harden-linux.sh scripts/harden-ecom.sh
```

Syntax validation does not prove firewalld policy behavior or application
compatibility. Run inventory and staged apply on a representative Rocky 9 lab
image, then verify SSH, web content, ping, store transactions, dependencies,
and rollback before live use.
