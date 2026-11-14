# CCDC Playbook

Reusable blue-team scripts and guidance for authorized CCDC environments.

## Linux

- [Rocky Linux 9 e-commerce hardening template](scripts/harden-ecom.sh)
- [Portable Linux persistence hunt and hardening template](scripts/harden-linux.sh)
- [Standalone stateful firewall with lockout-safe test mode](scripts/packet-filter.sh)
- [File-integrity monitor — alert on changes outside a whitelist](scripts/fim.sh)
- [Usage, changes from Claude's original draft, and validation](scripts/README.md)
- [Audit and retire unneeded cron jobs, services, and ports](guides/retire-unneeded-jobs-services-ports.md)
- [Detect pre-planted persistence on an inherited host](guides/detect-preplanted-persistence.md)

Run inventory first and test changes on a representative lab image before
applying them to a scored service. The scripts do not include event-specific
addresses, credentials, or team packet details.

Licensed under the [MIT License](LICENSE).
