# CCDC Playbook

Reusable blue-team scripts and guidance for authorized CCDC environments.

## Linux

- [Rocky Linux 9 e-commerce hardening template](scripts/harden-ecom.sh)
- [Portable Linux persistence hunt and hardening template](scripts/harden-linux.sh)
- [Usage, changes from Claude's original draft, and validation](scripts/README.md)
- [Retire unneeded cron jobs, services, and ports](guides/retire-unneeded-jobs-services-ports.md)

Run inventory first and test changes on a representative lab image before
applying them to a scored service. The scripts do not include event-specific
addresses, credentials, or team packet details.
