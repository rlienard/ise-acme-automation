# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-03-23

### Added
- Initial release of ISE ACME Certificate Auto-Renewal automation
- Full ACME protocol integration with DigiCert CertCentral
- Cisco ISE Open API integration for certificate lifecycle management
- **Shared certificate mode**: request once, distribute to all PSN nodes
- **Per-node certificate mode**: independent certificates per PSN node
- DNS-01 challenge automation with support for:
  - Cloudflare DNS
  - AWS Route53
  - Azure DNS
- Automatic DNS TXT record creation and cleanup
- DNS propagation verification with retry logic
- Certificate expiry monitoring across all ISE nodes
- Automatic certificate binding to ISE guest portal
- Certificate export/import for shared mode distribution
- Consolidated HTML email notifications with per-node status
- CLI interface with multiple actions:
  - `check` — read-only expiry check
  - `renew` — conditional renewal based on threshold
  - `force-renew` — unconditional renewal
- `--dry-run` flag for safe simulation
- `--mode` flag to override certificate mode via CLI
- Configuration via JSON file or environment variables
- Comprehensive logging with daily log rotation
- Docker support with Dockerfile and docker-compose.yml
- Kubernetes CronJob deployment manifests
- Full documentation and README

### Security
- Support for environment variable-based credential management
- Config file permission recommendations
- `.gitignore` template to prevent credential leaks

---

## [Unreleased]

### Planned
- HashiCorp Vault integration for secrets management
- Slack and Microsoft Teams webhook notifications
- Prometheus metrics endpoint for monitoring
- Certificate backup before renewal
- Automatic rollback on failure
- Parallel node processing for large deployments
- Ansible playbook alternative
- Additional DNS providers (GoDaddy, Namecheap, DigitalOcean)
- Web UI dashboard for certificate status
- Let's Encrypt support as alternative CA
