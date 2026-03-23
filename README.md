# 🔐 ISE ACME Certificate Auto-Renewal

Automated certificate lifecycle management for Cisco ISE guest portals using the ACME protocol with DigiCert CertCentral.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Cisco ISE 3.1+](https://img.shields.io/badge/Cisco%20ISE-3.1+-00bceb.svg)](https://www.cisco.com/c/en/us/products/security/identity-services-engine/index.html)
[![DigiCert ACME](https://img.shields.io/badge/DigiCert-ACME-003A70.svg)](https://www.digicert.com/)

---

## 📋 Table of Contents

- [Why This Project Exists](#-why-this-project-exists)
- [What It Does](#-what-it-does)
- [Architecture](#-architecture)
- [Features](#-features)
- [Prerequisites](#-prerequisites)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [CLI Reference](#-cli-reference)
- [Deployment Methods](#-deployment-methods)
  - [Direct CLI Execution](#1-direct-cli-execution)
  - [Cron Job (Linux)](#2-cron-job-linux)
  - [Windows Task Scheduler](#3-windows-task-scheduler)
  - [Docker](#4-docker)
  - [Kubernetes CronJob](#5-kubernetes-cronjob)
- [Certificate Modes](#-certificate-modes)
- [DNS Providers](#-dns-providers)
- [Email Notifications](#-email-notifications)
- [Security Best Practices](#-security-best-practices)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🤔 Why This Project Exists

Managing SSL/TLS certificates for Cisco ISE guest portals is a **painful, manual, and error-prone process**. In most enterprise environments, it looks like this:

1. 📅 Someone sets a calendar reminder for certificate expiry (hopefully)
2. 🖥️ An admin logs into ISE, generates a CSR manually
3. 📧 The CSR gets emailed to a PKI team or uploaded to a CA portal
4. ⏳ Everyone waits for the signed certificate to come back
5. 📥 The admin manually imports the certificate into ISE
6. 🔗 The certificate gets manually bound to the guest portal
7. 🔁 Repeat for every PSN node in the deployment
8. 🤞 Pray that nothing was missed

**This process breaks.** Certificates expire unexpectedly, guest portals go down, users see security warnings, and helpdesk tickets pile up. In multi-node ISE deployments with 2, 4, or even 10+ PSN nodes, the problem multiplies.

### The Solution

This project **fully automates** the certificate lifecycle using:

- **ACME Protocol (RFC 8555)** — the industry standard for automated certificate management, the same protocol that powers Let's Encrypt
- **DigiCert CertCentral** — enterprise-grade certificates with ACME support
- **Cisco ISE Open APIs** — programmatic certificate management without touching the GUI
- **DNS-01 Challenge Automation** — automatic DNS record creation and cleanup via Cloudflare, AWS Route53, or Azure DNS

The result: **zero-touch certificate renewals** that run on a schedule, renew certificates before they expire, distribute them across all your ISE nodes, and notify your team of the results.

---

## 🔄 What It Does

┌─────────────────────────────────────────────────────────────┐
│ Automated Workflow │
│ │
│ 1. Check certificate expiry on all ISE PSN nodes │
│ 2. If within renewal threshold → initiate ACME request │
│ 3. Retrieve DNS-01 challenge from ISE │
│ 4. Automatically create DNS TXT record via cloud API │
│ 5. Wait for DNS propagation and verify │
│ 6. Trigger ACME challenge validation │
│ 7. Wait for DigiCert to issue the new certificate │
│ 8. Bind certificate to ISE guest portal │
│ 9. (Shared mode) Distribute cert to all secondary nodes │
│ 10. Clean up DNS challenge record │
│ 11. Send email notification with full report │
└─────────────────────────────────────────────────────────────┘

### Before vs. After

| Aspect | Before (Manual) | After (Automated) |
|---|---|---|
| Certificate expiry check | Log into ISE, check manually | ✅ Automated daily check |
| CSR generation | Manual via ISE GUI | ✅ ACME protocol handles it |
| DNS validation | Manually add TXT record | ✅ Cloud DNS API |
| Certificate installation | Manual import | ✅ API-driven |
| Portal binding | Manual assignment | ✅ Automatic |
| Multi-node distribution | Repeat for each PSN | ✅ Automatic distribution |
| DNS cleanup | Manually remove TXT record | ✅ Automatic cleanup |
| Failure notification | None | ✅ Email alerts |
| Time per renewal | 30-60 minutes | ✅ ~5 minutes (unattended) |

---

## 🏗️ Architecture

                ┌──────────────────────────┐
                │    Automation Script      │
                │   (Python / Container)    │
                └─────┬──────┬──────┬──────┘
                      │      │      │
          ┌───────────┘      │      └───────────┐
          │                  │                   │
          ▼                  ▼                   ▼
 ┌────────────────┐  ┌────────────┐   ┌─────────────────┐
 │   Cisco ISE    │  │  DigiCert  │   │  DNS Provider   │
 │   Open API     │  │   ACME     │   │  (Cloudflare /  │
 │                │  │   Server   │   │   Route53 /     │
 │  • Check certs │  │            │   │   Azure DNS)    │
 │  • Request     │  │  • Issue   │   │                 │
 │  • Import      │  │  • Renew   │   │  • Create TXT   │
 │  • Bind        │  │  • Validate│   │  • Delete TXT   │
 └────────────────┘  └────────────┘   └─────────────────┘
          │
     ┌────┴────┐
     │         │
     ▼         ▼
  PSN-01    PSN-02        (... PSN-N)

---

## ✨ Features

- **🔄 Fully Automated Renewal** — zero manual intervention from check to binding
- **🏢 Multi-Node Support** — handles any number of ISE PSN nodes
- **🔗 Shared Certificate Mode** — request once, distribute to all nodes
- **🔀 Per-Node Certificate Mode** — independent certificates per node
- **🌐 Multi-DNS Provider** — Cloudflare, AWS Route53, Azure DNS
- **📧 Email Notifications** — consolidated HTML reports with per-node status
- **🔍 DNS Propagation Verification** — confirms TXT records before validation
- **🧹 Automatic Cleanup** — removes DNS challenge records after use
- **🏃 Dry Run Mode** — simulate without making changes
- **⚡ Force Renewal** — override expiry check when needed
- **📋 Comprehensive Logging** — daily log files with full audit trail
- **🐳 Container Ready** — Docker and Kubernetes deployment support
- **🔐 Flexible Configuration** — JSON config file, environment variables, or CLI overrides

---

## 📦 Prerequisites

### Required
- **Python 3.9+**
- **Cisco ISE 3.1+** (3.2+ recommended for improved ACME support)
- **DigiCert CertCentral** account with ACME enabled
- **ISE Open API** enabled on your PAN node
- **DNS provider** account with API access (Cloudflare, AWS, or Azure)

### ISE Configuration
1. Enable **Open API** on ISE: `Administration → System → Settings → API Settings → Open API → Enable`
2. Create a dedicated **API admin account** with certificate management permissions
3. Configure **ACME CA profile** in ISE: `Administration → System → Certificates → ACME Certification Authorities`

### DigiCert Configuration
1. Log into **CertCentral** → `Automation → ACME Directory URLs`
2. Create an ACME directory and note the:
   - ACME Directory URL
   - Key ID (KID)
   - HMAC Key

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
    git clone https://github.com/yourusername/ise-acme-automation.git
    cd ise-acme-automation

2. Install Dependencies

bash
Copy
pip install -r requirements.txt

3. Configure

bash
Copy
cp config.example.json config.json
# Edit config.json with your environment details

4. Test (Dry Run)

bash
Copy
python ise_acme_automation.py --action check --config config.json

5. Run

bash
Copy
python ise_acme_automation.py --action renew --config config.json


⚙️ Configuration

Configuration File (config.json)

json
Copy
{
    "ise_host": "ise-pan.yourdomain.com",
    "ise_username": "admin",
    "ise_password": "securepassword",
    "ise_ers_port": 9060,
    "ise_open_api_port": 443,
    "acme_directory_url": "https://acme.digicert.com/v2/acme/directory/",
    "acme_kid": "your_digicert_key_id",
    "acme_hmac_key": "your_digicert_hmac_key",
    "common_name": "guest.yourdomain.com",
    "san_names": ["guest.yourdomain.com", "portal.yourdomain.com"],
    "key_type": "RSA_2048",
    "portal_group_tag": "Default Portal Certificate Group",
    "certificate_mode": "shared",
    "primary_node": "ise-psn01.yourdomain.com",
    "ise_nodes": [
        {
            "name": "ise-psn01.yourdomain.com",
            "role": "PSN",
            "enabled": true
        },
        {
            "name": "ise-psn02.yourdomain.com",
            "role": "PSN",
            "enabled": true
        }
    ],
    "renewal_threshold_days": 30,
    "dns_provider": "cloudflare",
    "cloudflare_api_token": "your_token",
    "cloudflare_zone_id": "your_zone_id",
    "smtp_server": "smtp.yourdomain.com",
    "smtp_port": 587,
    "smtp_username": "alerts@yourdomain.com",
    "smtp_password": "smtp_password",
    "alert_recipients": ["netadmin@yourdomain.com"]
}

Configuration Reference

Parameter	Type	Required	Description
ise_host	string	✅	ISE PAN (Primary Admin Node) hostname or IP
ise_username	string	✅	ISE admin username with API access
ise_password	string	✅	ISE admin password
ise_ers_port	integer	❌	ISE ERS API port (default: 9060)
ise_open_api_port	integer	❌	ISE Open API port (default: 443)
acme_directory_url	string	✅	DigiCert ACME directory URL
acme_kid	string	✅	ACME External Account Binding Key ID
acme_hmac_key	string	✅	ACME External Account Binding HMAC Key
common_name	string	✅	Certificate Common Name (e.g., guest.yourdomain.com)
san_names	array	❌	Subject Alternative Names
key_type	string	❌	Key type: RSA_2048, RSA_4096, ECDSA_256 (default: RSA_2048)
portal_group_tag	string	✅	ISE portal certificate group tag
certificate_mode	string	❌	shared or per-node (default: shared)
primary_node	string	❌	Primary node for shared mode (default: first enabled node)
ise_nodes	array	✅	List of ISE PSN nodes
renewal_threshold_days	integer	❌	Days before expiry to trigger renewal (default: 30)
dns_provider	string	✅	DNS provider: cloudflare, aws_route53, azure_dns
cloudflare_api_token	string	⚠️	Cloudflare API token (if using Cloudflare)
cloudflare_zone_id	string	⚠️	Cloudflare Zone ID (if using Cloudflare)
aws_hosted_zone_id	string	⚠️	AWS Route53 Hosted Zone ID (if using AWS)
aws_region	string	⚠️	AWS Region (if using AWS)
azure_subscription_id	string	⚠️	Azure Subscription ID (if using Azure)
azure_resource_group	string	⚠️	Azure Resource Group (if using Azure)
azure_dns_zone_name	string	⚠️	Azure DNS Zone Name (if using Azure)
smtp_server	string	❌	SMTP server for notifications
smtp_port	integer	❌	SMTP port (default: 587)
smtp_username	string	❌	SMTP username
smtp_password	string	❌	SMTP password
alert_recipients	array	❌	Email addresses for notifications

Environment Variables

All configuration parameters can also be set via environment variables, which take precedence over config file defaults:


bash
Copy Code
export ISE_HOST="ise-pan.yourdomain.com"
export ISE_USERNAME="admin"
export ISE_PASSWORD="securepassword"
export ACME_KID="your_key_id"
export ACME_HMAC_KEY="your_hmac_key"
export CERT_CN="guest.yourdomain.com"
export DNS_PROVIDER="cloudflare"
export CLOUDFLARE_API_TOKEN="your_token"
export CLOUDFLARE_ZONE_ID="your_zone_id"
export CERTIFICATE_MODE="shared"
export PRIMARY_NODE="ise-psn01.yourdomain.com"
# ... etc


🖥️ CLI Reference

Syntax

bash
Copy Code
python ise_acme_automation.py [OPTIONS]

Arguments

Argument	Values	Default	Description
--action	check, renew, force-renew	renew	Action to perform
--config	/path/to/config.json	—	Path to configuration file
--dry-run	(flag)	false	Simulate without making changes
--mode	shared, per-node	config value	Override certificate mode

Actions Explained

check — Read-Only Expiry Check

Queries all enabled ISE nodes and reports certificate expiry status. Makes no changes.


bash
Copy Code
python ise_acme_automation.py --action check --config config.json

Example output:


json
Copy Code
{
  "ise-psn01.yourdomain.com": {
    "needs_renewal": false,
    "days_remaining": 45,
    "expiry_date": "2026-05-07T12:00:00.000Z",
    "node": "ise-psn01.yourdomain.com"
  },
  "ise-psn02.yourdomain.com": {
    "needs_renewal": false,
    "days_remaining": 45,
    "expiry_date": "2026-05-07T12:00:00.000Z",
    "node": "ise-psn02.yourdomain.com"
  }
}

renew — Conditional Renewal

Checks certificate expiry on all nodes. If any certificate is within the renewal_threshold_days, it triggers the ACME renewal workflow. This is the default action.


bash
Copy Code
# Standard renewal
python ise_acme_automation.py --action renew --config config.json

# Dry run (check what would happen)
python ise_acme_automation.py --action renew --config config.json --dry-run

force-renew — Unconditional Renewal

Forces certificate renewal on all nodes regardless of current expiry status. Useful for:


Testing the workflow
Rotating certificates after a security incident
Replacing certificates with different parameters

bash
Copy Code
python ise_acme_automation.py --action force-renew --config config.json

Mode Override

Override the certificate_mode setting from the config file:


bash
Copy Code
# Force shared mode
python ise_acme_automation.py --action renew --config config.json --mode shared

# Force per-node mode
python ise_acme_automation.py --action renew --config config.json --mode per-node

Combined Examples

bash
Copy Code
# Daily automated check and renewal
python ise_acme_automation.py --action renew --config /opt/ise-acme/config.json

# Pre-deployment validation (dry run)
python ise_acme_automation.py --action renew --config config.json --dry-run

# Emergency re-key all nodes
python ise_acme_automation.py --action force-renew --config config.json --mode shared

# Quick expiry check from monitoring system
python ise_acme_automation.py --action check --config config.json


🚢 Deployment Methods

1. Direct CLI Execution

The simplest method — run directly on any machine with Python and network access to ISE.


bash
Copy Code
# Install
git clone https://github.com/yourusername/ise-acme-automation.git
cd ise-acme-automation
pip install -r requirements.txt

# Configure
cp config.example.json config.json
vim config.json

# Run
python ise_acme_automation.py --action renew --config config.json

Best for: Testing, one-off executions, small environments.



2. Cron Job (Linux)

Schedule automatic daily execution using cron.


bash
Copy Code
# Edit crontab
crontab -e

# Add the following line (runs daily at 2:00 AM)
0 2 * * * /usr/bin/python3 /opt/ise-acme/ise_acme_automation.py --action renew --config /opt/ise-acme/config.json >> /opt/ise-acme/logs/cron.log 2>&1

Recommended Setup

bash
Copy Code
# Create dedicated directory
sudo mkdir -p /opt/ise-acme
sudo cp ise_acme_automation.py /opt/ise-acme/
sudo cp config.json /opt/ise-acme/
sudo cp requirements.txt /opt/ise-acme/

# Install dependencies
cd /opt/ise-acme
pip install -r requirements.txt

# Secure the config file
sudo chmod 600 /opt/ise-acme/config.json
sudo chown root:root /opt/ise-acme/config.json

# Create log directory
sudo mkdir -p /opt/ise-acme/logs

Cron Schedule Examples

bash
Copy Code
# Every day at 2:00 AM
0 2 * * * /usr/bin/python3 /opt/ise-acme/ise_acme_automation.py --action renew --config /opt/ise-acme/config.json

# Every Monday and Thursday at 3:00 AM
0 3 * * 1,4 /usr/bin/python3 /opt/ise-acme/ise_acme_automation.py --action renew --config /opt/ise-acme/config.json

# Every 12 hours
0 */12 * * * /usr/bin/python3 /opt/ise-acme/ise_acme_automation.py --action check --config /opt/ise-acme/config.json

# First day of every month (force renew)
0 2 1 * * /usr/bin/python3 /opt/ise-acme/ise_acme_automation.py --action force-renew --config /opt/ise-acme/config.json

Best for: Linux servers, VMs, jump hosts with Python already installed.



3. Windows Task Scheduler

For Windows-based environments.


PowerShell Setup

powershell
Copy Code
# Create scheduled task — runs daily at 2:00 AM
$action = New-ScheduledTaskAction `
    -Execute "python" `
    -Argument "C:\ise-acme\ise_acme_automation.py --action renew --config C:\ise-acme\config.json" `
    -WorkingDirectory "C:\ise-acme"

$trigger = New-ScheduledTaskTrigger -Daily -At 2:00AM

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable

Register-ScheduledTask `
    -TaskName "ISE_ACME_Certificate_Renewal" `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Description "Automated ISE certificate renewal via ACME" `
    -User "SYSTEM" `
    -RunLevel Highest

Best for: Windows management servers, environments without Linux.



4. Docker

Containerized deployment for portability and isolation.


Dockerfile

dockerfile
Copy Code
FROM python:3.11-slim

LABEL maintainer="your-email@yourdomain.com"
LABEL description="ISE ACME Certificate Auto-Renewal"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY ise_acme_automation.py .

# Create log directory
RUN mkdir -p /app/logs

# Default command
ENTRYPOINT ["python", "ise_acme_automation.py"]
CMD ["--action", "renew", "--config", "/app/config/config.json"]

Build and Run

bash
Copy Code
# Build the image
docker build -t ise-acme-automation:latest .

# Run with config file mounted
docker run --rm \
  -v $(pwd)/config.json:/app/config/config.json:ro \
  -v $(pwd)/logs:/app/logs \
  ise-acme-automation:latest

# Run with environment variables
docker run --rm \
  -e ISE_HOST="ise-pan.yourdomain.com" \
  -e ISE_USERNAME="admin" \
  -e ISE_PASSWORD="securepassword" \
  -e ACME_KID="your_key_id" \
  -e ACME_HMAC_KEY="your_hmac_key" \
  -e CERT_CN="guest.yourdomain.com" \
  -e DNS_PROVIDER="cloudflare" \
  -e CLOUDFLARE_API_TOKEN="your_token" \
  -e CLOUDFLARE_ZONE_ID="your_zone_id" \
  -e CERTIFICATE_MODE="shared" \
  -v $(pwd)/logs:/app/logs \
  ise-acme-automation:latest

# Check only (dry run)
docker run --rm \
  -v $(pwd)/config.json:/app/config/config.json:ro \
  ise-acme-automation:latest --action check --config /app/config/config.json

# Force renewal
docker run --rm \
  -v $(pwd)/config.json:/app/config/config.json:ro \
  -v $(pwd)/logs:/app/logs \
  ise-acme-automation:latest --action force-renew --config /app/config/config.json

Docker Compose

yaml
Copy Code
# docker-compose.yml
version: "3.8"

services:
  ise-acme:
    build: .
    image: ise-acme-automation:latest
    container_name: ise-acme-renewal
    restart: "no"
    volumes:
      - ./config.json:/app/config/config.json:ro
      - ./logs:/app/logs
    environment:
      - TZ=Europe/Amsterdam
    command: ["--action", "renew", "--config", "/app/config/config.json"]

bash
Copy Code
# Run via Docker Compose
docker-compose run --rm ise-acme

# Check only
docker-compose run --rm ise-acme --action check --config /app/config/config.json

Best for: Containerized environments, CI/CD pipelines, portable deployments.



5. Kubernetes CronJob

Production-grade scheduled execution in Kubernetes.


Kubernetes Secret

yaml
Copy Code
# ise-acme-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: ise-acme-credentials
  namespace: network-automation
type: Opaque
stringData:
  ISE_USERNAME: "admin"
  ISE_PASSWORD: "securepassword"
  ACME_KID: "your_key_id"
  ACME_HMAC_KEY: "your_hmac_key"
  CLOUDFLARE_API_TOKEN: "your_cloudflare_token"
  SMTP_PASSWORD: "your_smtp_password"

Kubernetes ConfigMap

yaml
Copy Code
# ise-acme-configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ise-acme-config
  namespace: network-automation
data:
  config.json: |
    {
      "ise_host": "ise-pan.yourdomain.com",
      "ise_ers_port": 9060,
      "ise_open_api_port": 443,
      "acme_directory_url": "https://acme.digicert.com/v2/acme/directory/",
      "common_name": "guest.yourdomain.com",
      "san_names": ["guest.yourdomain.com", "portal.yourdomain.com"],
      "key_type": "RSA_2048",
      "portal_group_tag": "Default Portal Certificate Group",
      "certificate_mode": "shared",
      "primary_node": "ise-psn01.yourdomain.com",
      "ise_nodes": [
        {"name": "ise-psn01.yourdomain.com", "role": "PSN", "enabled": true},
        {"name": "ise-psn02.yourdomain.com", "role": "PSN", "enabled": true}
      ],
      "renewal_threshold_days": 30,
      "dns_provider": "cloudflare",
      "cloudflare_zone_id": "your_zone_id",
      "smtp_server": "smtp.yourdomain.com",
      "smtp_port": 587,
      "smtp_username": "alerts@yourdomain.com",
      "alert_recipients": ["netadmin@yourdomain.com"]
    }

Kubernetes CronJob

yaml
Copy Code
# ise-acme-cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: ise-acme-renewal
  namespace: network-automation
  labels:
    app: ise-acme
    component: certificate-management
spec:
  schedule: "0 2 * * *"  # Daily at 2:00 AM
  timeZone: "Europe/Amsterdam"
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 7
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      backoffLimit: 2
      activeDeadlineSeconds: 1800  # 30 minute timeout
      template:
        metadata:
          labels:
            app: ise-acme
        spec:
          restartPolicy: OnFailure
          containers:
            - name: ise-acme
              image: ise-acme-automation:latest
              imagePullPolicy: Always
              args:
                - "--action"
                - "renew"
                - "--config"
                - "/app/config/config.json"
              envFrom:
                - secretRef:
                    name: ise-acme-credentials
              volumeMounts:
                - name: config
                  mountPath: /app/config
                  readOnly: true
                - name: logs
                  mountPath: /app/logs
              resources:
                requests:
                  memory: "128Mi"
                  cpu: "100m"
                limits:
                  memory: "256Mi"
                  cpu: "500m"
          volumes:
            - name: config
              configMap:
                name: ise-acme-config
            - name: logs
              emptyDir: {}

Deploy to Kubernetes

bash
Copy Code
# Create namespace
kubectl create namespace network-automation

# Deploy secrets and config
kubectl apply -f ise-acme-secret.yaml
kubectl apply -f ise-acme-configmap.yaml
kubectl apply -f ise-acme-cronjob.yaml

# Verify
kubectl get cronjobs -n network-automation

# Trigger a manual run
kubectl create job --from=cronjob/ise-acme-renewal manual-renewal-001 -n network-automation

# Check job status
kubectl get jobs -n network-automation
kubectl logs job/manual-renewal-001 -n network-automation

# Check next scheduled run
kubectl get cronjob ise-acme-renewal -n network-automation -o jsonpath='{.status.lastScheduleTime}'

Helm Chart (Optional)

For teams using Helm, a basic values.yaml:


yaml
Copy Code
# values.yaml
replicaCount: 1
schedule: "0 2 * * *"
timeZone: "Europe/Amsterdam"

image:
  repository: ise-acme-automation
  tag: latest
  pullPolicy: Always

config:
  ise_host: "ise-pan.yourdomain.com"
  common_name: "guest.yourdomain.com"
  certificate_mode: "shared"
  dns_provider: "cloudflare"

secrets:
  ise_password: ""       # Set via --set or external secret manager
  acme_kid: ""
  acme_hmac_key: ""
  cloudflare_api_token: ""

resources:
  requests:
    memory: "128Mi"
    cpu: "100m"
  limits:
    memory: "256Mi"
    cpu: "500m"

Best for: Production environments, Kubernetes-native infrastructure, teams with existing K8s clusters.



🔗 Certificate Modes

Shared Mode ("certificate_mode": "shared")

One certificate is requested on the primary node and then distributed to all secondary nodes. All nodes use the identical certificate.


Copy Code
  ACME (DigiCert)
       │
       ▼
  1 Certificate
       │
  ┌────┴────┐
  │         │
  ▼         ▼
PSN-01   PSN-02
(primary) (secondary)
 same      same
 cert      cert

When to use:


✅ You want simplicity
✅ All PSN nodes serve the same guest portal FQDN
✅ You use a wildcard or multi-SAN certificate
✅ You want to minimize ACME requests

Per-Node Mode ("certificate_mode": "per-node")

Each node gets its own independent certificate via a separate ACME request.


Copy Code
  ACME (DigiCert)
       │
  ┌────┴────┐
  │         │
  ▼         ▼
Cert A   Cert B
  │         │
  ▼         ▼
PSN-01   PSN-02

When to use:


✅ Each PSN node has a unique FQDN
✅ You want certificate independence between nodes
✅ You prefer no export/import operations between nodes


🌐 DNS Providers

Cloudflare

json
Copy Code
{
  "dns_provider": "cloudflare",
  "cloudflare_api_token": "your_api_token",
  "cloudflare_zone_id": "your_zone_id"
}

Get your credentials: Cloudflare Dashboard → API Tokens → Create Token → Edit Zone DNS


AWS Route53

json
Copy Code
{
  "dns_provider": "aws_route53",
  "aws_hosted_zone_id": "Z1234567890ABC",
  "aws_region": "us-east-1"
}

Requires boto3 and configured AWS credentials (~/.aws/credentials or IAM role).


Azure DNS

json
Copy Code
{
  "dns_provider": "azure_dns",
  "azure_subscription_id": "your-subscription-id",
  "azure_resource_group": "your-rg",
  "azure_dns_zone_name": "yourdomain.com"
}

Requires azure-mgmt-dns, azure-identity, and Azure credentials (service principal or managed identity).



📧 Email Notifications

The script sends HTML-formatted email reports after each run:


✅ Success Report

Copy Code
Subject: [ISE ACME] All Nodes OK

┌──────────────────────────┬──────────┬──────────────────────────┐
│ ISE Node                 │ Status   │ Details                  │
├──────────────────────────┼──────────┼──────────────────────────┤
│ 🟢 ise-psn01 [PRIMARY]  │ RENEWED  │ Expires 2027-03-23       │
│ 🟢 ise-psn02            │ RENEWED  │ Expires 2027-03-23       │
└──────────────────────────┴──────────┴──────────────────────────┘

❌ Failure Report

Copy Code
Subject: [ISE ACME] ⚠️ Some Nodes Failed

┌──────────────────────────┬──────────┬──────────────────────────┐
│ ISE Node                 │ Status   │ Details                  │
├──────────────────────────┼──────────┼──────────────────────────┤
│ 🟢 ise-psn01 [PRIMARY]  │ RENEWED  │ Expires 2027-03-23       │
│ 🔴 ise-psn02            │ FAILED   │ Import failed: timeout   │
└──────────────────────────┴──────────┴──────────────────────────┘


🔒 Security Best Practices

Practice	Recommendation
Credentials	Use environment variables or a secrets manager — never commit config.json with real passwords
Config file permissions	chmod 600 config.json — restrict to owner only
ISE API account	Create a dedicated service account with minimum required permissions
Network access	Run from a management VLAN with restricted access to ISE and DNS APIs
Secrets management	Use HashiCorp Vault, AWS Secrets Manager, or Kubernetes Secrets
Git safety	Add config.json to .gitignore — use config.example.json as a template
Audit trail	Ship logs to your SIEM (Splunk, ELK, etc.)
TLS verification	In production, import ISE's CA cert and set verify=True

.gitignore

Copy Code
config.json
*.log
logs/
__pycache__/
.env


🔧 Troubleshooting

Issue	Cause	Solution
Connection refused to ISE	Open API not enabled or firewall	Enable Open API in ISE; check firewall rules for port 443/9060
401 Unauthorized	Wrong ISE credentials	Verify username/password; ensure API access is enabled for the account
DNS TXT record not found	DNS propagation delay	Increase wait time; verify DNS provider credentials
ACME challenge failed	TXT record incorrect or not propagated	Check DNS record value matches exactly; try DNS-01 debug
Certificate not issued	DigiCert validation pending	Check CertCentral dashboard for pending orders; verify organization validation
Import failed on secondary	Certificate export permissions	Ensure ISE admin has certificate export permissions
Email notification failed	SMTP configuration	Verify SMTP server, port, credentials; check firewall for outbound SMTP
Timeout waiting for cert	Slow issuance	Increase max_wait parameter; check DigiCert ACME endpoint status

Debug Logging

For verbose output, modify the logging level in the script:


python
Copy Code
logging.basicConfig(level=logging.DEBUG, ...)

Log Files

Logs are written to the logs/ directory with daily rotation:


Copy Code
logs/
├── ise_acme_20260323.log
├── ise_acme_20260324.log
└── ...


🤝 Contributing

Contributions are welcome! Please:


Fork the repository
Create a feature branch (git checkout -b feature/amazing-feature)
Commit your changes (git commit -m 'Add amazing feature')
Push to the branch (git push origin feature/amazing-feature)
Open a Pull Request

Ideas for Contribution

Add support for additional DNS providers (GoDaddy, Namecheap, etc.)
Add HashiCorp Vault integration for secrets
Add Slack/Teams webhook notifications
Add Prometheus metrics endpoint
Add certificate backup before renewal
Add automatic rollback on failure
Create Ansible playbook alternative
Create Terraform module for infrastructure setup

📄 License

This project is licensed under the MIT License — see the LICENSE file for details.

🙏 Acknowledgments

Cisco ISE API Documentation
DigiCert ACME Documentation
RFC 8555 — Automatic Certificate Management Environment (ACME)
Cloudflare API Documentation


Made with ❤️ for network engineers who are tired of manually renewing certificates.
