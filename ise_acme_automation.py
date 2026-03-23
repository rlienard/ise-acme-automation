#!/usr/bin/env python3
"""
ISE ACME Certificate Auto-Renewal Automation Script (Multi-Node, Shared Certificate)
Automates: DNS-01 challenge, certificate request, binding, monitoring
Compatible with: Cisco ISE 3.1+ | DigiCert CertCentral ACME | Multiple DNS Providers
Supports: Multiple PSN nodes with shared or per-node certificate modes
"""

import os
import sys
import json
import time
import logging
import argparse
import requests
import subprocess
import urllib3
from datetime import datetime, timedelta
from pathlib import Path

# Suppress insecure HTTPS warnings for ISE self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ──────────────────────────────────────────────
# CONFIGURATION — Update these values or use env vars
# ──────────────────────────────────────────────

CONFIG = {
    # Cisco ISE Settings
    "ise_host": os.getenv("ISE_HOST", "ise-pan.yourdomain.com"),
    "ise_username": os.getenv("ISE_USERNAME", "admin"),
    "ise_password": os.getenv("ISE_PASSWORD", "your_ise_password"),
    "ise_ers_port": int(os.getenv("ISE_ERS_PORT", "9060")),
    "ise_open_api_port": int(os.getenv("ISE_OPEN_API_PORT", "443")),

    # ACME / DigiCert Settings
    "acme_directory_url": os.getenv("ACME_DIRECTORY_URL", "https://acme.digicert.com/v2/acme/directory/"),
    "acme_kid": os.getenv("ACME_KID", "your_key_id"),
    "acme_hmac_key": os.getenv("ACME_HMAC_KEY", "your_hmac_key"),

    # Certificate Settings
    "common_name": os.getenv("CERT_CN", "guest.yourdomain.com"),
    "san_names": os.getenv("CERT_SAN", "guest.yourdomain.com,portal.yourdomain.com").split(","),
    "key_type": os.getenv("CERT_KEY_TYPE", "RSA_2048"),
    "portal_group_tag": os.getenv("PORTAL_GROUP_TAG", "Default Portal Certificate Group"),
    "renewal_threshold_days": int(os.getenv("RENEWAL_THRESHOLD_DAYS", "30")),

    # Certificate Mode: "shared" (one cert for all nodes) or "per-node" (individual certs)
    "certificate_mode": os.getenv("CERTIFICATE_MODE", "shared"),

    # Primary node for shared certificate mode (cert is requested here first)
    "primary_node": os.getenv("PRIMARY_NODE", "ise-psn01.yourdomain.com"),

    # Multiple ISE PSN Nodes
    "ise_nodes": json.loads(os.getenv("ISE_NODES", json.dumps([
        {
            "name": "ise-psn01.yourdomain.com",
            "role": "PSN",
            "enabled": True
        },
        {
            "name": "ise-psn02.yourdomain.com",
            "role": "PSN",
            "enabled": True
        }
    ]))),

    # DNS Provider: "cloudflare", "aws_route53", or "azure_dns"
    "dns_provider": os.getenv("DNS_PROVIDER", "cloudflare"),

    # Cloudflare DNS Settings
    "cloudflare_api_token": os.getenv("CLOUDFLARE_API_TOKEN", "your_cloudflare_token"),
    "cloudflare_zone_id": os.getenv("CLOUDFLARE_ZONE_ID", "your_zone_id"),

    # AWS Route53 Settings (alternative)
    "aws_hosted_zone_id": os.getenv("AWS_HOSTED_ZONE_ID", "your_hosted_zone_id"),
    "aws_region": os.getenv("AWS_REGION", "us-east-1"),

    # Azure DNS Settings (alternative)
    "azure_subscription_id": os.getenv("AZURE_SUBSCRIPTION_ID", ""),
    "azure_resource_group": os.getenv("AZURE_RESOURCE_GROUP", ""),
    "azure_dns_zone_name": os.getenv("AZURE_DNS_ZONE_NAME", ""),

    # Notification Settings
    "smtp_server": os.getenv("SMTP_SERVER", "smtp.yourdomain.com"),
    "smtp_port": int(os.getenv("SMTP_PORT", "587")),
    "smtp_username": os.getenv("SMTP_USERNAME", "alerts@yourdomain.com"),
    "smtp_password": os.getenv("SMTP_PASSWORD", "your_smtp_password"),
    "alert_recipients": os.getenv("ALERT_RECIPIENTS", "netadmin@yourdomain.com").split(","),
}

# ──────────────────────────────────────────────
# LOGGING SETUP
# ──────────────────────────────────────────────

log_dir = Path("logs")
log_dir.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(f"logs/ise_acme_{datetime.now().strftime('%Y%m%d')}.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════
# ISE API CLIENT
# ══════════════════════════════════════════════

class ISEClient:
    """Handles all Cisco ISE API interactions."""

    def __init__(self, config):
        self.host = config["ise_host"]
        self.username = config["ise_username"]
        self.password = config["ise_password"]
        self.ers_port = config["ise_ers_port"]
        self.open_api_port = config["ise_open_api_port"]
        self.base_ers_url = f"https://{self.host}:{self.ers_port}/ers"
        self.base_open_api_url = f"https://{self.host}:{self.open_api_port}/api/v1"
        self.session = requests.Session()
        self.session.auth = (self.username, self.password)
        self.session.verify = False
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json"
        })

    def get_system_certificates(self, node_name):
        """Retrieve all system certificates from a specific ISE node."""
        url = f"{self.base_open_api_url}/certs/system-certificate/{node_name}"
        try:
            response = self.session.get(url)
            response.raise_for_status()
            certs = response.json().get("response", [])
            logger.info(f"[{node_name}] Retrieved {len(certs)} system certificates.")
            return certs
        except requests.exceptions.RequestException as e:
            logger.error(f"[{node_name}] Failed to retrieve certificates: {e}")
            raise

    def get_certificate_by_cn(self, common_name, node_name):
        """Find a specific certificate by Common Name on a given node."""
        certs = self.get_system_certificates(node_name)
        for cert in certs:
            if common_name in cert.get("friendlyName", "") or \
               common_name in cert.get("subject", ""):
                logger.info(f"[{node_name}] Found certificate for {common_name}: ID={cert.get('id')}")
                return cert
        logger.warning(f"[{node_name}] No certificate found for CN={common_name}")
        return None

    def check_certificate_expiry(self, common_name, threshold_days, node_name):
        """Check if a certificate is nearing expiry on a specific node."""
        cert = self.get_certificate_by_cn(common_name, node_name)
        if not cert:
            return {
                "needs_renewal": True,
                "reason": "Certificate not found",
                "node": node_name
            }

        expiry_str = cert.get("expirationDate", "")
        try:
            expiry_date = datetime.strptime(expiry_str, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            try:
                expiry_date = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                logger.error(f"[{node_name}] Cannot parse expiry date: {expiry_str}")
                return {
                    "needs_renewal": True,
                    "reason": "Cannot parse expiry date",
                    "node": node_name
                }

        days_remaining = (expiry_date - datetime.utcnow()).days
        needs_renewal = days_remaining <= threshold_days

        result = {
            "needs_renewal": needs_renewal,
            "days_remaining": days_remaining,
            "expiry_date": expiry_str,
            "certificate_id": cert.get("id"),
            "friendly_name": cert.get("friendlyName"),
            "node": node_name
        }

        if needs_renewal:
            logger.warning(f"[{node_name}] Certificate expires in {days_remaining} days — RENEWAL NEEDED")
        else:
            logger.info(f"[{node_name}] Certificate expires in {days_remaining} days — OK")

        return result

    def initiate_acme_certificate_request(self, common_name, san_names, key_type,
                                           node_name, portal_group_tag):
        """Initiate ACME certificate request via ISE Open API for a specific node."""
        url = f"{self.base_open_api_url}/certs/system-certificate/acme"

        payload = {
            "nodeName": node_name,
            "commonName": common_name,
            "subjectAlternativeNames": ",".join(san_names),
            "keyType": key_type,
            "usedBy": "Portal",
            "portalGroupTag": portal_group_tag,
            "autoRenew": True,
            "allowWildcardCerts": "*" in common_name,
        }

        try:
            response = self.session.post(url, json=payload)
            response.raise_for_status()
            result = response.json()
            logger.info(f"[{node_name}] ACME certificate request initiated: {result}")
            return result
        except requests.exceptions.RequestException as e:
            logger.error(f"[{node_name}] Failed to initiate ACME certificate request: {e}")
            raise

    def get_acme_challenge(self, request_id, node_name):
        """Retrieve the ACME DNS-01 challenge details."""
        url = f"{self.base_open_api_url}/certs/acme-challenge/{request_id}"
        try:
            response = self.session.get(url)
            response.raise_for_status()
            challenge = response.json()
            logger.info(f"[{node_name}] ACME challenge retrieved: {challenge}")
            return challenge
        except requests.exceptions.RequestException as e:
            logger.error(f"[{node_name}] Failed to retrieve ACME challenge: {e}")
            raise

    def confirm_acme_challenge(self, request_id, node_name):
        """Notify ISE that the DNS challenge has been fulfilled."""
        url = f"{self.base_open_api_url}/certs/acme-challenge/{request_id}/validate"
        try:
            response = self.session.post(url)
            response.raise_for_status()
            result = response.json()
            logger.info(f"[{node_name}] ACME challenge validation triggered: {result}")
            return result
        except requests.exceptions.RequestException as e:
            logger.error(f"[{node_name}] Failed to confirm ACME challenge: {e}")
            raise

    def export_certificate(self, cert_id, node_name):
        """Export a certificate (with private key) from a specific node."""
        url = f"{self.base_open_api_url}/certs/system-certificate/{node_name}/{cert_id}/export"
        try:
            response = self.session.get(url)
            response.raise_for_status()
            cert_data = response.json()
            logger.info(f"[{node_name}] Certificate {cert_id} exported successfully")
            return cert_data
        except requests.exceptions.RequestException as e:
            logger.error(f"[{node_name}] Failed to export certificate: {e}")
            raise

    def import_certificate(self, cert_data, node_name, portal_group_tag):
        """Import a certificate (with private key) to a specific node."""
        url = f"{self.base_open_api_url}/certs/system-certificate/{node_name}/import"

        payload = {
            "certData": cert_data.get("certData"),
            "privateKeyData": cert_data.get("privateKeyData"),
            "usedBy": "Portal",
            "portalGroupTag": portal_group_tag,
            "allowExtendedValidity": True
        }

        try:
            response = self.session.post(url, json=payload)
            response.raise_for_status()
            result = response.json()
            logger.info(f"[{node_name}] Certificate imported successfully: {result}")
            return result
        except requests.exceptions.RequestException as e:
            logger.error(f"[{node_name}] Failed to import certificate: {e}")
            raise

    def bind_certificate_to_portal(self, cert_id, portal_group_tag, node_name):
        """Bind a system certificate to the guest portal on a specific node."""
        url = f"{self.base_open_api_url}/certs/system-certificate/{node_name}/{cert_id}"

        payload = {
            "usedBy": "Portal",
            "portalGroupTag": portal_group_tag
        }

        try:
            response = self.session.put(url, json=payload)
            response.raise_for_status()
            logger.info(
                f"[{node_name}] Certificate {cert_id} bound to "
                f"portal group '{portal_group_tag}'"
            )
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"[{node_name}] Failed to bind certificate to portal: {e}")
            raise


# ══════════════════════════════════════════════
# DNS PROVIDER CLIENTS
# ══════════════════════════════════════════════

class CloudflareDNS:
    """Manage DNS TXT records via Cloudflare API."""

    def __init__(self, config):
        self.api_token = config["cloudflare_api_token"]
        self.zone_id = config["cloudflare_zone_id"]
        self.base_url = "https://api.cloudflare.com/client/v4"
        self.headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        }

    def create_txt_record(self, record_name, record_value, ttl=120):
        """Create a DNS TXT record for ACME challenge."""
        url = f"{self.base_url}/zones/{self.zone_id}/dns_records"
        payload = {
            "type": "TXT",
            "name": record_name,
            "content": record_value,
            "ttl": ttl
        }

        response = requests.post(url, headers=self.headers, json=payload)
        response.raise_for_status()
        result = response.json()

        if result.get("success"):
            record_id = result["result"]["id"]
            logger.info(f"DNS TXT record created: {record_name} = {record_value} (ID: {record_id})")
            return record_id
        else:
            logger.error(f"Failed to create DNS record: {result.get('errors')}")
            raise Exception(f"Cloudflare DNS error: {result.get('errors')}")

    def delete_txt_record(self, record_id):
        """Clean up the DNS TXT record after validation."""
        url = f"{self.base_url}/zones/{self.zone_id}/dns_records/{record_id}"
        response = requests.delete(url, headers=self.headers)
        response.raise_for_status()
        logger.info(f"DNS TXT record deleted: {record_id}")

    def find_txt_record(self, record_name):
        """Find existing TXT record by name."""
        url = f"{self.base_url}/zones/{self.zone_id}/dns_records"
        params = {"type": "TXT", "name": record_name}
        response = requests.get(url, headers=self.headers, params=params)
        response.raise_for_status()
        records = response.json().get("result", [])
        return records


class AWSRoute53DNS:
    """Manage DNS TXT records via AWS Route53."""

    def __init__(self, config):
        try:
            import boto3
            self.client = boto3.client("route53", region_name=config["aws_region"])
        except ImportError:
            raise ImportError("boto3 is required for AWS Route53. Install with: pip install boto3")
        self.hosted_zone_id = config["aws_hosted_zone_id"]

    def create_txt_record(self, record_name, record_value, ttl=120):
        """Create/update a DNS TXT record in Route53."""
        response = self.client.change_resource_record_sets(
            HostedZoneId=self.hosted_zone_id,
            ChangeBatch={
                "Changes": [{
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": record_name,
                        "Type": "TXT",
                        "TTL": ttl,
                        "ResourceRecords": [{"Value": f'"{record_value}"'}]
                    }
                }]
            }
        )
        change_id = response["ChangeInfo"]["Id"]
        logger.info(f"Route53 TXT record created: {record_name} (Change ID: {change_id})")
        return change_id

    def delete_txt_record(self, record_id, record_name=None, record_value=None):
        """Delete a DNS TXT record from Route53."""
        if record_name and record_value:
            self.client.change_resource_record_sets(
                HostedZoneId=self.hosted_zone_id,
                ChangeBatch={
                    "Changes": [{
                        "Action": "DELETE",
                        "ResourceRecordSet": {
                            "Name": record_name,
                            "Type": "TXT",
                            "TTL": 120,
                            "ResourceRecords": [{"Value": f'"{record_value}"'}]
                        }
                    }]
                }
            )
            logger.info(f"Route53 TXT record deleted: {record_name}")


class AzureDNS:
    """Manage DNS TXT records via Azure DNS."""

    def __init__(self, config):
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.dns import DnsManagementClient
            credential = DefaultAzureCredential()
            self.client = DnsManagementClient(credential, config["azure_subscription_id"])
        except ImportError:
            raise ImportError(
                "azure-mgmt-dns is required. Install with: pip install azure-mgmt-dns azure-identity"
            )
        self.resource_group = config["azure_resource_group"]
        self.zone_name = config["azure_dns_zone_name"]

    def create_txt_record(self, record_name, record_value, ttl=120):
        """Create a DNS TXT record in Azure DNS."""
        relative_name = record_name.replace(f".{self.zone_name}", "")

        from azure.mgmt.dns.models import RecordSet, TxtRecord
        self.client.record_sets.create_or_update(
            self.resource_group,
            self.zone_name,
            relative_name,
            "TXT",
            RecordSet(ttl=ttl, txt_records=[TxtRecord(value=[record_value])])
        )
        logger.info(f"Azure DNS TXT record created: {record_name}")
        return relative_name

    def delete_txt_record(self, record_id, **kwargs):
        """Delete a DNS TXT record from Azure DNS."""
        relative_name = record_id
        self.client.record_sets.delete(
            self.resource_group, self.zone_name, relative_name, "TXT"
        )
        logger.info(f"Azure DNS TXT record deleted: {relative_name}")


# ══════════════════════════════════════════════
# EMAIL NOTIFICATION
# ══════════════════════════════════════════════

class EmailNotifier:
    """Send email notifications for certificate events."""

    def __init__(self, config):
        self.smtp_server = config["smtp_server"]
        self.smtp_port = config["smtp_port"]
        self.username = config["smtp_username"]
        self.password = config["smtp_password"]
        self.recipients = config["alert_recipients"]

    def send(self, subject, body):
        """Send an email notification."""
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        msg = MIMEMultipart()
        msg["From"] = self.username
        msg["To"] = ", ".join(self.recipients)
        msg["Subject"] = f"[ISE ACME] {subject}"
        msg.attach(MIMEText(body, "html"))

        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
            logger.info(f"Email notification sent: {subject}")
        except Exception as e:
            logger.error(f"Failed to send email: {e}")


# ══════════════════════════════════════════════
# MAIN AUTOMATION ORCHESTRATOR
# ══════════════════════════════════════════════

class ACMEAutomation:
    """Orchestrates the full ACME certificate lifecycle across multiple ISE nodes."""

    def __init__(self, config):
        self.config = config
        self.ise = ISEClient(config)
        self.notifier = EmailNotifier(config)

        # Initialize DNS provider
        dns_provider = config["dns_provider"].lower()
        if dns_provider == "cloudflare":
            self.dns = CloudflareDNS(config)
        elif dns_provider == "aws_route53":
            self.dns = AWSRoute53DNS(config)
        elif dns_provider == "azure_dns":
            self.dns = AzureDNS(config)
        else:
            raise ValueError(f"Unsupported DNS provider: {dns_provider}")

        # Determine certificate mode
        self.shared_mode = config.get("certificate_mode", "shared").lower() == "shared"
        self.primary_node = config.get("primary_node", self._get_enabled_nodes()[0]["name"])

        mode_label = "SHARED" if self.shared_mode else "PER-NODE"
        logger.info(f"ACME Automation initialized | Mode: {mode_label} | DNS: {dns_provider}")
        if self.shared_mode:
            logger.info(f"Primary node for certificate request: {self.primary_node}")

    def _get_enabled_nodes(self):
        """Return list of enabled ISE nodes."""
        return [
            node for node in self.config["ise_nodes"]
            if node.get("enabled", True)
        ]

    def _get_secondary_nodes(self):
        """Return list of enabled nodes excluding the primary node."""
        return [
            node for node in self._get_enabled_nodes()
            if node["name"] != self.primary_node
        ]

    def check_all_nodes(self):
        """Check certificate expiry across all enabled nodes (read-only)."""
        results = {}
        enabled_nodes = self._get_enabled_nodes()
        logger.info(f"Checking certificate expiry on {len(enabled_nodes)} node(s)")

        for node in enabled_nodes:
            node_name = node["name"]
            result = self.ise.check_certificate_expiry(
                self.config["common_name"],
                self.config["renewal_threshold_days"],
                node_name
            )
            results[node_name] = result

        return results

    def check_and_renew(self):
        """Route to the appropriate renewal workflow based on certificate mode."""
        if self.shared_mode:
            return self._renew_shared_certificate()
        else:
            return self._renew_per_node_certificates()

    # ──────────────────────────────────────────
    # SHARED CERTIFICATE MODE
    # ──────────────────────────────────────────

    def _renew_shared_certificate(self):
        """
        Shared certificate workflow:
        1. Request certificate on primary node via ACME
        2. Export certificate from primary node
        3. Import same certificate to all secondary nodes
        4. Bind to portal on all nodes
        """
        logger.info("=" * 60)
        logger.info("SHARED CERTIFICATE MODE")
        logger.info(f"Primary node: {self.primary_node}")
        logger.info(f"Secondary nodes: {[n['name'] for n in self._get_secondary_nodes()]}")
        logger.info("=" * 60)

        results = {}
        cn = self.config["common_name"]
        threshold = self.config["renewal_threshold_days"]

        # Step 1: Check expiry on primary node
        logger.info(f"\n{'─' * 40}")
        logger.info(f"Step 1: Checking certificate on primary node: {self.primary_node}")
        logger.info(f"{'─' * 40}")

        expiry_check = self.ise.check_certificate_expiry(cn, threshold, self.primary_node)

        if not expiry_check["needs_renewal"]:
            logger.info(
                f"[{self.primary_node}] Certificate valid for "
                f"{expiry_check['days_remaining']} more days."
            )
            # Still check secondary nodes for consistency
            results[self.primary_node] = {"status": "ok", "details": expiry_check}
            self._verify_secondary_nodes(results)
            self._notify_multi_node_results(results)
            return results

        # Step 2: Request new certificate on primary node via ACME
        logger.info(f"\n{'─' * 40}")
        logger.info(f"Step 2: Requesting certificate via ACME on {self.primary_node}")
        logger.info(f"{'─' * 40}")

        dns_record_id = None
        challenge_record_name = None
        challenge_record_value = None

        try:
            acme_request = self.ise.initiate_acme_certificate_request(
                common_name=self.config["common_name"],
                san_names=self.config["san_names"],
                key_type=self.config["key_type"],
                node_name=self.primary_node,
                portal_group_tag=self.config["portal_group_tag"]
            )
            request_id = acme_request.get("id") or acme_request.get("requestId")

            # Step 3: Get and fulfill DNS challenge
            logger.info(f"[{self.primary_node}] Waiting for ACME challenge...")
            time.sleep(10)
            challenge = self.ise.get_acme_challenge(request_id, self.primary_node)
            challenge_record_name = challenge.get("recordName")
            challenge_record_value = challenge.get("recordValue")

            logger.info(f"Creating DNS TXT record: {challenge_record_name} = {challenge_record_value}")
            dns_record_id = self.dns.create_txt_record(
                challenge_record_name, challenge_record_value
            )

            logger.info("Waiting for DNS propagation (90 seconds)...")
            time.sleep(90)
            self._verify_dns_propagation(challenge_record_name, challenge_record_value)

            # Step 4: Validate challenge
            logger.info(f"[{self.primary_node}] Triggering ACME challenge validation...")
            self.ise.confirm_acme_challenge(request_id, self.primary_node)

            # Step 5: Wait for certificate
            logger.info(f"[{self.primary_node}] Waiting for certificate issuance...")
            cert = self._wait_for_certificate(cn, node_name=self.primary_node, max_wait=300)

            if not cert:
                raise Exception("Certificate not issued in time on primary node")

            # Step 6: Bind on primary node
            self.ise.bind_certificate_to_portal(
                cert_id=cert["id"],
                portal_group_tag=self.config["portal_group_tag"],
                node_name=self.primary_node
            )
            results[self.primary_node] = {"status": "renewed", "certificate": cert}
            logger.info(f"[{self.primary_node}] ✅ Certificate renewed and bound to portal!")

        except Exception as e:
            logger.error(f"[{self.primary_node}] ❌ Failed: {e}")
            results[self.primary_node] = {"status": "failed", "error": str(e)}
            # Cleanup and notify
            if dns_record_id:
                self._cleanup_dns(dns_record_id, challenge_record_name, challenge_record_value)
            self._notify_multi_node_results(results)
            return results

        # Step 7: Clean up DNS
        if dns_record_id:
            self._cleanup_dns(dns_record_id, challenge_record_name, challenge_record_value)

        # Step 8: Distribute certificate to secondary nodes
        logger.info(f"\n{'─' * 40}")
        logger.info("Step 3: Distributing certificate to secondary nodes")
        logger.info(f"{'─' * 40}")

        try:
            cert_data = self.ise.export_certificate(cert["id"], self.primary_node)
        except Exception as e:
            logger.error(f"Failed to export certificate from primary node: {e}")
            # Primary succeeded but distribution failed
            for node in self._get_secondary_nodes():
                results[node["name"]] = {
                    "status": "failed",
                    "error": f"Certificate export failed: {e}"
                }
            self._notify_multi_node_results(results)
            return results

        for node in self._get_secondary_nodes():
            node_name = node["name"]
            logger.info(f"[{node_name}] Importing shared certificate...")

            try:
                import_result = self.ise.import_certificate(
                    cert_data=cert_data,
                    node_name=node_name,
                    portal_group_tag=self.config["portal_group_tag"]
                )

                # Get the imported certificate ID
                imported_cert = self.ise.get_certificate_by_cn(cn, node_name)
                if imported_cert:
                    self.ise.bind_certificate_to_portal(
                        cert_id=imported_cert["id"],
                        portal_group_tag=self.config["portal_group_tag"],
                        node_name=node_name
                    )

                results[node_name] = {"status": "renewed", "certificate": imported_cert}
                logger.info(f"[{node_name}] ✅ Shared certificate imported and bound!")

            except Exception as e:
                logger.error(f"[{node_name}] ❌ Failed to import certificate: {e}")
                results[node_name] = {"status": "failed", "error": str(e)}

        # Step 9: Send consolidated notification
        self._notify_multi_node_results(results)

        # Summary
        self._print_summary(results)

        return results

    def _verify_secondary_nodes(self, results):
        """Verify secondary nodes have valid certificates (used in shared mode when primary is OK)."""
        cn = self.config["common_name"]
        threshold = self.config["renewal_threshold_days"]

        for node in self._get_secondary_nodes():
            node_name = node["name"]
            expiry_check = self.ise.check_certificate_expiry(cn, threshold, node_name)

            if expiry_check["needs_renewal"]:
                logger.warning(
                    f"[{node_name}] Secondary node certificate needs renewal — "
                    f"re-distributing from primary"
                )
                try:
                    primary_cert = self.ise.get_certificate_by_cn(cn, self.primary_node)
                    if primary_cert:
                        cert_data = self.ise.export_certificate(
                            primary_cert["id"], self.primary_node
                        )
                        self.ise.import_certificate(
                            cert_data=cert_data,
                            node_name=node_name,
                            portal_group_tag=self.config["portal_group_tag"]
                        )
                        imported_cert = self.ise.get_certificate_by_cn(cn, node_name)
                        if imported_cert:
                            self.ise.bind_certificate_to_portal(
                                cert_id=imported_cert["id"],
                                portal_group_tag=self.config["portal_group_tag"],
                                node_name=node_name
                            )
                        results[node_name] = {"status": "renewed", "certificate": imported_cert}
                        logger.info(f"[{node_name}] ✅ Certificate re-distributed from primary")
                    else:
                        results[node_name] = {
                            "status": "failed",
                            "error": "Primary certificate not found for distribution"
                        }
                except Exception as e:
                    results[node_name] = {"status": "failed", "error": str(e)}
            else:
                results[node_name] = {"status": "ok", "details": expiry_check}

    # ──────────────────────────────────────────
    # PER-NODE CERTIFICATE MODE
    # ──────────────────────────────────────────

    def _renew_per_node_certificates(self):
        """Per-node certificate workflow: each node gets its own certificate."""
        logger.info("=" * 60)
        logger.info("PER-NODE CERTIFICATE MODE")
        logger.info(f"Processing {len(self._get_enabled_nodes())} ISE PSN node(s)")
        logger.info("=" * 60)

        results = {}
        dns_record_created = False
        dns_record_id = None
        challenge_record_name = None
        challenge_record_value = None

        enabled_nodes = self._get_enabled_nodes()

        for i, node in enumerate(enabled_nodes):
            node_name = node["name"]
            logger.info(f"\n{'─' * 40}")
            logger.info(f"Processing node {i + 1}/{len(enabled_nodes)}: {node_name}")
            logger.info(f"{'─' * 40}")

            try:
                # Check expiry
                cn = self.config["common_name"]
                threshold = self.config["renewal_threshold_days"]
                expiry_check = self.ise.check_certificate_expiry(cn, threshold, node_name)

                if not expiry_check["needs_renewal"]:
                    logger.info(
                        f"[{node_name}] Certificate valid for "
                        f"{expiry_check['days_remaining']} more days. Skipping."
                    )
                    results[node_name] = {"status": "ok", "details": expiry_check}
                    continue

                # Initiate ACME request
                logger.info(f"[{node_name}] Initiating ACME request...")
                acme_request = self.ise.initiate_acme_certificate_request(
                    common_name=self.config["common_name"],
                    san_names=self.config["san_names"],
                    key_type=self.config["key_type"],
                    node_name=node_name,
                    portal_group_tag=self.config["portal_group_tag"]
                )
                request_id = acme_request.get("id") or acme_request.get("requestId")

                # Get challenge
                logger.info(f"[{node_name}] Waiting for ACME challenge...")
                time.sleep(10)
                challenge = self.ise.get_acme_challenge(request_id, node_name)
                challenge_record_name = challenge.get("recordName")
                challenge_record_value = challenge.get("recordValue")

                # Create DNS record (only once for same domain)
                if not dns_record_created:
                    logger.info(
                        f"Creating DNS TXT record: "
                        f"{challenge_record_name} = {challenge_record_value}"
                    )
                    dns_record_id = self.dns.create_txt_record(
                        challenge_record_name, challenge_record_value
                    )
                    dns_record_created = True

                    logger.info("Waiting for DNS propagation (90 seconds)...")
                    time.sleep(90)
                    self._verify_dns_propagation(
                        challenge_record_name, challenge_record_value
                    )
                else:
                    logger.info(f"[{node_name}] Reusing existing DNS challenge record")

                # Validate
                logger.info(f"[{node_name}] Triggering ACME challenge validation...")
                self.ise.confirm_acme_challenge(request_id, node_name)

                # Wait for certificate
                logger.info(f"[{node_name}] Waiting for certificate issuance...")
                cert = self._wait_for_certificate(cn, node_name=node_name, max_wait=300)

                # Bind
                if cert:
                    self.ise.bind_certificate_to_portal(
                        cert_id=cert["id"],
                        portal_group_tag=self.config["portal_group_tag"],
                        node_name=node_name
                    )
                    results[node_name] = {"status": "renewed", "certificate": cert}
                    logger.info(f"[{node_name}] ✅ Certificate renewed successfully!")
                else:
                    results[node_name] = {
                        "status": "failed",
                        "error": "Certificate not issued in time"
                    }
                    logger.error(f"[{node_name}] ❌ Certificate renewal failed — timeout")

            except Exception as e:
                logger.error(f"[{node_name}] ❌ Error during renewal: {e}")
                results[node_name] = {"status": "failed", "error": str(e)}

        # Cleanup DNS
        if dns_record_created:
            self._cleanup_dns(dns_record_id, challenge_record_name, challenge_record_value)

        # Notify
        self._notify_multi_node_results(results)
        self._print_summary(results)

        return results

    # ──────────────────────────────────────────
    # SHARED HELPER METHODS
    # ──────────────────────────────────────────

    def _verify_dns_propagation(self, record_name, expected_value, retries=6, delay=30):
        """Verify that the DNS TXT record has propagated."""
        for attempt in range(retries):
            try:
                result = subprocess.run(
                    ["nslookup", "-type=TXT", record_name, "8.8.8.8"],
                    capture_output=True, text=True, timeout=10
                )
                if expected_value in result.stdout:
                    logger.info(f"DNS propagation verified (attempt {attempt + 1})")
                    return True
            except Exception:
                pass

            if attempt < retries - 1:
                logger.info(
                    f"DNS not propagated yet, retrying in {delay}s... "
                    f"(attempt {attempt + 1}/{retries})"
                )
                time.sleep(delay)

        logger.warning("DNS propagation could not be fully verified — proceeding anyway")
        return False

    def _wait_for_certificate(self, common_name, node_name, max_wait=300, interval=15):
        """Poll ISE until the new certificate appears on a specific node."""
        elapsed = 0
        while elapsed < max_wait:
            cert = self.ise.get_certificate_by_cn(common_name, node_name)
            if cert:
                expiry_str = cert.get("expirationDate", "")
                try:
                    expiry_date = datetime.strptime(expiry_str, "%Y-%m-%dT%H:%M:%S.%fZ")
                    if expiry_date > datetime.utcnow() + timedelta(days=60):
                        logger.info(
                            f"[{node_name}] New certificate detected: expires {expiry_str}"
                        )
                        return cert
                except ValueError:
                    pass

            time.sleep(interval)
            elapsed += interval
            logger.info(f"[{node_name}] Waiting for certificate... ({elapsed}s / {max_wait}s)")

        logger.error(f"[{node_name}] Timed out waiting for new certificate")
        return None

    def _cleanup_dns(self, record_id, record_name, record_value):
        """Remove the ACME challenge DNS record."""
        try:
            if isinstance(self.dns, CloudflareDNS):
                self.dns.delete_txt_record(record_id)
            elif isinstance(self.dns, AWSRoute53DNS):
                self.dns.delete_txt_record(
                    record_id, record_name=record_name, record_value=record_value
                )
            elif isinstance(self.dns, AzureDNS):
                self.dns.delete_txt_record(record_id)
            logger.info("DNS challenge record cleaned up")
        except Exception as e:
            logger.warning(f"Failed to clean up DNS record: {e}")

    def _notify_multi_node_results(self, results):
        """Send consolidated notification for all nodes."""
        all_success = all(
            r["status"] in ("ok", "renewed") for r in results.values()
        )

        mode_label = "Shared Certificate" if self.shared_mode else "Per-Node Certificate"

        rows = ""
        for node_name, result in results.items():
            status = result["status"]
            is_primary = node_name == self.primary_node and self.shared_mode

            if status == "ok":
                icon = "🟢"
                detail = (
                    f"Valid — {result.get('details', {}).get('days_remaining', '?')} "
                    f"days remaining"
                )
            elif status == "renewed":
                icon = "🟢"
                cert = result.get("certificate", {})
                detail = f"Renewed — expires {cert.get('expirationDate', 'N/A')}"
            else:
                icon = "🔴"
                detail = f"Failed — {result.get('error', 'Unknown error')}"

            primary_badge = " <b>[PRIMARY]</b>" if is_primary else ""

            rows += f"""
            <tr>
                <td>{icon} {node_name}{primary_badge}</td>
                <td>{status.upper()}</td>
                <td>{detail}</td>
            </tr>"""

        subject = "All Nodes OK" if all_success else "⚠️ Some Nodes Failed"

        body = f"""
        <h2>{'✅' if all_success else '⚠️'} ISE ACME Certificate Renewal Report</h2>
        <p><b>Mode:</b> {mode_label}</p>
        <p><b>Common Name:</b> {self.config['common_name']}</p>
        <p><b>Nodes Processed:</b> {len(results)}</p>
        <p><b>Timestamp:</b> {datetime.now().isoformat()}</p>
        <table border="1" cellpadding="8" cellspacing="0">
            <tr style="background-color: #f0f0f0;">
                <th>ISE Node</th>
                <th>Status</th>
                <th>Details</th>
            </tr>
            {rows}
        </table>
        <br>
        <p><i>This is an automated notification from the ISE ACME Certificate Renewal System.</i></p>
        """

        self.notifier.send(subject, body)

    def _print_summary(self, results):
        """Print a summary of all node results to the log."""
        mode_label = "SHARED" if self.shared_mode else "PER-NODE"
        logger.info("\n" + "=" * 60)
        logger.info(f"RENEWAL SUMMARY ({mode_label} MODE)")
        logger.info("=" * 60)
        for node_name, result in results.items():
            status_icon = "✅" if result["status"] in ("ok", "renewed") else "❌"
            primary_tag = " [PRIMARY]" if (
                node_name == self.primary_node and self.shared_mode
            ) else ""
            logger.info(f"  {status_icon} {node_name}{primary_tag}: {result['status']}")
        logger.info("=" * 60)


# ══════════════════════════════════════════════
# CLI INTERFACE
# ══════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="ISE ACME Certificate Auto-Renewal Automation (Multi-Node, Shared/Per-Node)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check expiry on all nodes (read-only)
  python ise_acme_automation.py --action check

  # Renew using shared certificate mode (default)
  python ise_acme_automation.py --action renew --config config.json

  # Dry run — see what would happen
  python ise_acme_automation.py --action renew --config config.json --dry-run

  # Force renewal on all nodes
  python ise_acme_automation.py --action force-renew --config config.json

  # Override mode via CLI
  python ise_acme_automation.py --action renew --config config.json --mode per-node
        """
    )

    parser.add_argument(
        "--action",
        choices=["check", "renew", "force-renew"],
        default="renew",
        help="Action to perform (default: renew)"
    )
    parser.add_argument(
        "--config",
        type=str,
        help="Path to JSON config file (overrides environment variables)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate the process without making changes"
    )
    parser.add_argument(
        "--mode",
        choices=["shared", "per-node"],
        help="Override certificate mode (shared or per-node)"
    )

    args = parser.parse_args()

    # Load config from file if provided
    config = CONFIG.copy()
    if args.config:
        with open(args.config, "r") as f:
            file_config = json.load(f)
            config.update(file_config)
            logger.info(f"Configuration loaded from {args.config}")

    # Override mode if specified via CLI
    if args.mode:
        config["certificate_mode"] = args.mode
        logger.info(f"Certificate mode overridden via CLI: {args.mode}")

    # Initialize automation
    automation = ACMEAutomation(config)

    if args.action == "check":
        results = automation.check_all_nodes()
        print(json.dumps(results, indent=2, default=str))

    elif args.action == "renew":
        if args.dry_run:
            logger.info("[DRY RUN] Checking all nodes — no changes will be made")
            results = automation.check_all_nodes()
            print(json.dumps(results, indent=2, default=str))
        else:
            results = automation.check_and_renew()
            print(json.dumps(results, indent=2, default=str))

    elif args.action == "force-renew":
        if args.dry_run:
            logger.info("[DRY RUN] Would force-renew certificates on all nodes")
            results = automation.check_all_nodes()
            print(json.dumps(results, indent=2, default=str))
        else:
            config["renewal_threshold_days"] = 9999
            automation = ACMEAutomation(config)
            results = automation.check_and_renew()
            print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
