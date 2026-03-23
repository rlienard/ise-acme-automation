# Contributing to ISE ACME Certificate Auto-Renewal

Thank you for your interest in contributing! 🎉

## How to Contribute

### Reporting Bugs

1. Check existing [Issues](https://github.com/rlienard/ise-acme-automation/issues) first
2. Create a new issue with:
   
   - Clear title and description
   - Steps to reproduce
   - Expected vs. actual behavior
   - ISE version, Python version, DNS provider
   - Relevant log snippets (redact sensitive info!)

### Suggesting Features

1. Open a [Feature Request](https://github.com/rlienard/ise-acme-automation/issues/new?template=feature_request.md)
2. Describe the use case and expected behavior
3. Include any relevant technical details

### Submitting Code

1. **Fork** the repository
2. **Clone** your fork:
   ```bash
   git clone https://github.com/your-fork/ise-acme-automation.git
   cd ise-acme-automation
   ```
3. **Create a branch**:
   ```bash
   git checkout -b feature/your-amazing-feature
   ```
4. **Make your changes** and test thoroughly
5. **Commit** with a clear message:
   ```bash
   git commit -m "feat: add support for GoDaddy DNS provider"
   ```
6. **Push** to your fork:
   ```bash
   git push origin feature/your-amazing-feature
   ```
7. **Open a Pull Request** against the main branch
   Commit Message Convention
   
   We follow Conventional Commits:

   |Prefix      |   Usage                     |
   |:-----------|:----------------------------|      
   |feat:       |	  New feature               |
   |fix:	       |   Bug fix                   |
   |docs:	    |   Documentation changes     |
   |refactor:   |   Code refactoring          |
   |test:       |   Adding or updating tests  |
   |chore:      |   Maintenance tasks         |
   |security:   |   Security improvements     |

   Code Style

   * Follow PEP 8 for Python code
   * Use type hints where practical
   * Add docstrings to all classes and public methods
   * Keep functions focused and under 50 lines where possible
   * Add logging for key operations

   Testing

   Before submitting a PR:

   1. Test with --action check (read-only)
   2. Test with --action renew --dry-run
   3. If possible, test against a lab ISE environment
   4. Verify all three DNS providers still work (if modifying DNS code)
   5. Verify both shared and per-node modes

   Development Setup

bash
Copy Code
# Clone and setup
git clone https://github.com/yourusername/ise-acme-automation.git
cd ise-acme-automation
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run checks
python -m py_compile ise_acme_automation.py
python ise_acme_automation.py --help

Areas We'd Love Help With

Additional DNS providers (GoDaddy, DigitalOcean, Namecheap)
HashiCorp Vault integration
Slack / Microsoft Teams notifications
Prometheus metrics
Unit tests and integration tests
Certificate backup and rollback
Parallel node processing
Ansible playbook alternative
Terraform module
Web dashboard

Code of Conduct

Be kind, respectful, and constructive. We're all here to build something useful together.


Questions?

Open a Discussion or reach out via Issues.


Thank you! 🙏
