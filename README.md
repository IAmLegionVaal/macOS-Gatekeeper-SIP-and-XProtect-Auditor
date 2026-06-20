# macOS Gatekeeper, SIP and XProtect Auditor

A read-only Bash toolkit for auditing core macOS platform-security controls and assessing an optional application bundle.

## Checks performed

- Gatekeeper assessment state
- System Integrity Protection status and configuration
- XProtect, XProtect Remediator, MRT, and security-data package versions
- Recent security-related installation history
- Quarantine database presence and aggregate record counts
- Optional application code-signature, Gatekeeper, notarisation, entitlements, and quarantine-attribute evidence
- Relevant recent security and malware-remediation log events
- Text, CSV, and JSON reports

## Usage

```bash
chmod +x src/macos_platform_security_audit.sh
sudo ./src/macos_platform_security_audit.sh
```

Assess an application bundle:

```bash
sudo ./src/macos_platform_security_audit.sh --app /Applications/Example.app --hours 48
```

## Safety

The toolkit does not disable Gatekeeper or SIP, remove quarantine attributes, approve applications, modify trust settings, delete malware, or change security policy.

## Requirements

- macOS 12 or later recommended
- Bash 3.2+
- Administrator privileges for complete log and system evidence

## Author

Dewald Pretorius — L2 IT Support Engineer
