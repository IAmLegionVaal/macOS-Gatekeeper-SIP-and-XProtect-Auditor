# macOS Gatekeeper, SIP and XProtect Auditor

A Bash toolkit for auditing core macOS platform-security controls and assessing an optional application bundle. It also includes a guarded repair mode for Gatekeeper, security-data refresh, and `syspolicyd` recovery.

## Checks performed

- Gatekeeper assessment state
- System Integrity Protection and authenticated-root status
- XProtect, XProtect Remediator, MRT, and security-data package versions
- Recent security-related installation and log events
- Optional application code-signature, Gatekeeper, entitlement, and quarantine evidence
- Text, CSV, JSON, error, and repair-action logs

## Diagnostic usage

```bash
chmod +x src/macos_platform_security_audit.sh
sudo ./src/macos_platform_security_audit.sh
```

Assess an application bundle:

```bash
sudo ./src/macos_platform_security_audit.sh --app /Applications/Example.app --hours 48
```

## Repair usage

Preview repair actions:

```bash
sudo ./src/macos_platform_security_audit.sh --repair --dry-run
```

Apply guarded repairs:

```bash
sudo ./src/macos_platform_security_audit.sh --repair --yes
```

Repair mode can:

- Capture pre-repair Gatekeeper, SIP, package, and optional application xattr evidence
- Enable Gatekeeper when disabled, using the supported `spctl` command available on the Mac
- Request a background critical security-data update
- Restart `syspolicyd`
- Recheck Gatekeeper, SIP, and the optional application after repair

The tool never disables Gatekeeper or SIP, removes quarantine attributes, approves an untrusted application, changes trust settings, or deletes malware.

## SIP limitation

SIP cannot be enabled safely from a normal macOS boot. When SIP is disabled, the repair log records the manual Recovery procedure instead of attempting an unsupported live change.

## Safety controls

- Repair mode requires root privileges
- `--dry-run` logs intended actions without changing the Mac
- A confirmation prompt is shown unless `--yes` is supplied
- Pre-repair evidence is stored in the report directory
- Every action and failure is written to `repair-actions.log`
- Post-repair verification is automatic

## Exit codes

- `0` — compliant or successful repair
- `10` — attention still required or repair cancelled
- `20` — one or more repair actions failed
- `2` — invalid arguments
- `3` — wrong platform or insufficient privileges

## Requirements

- macOS 12 or later recommended
- Bash 3.2+
- Administrator privileges for complete evidence and repair mode

## Validation note

The script has been statically reviewed for shell syntax and control flow. Runtime testing must be performed on a suitable macOS system before production use.

## Author

Dewald Pretorius — L2 IT Support Engineer
