# CVE-2026-24849 — Role × File-Access Evaluation Matrix (Test Plan)

**Goal:** Determine empirically whether OpenEMR account role has any effect on which files `disposeDocument()` can read.

**Working hypothesis:** Role has zero effect — the only gate is OS-level file permissions for the `apache` user.

## Accounts tested (Part A)
| ID | Account | ACL Group |
|----|---------|-----------|
| R1 | admin | Administrators |
| R2 | NIU | Clinician |

## File categories tested (Part B)
| ID | Category | Path |
|----|----------|------|
| F1 | World-readable | /etc/passwd |
| F2 | Apache-owned 400 | /var/www/.../sqlconf.php |
| F3 | Root-owned, no other-read | /etc/shadow |

See project documentation for full test plan.
