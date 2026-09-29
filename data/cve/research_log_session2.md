# OpenEMR Vulnerability Research Log — Session 2

**Researcher:** Rezwanul Haque (PhD, Computer Science, Northern Illinois University)
**Date:** 2026-09-04
**Lab:** Proxmox host `karlin`, VM `rezwan` (Kali), containers `openemr-lab-openemr-1` / `openemr-lab-mysql-1`, OpenEMR 7.0.2 on port 8080.

## Summary of confirmed findings

| # | Finding | Component | Role required | Status |
|---|---|---|---|---|
| 1 | Arbitrary file read (CVE-2026-24849) | `EtherFaxActions::disposeDocument()` | Any authenticated user | Confirmed |
| 2 | Arbitrary file write (same endpoint) | `EtherFaxActions::disposeDocument()` | Any authenticated user | Confirmed; no RCE escalation |
| 3 | No brute-force lockout (CWE-307) | Login endpoint | N/A (pre-auth) | Confirmed |
| 4 | Missing ACL is a shared base-class defect | `AppDispatch::dispatchActions()` | — | Confirmed via source |
| 5 | emailDocument() reachable but not exploitable via generic dispatch | `EmailClient::emailDocument()` | Any authenticated user | Confirmed negative, root-caused |
| 6 | saveSetup() credential overwrite | `AppDispatch::saveSetup()` | Any authenticated user (hypothesis) | Not yet tested |

See project documentation for full session notes.
