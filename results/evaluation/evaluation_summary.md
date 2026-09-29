# AMENDER — Evaluation Results

## Pipeline Overview
- Total LLM-analyst cycles: 13 (across 4 phases)
- CVEs targeted: CVE-2026-24849 (CVSS 9.9), CVE-2026-33305 (CVSS 5.4)
- Lab: OpenEMR 7.0.2 (vulnerable) and 7.0.4 (patched) in Docker

## Table 4: Per-Iteration Conformance Gates

| Iter. | χ1 Syntax | χ2 msftidy | χ3 Functional | Evidence / Outcome |
|-------|-----------|------------|---------------|--------------------|
| **CVE-2026-24849** — Authenticated file read via FaxSMS module |
| E0 | PASS | FAIL | — | NameError: CheckCode outside Exploit:: namespace; msftidy FATAL |
| E1 | PASS | PASS | FAIL | Stale session state after module reload ("Login failed") |
| E2 | PASS | PASS | PASS | check() reports vulnerable; run() reads 1,220 B from /etc/passwd |
| SPR = 3/3 = 1.00 | MPR = 2/3 = 0.67 | Accepted at E2 | | |
| **CVE-2026-33305** — Authenticated credential injection via setup endpoint |
| E0 | PASS | PASS | FAIL | Vendor credentials absent from module datastore; "Login failed" |
| E1 | PASS | PASS | PASS | Credentials configured; SAVE_SETUP action executes; credentials overwritten |
| SPR = 2/2 = 1.00 | MPR = 2/2 = 1.00 | Accepted at E1 | | |

## Table 2: Differential Functional Test (RQ1)

| Target | check verdict | Demonstrative read |
|--------|---------------|--------------------|
| OpenEMR 7.0.2 (vulnerable) | Vulnerable | Success — 1,220 B from /etc/passwd |
| OpenEMR 7.0.4 (patched) | Safe | Fail |

## Coverage Gap (RQ4)
- Total disclosed OpenEMR CVEs: 200+
- Existing Metasploit modules before this work: 4 (< 3%)
- Modules added by AMENDER: 2 (CVE-2026-24849, CVE-2026-33305)
