# AMENDER — Evaluation Results

## Table 4: Complete Research Iteration Log (13 Steps Across 4 Phases)

Phase: P1=Python PoC analysis; P2=sibling-class analysis;
P3=module synthesis (CVE-2026-24849); P4=module synthesis (CVE-2026-33305).
Fix: auto=pipeline self-repair; analyst=analyst intervention;
Theta=negative result; —=accepted.

### Phase P1 — Python PoC Analysis

| ID  | Analyst Action | LLM Output / Observed Outcome | Fix |
|-----|---------------|-------------------------------|-----|
| 1.1 | Run public PoC script | Three defects identified; wrong method name causes silent failure | analyst |
| 1.2 | Inspect FaxSMS source for correct method | disposeDocument() located; action=download path confirmed | analyst |
| 1.3 | Write minimal script; test with administrator role | Minimal script produced; 1,220 B read from target file | — |
| 1.4 | Repeat test with clinician role | Identical result; role-based access restriction disproved | — |

### Phase P2 — Root-Cause and Sibling-Class Analysis

| ID  | Analyst Action | LLM Output / Observed Outcome | Fix |
|-----|---------------|-------------------------------|-----|
| 2.1 | Trace dispatcher to AppDispatch class | call_user_func with no ACL check identified; CWE-862 confirmed | — |
| 2.2 | Probe EmailClient through dispatcher | 3-argument signature incompatible; ArgumentCountError thrown | Θ |
| 2.3 | Change fax provider; probe RCFaxClient | Identical vulnerable pattern confirmed; file read reproduced across providers | — |
| 2.4 | Check scope across custom modules | Vulnerable dispatcher confined to FaxSMS module; attack surface bounded | — |

### Phase P3 — Module Synthesis (CVE-2026-24849)

| ID  | Analyst Action | LLM Output / Observed Outcome | Fix |
|-----|---------------|-------------------------------|-----|
| m0  | Generate initial candidate module | Bare CheckCode constant triggers NameError; msftidy FATAL | auto |
| m1  | Reload; execute check() and run() | Session cookie not propagated; login failed; false negative | analyst |
| m2  | Attach session cookie to all requests | check() reports Vulnerable; 1,220 B read; χ3 passed | — |

### Phase P4 — Module Synthesis (CVE-2026-33305)

| ID  | Analyst Action | LLM Output / Observed Outcome | Fix |
|-----|---------------|-------------------------------|-----|
| m0  | Generate candidate module for credential modification | SAVE_SETUP action produced; credentials absent from datastore; login failed | analyst |
| m1  | Set credentials in datastore | Module re-executed; injected credentials overwritten; χ3 passed | — |

---

## Table 2: Differential Functional Test (RQ1)

| Target | check() verdict | Demonstrative read |
|--------|----------------|--------------------|
| OpenEMR 7.0.2 (vulnerable) | Vulnerable | Success — 1,220 B from /etc/passwd |
| OpenEMR 7.0.4 (patched) | Safe | Fail |

## Coverage Gap (RQ4)
- Total disclosed OpenEMR CVEs: 200+
- Existing Metasploit modules before this work: 4 (< 3%)
- Modules added by AMENDER: 2 (CVE-2026-24849, CVE-2026-33305)
