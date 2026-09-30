# OpenEMR CVE Analysis

This script analyzes an OpenEMR CVE dataset and performs two tasks in one reproducible pipeline:

1. **CVE/CVSS analysis:** groups OpenEMR CVEs by publication year, selects the newest available CVSS score in the order CVSS 4.0 → 3.1 → 3.0 → 2.0, calculates yearly counts and average CVSS scores, and exports a PNG/PDF figure and CSV summary.
2. **Metasploit cross-reference:** downloads the official Metasploit module metadata, matches CVE identifiers against module references, and exports separate CSV files for CVEs with and without Metasploit modules.

## Recommended repository files

```text
openemr-cve-analysis/
├── openemr_cve_analysis.py
├── requirements.txt
├── README.md
├── data/
│   └── openemr_nvd_cves.csv
└── results/
```

Generated files should normally remain under `results/` rather than being mixed with source code.

## Requirements

- Python 3.10+
- pandas
- matplotlib

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the complete pipeline:

```bash
python openemr_cve_analysis.py data/openemr_nvd_cves.csv
```

Choose a different output directory:

```bash
python openemr_cve_analysis.py data/openemr_nvd_cves.csv --output-dir results
```

Run only the local CVE/CVSS analysis without downloading Metasploit metadata:

```bash
python openemr_cve_analysis.py data/openemr_nvd_cves.csv --skip-metasploit
```

## Input columns

The CSV is expected to contain `CVE`, `Published`, `CVSS 4.0 Score`, `CVSS 3.1 Score`, `CVSS 3.0 Score`, and `CVSS 2.0 Score` columns.

## Main classes

- `PipelineConfig`: centralizes input, output, and network configuration.
- `OpenEMRCVEAnalyzer`: loads the dataset, selects CVSS scores, computes yearly statistics, and creates the figure.
- `MetasploitMatcher`: downloads/indexes Metasploit metadata and matches CVEs.
- `OpenEMRAnalysisPipeline`: coordinates both tasks.

The code follows PEP 8-style naming, uses `pathlib`, type hints, docstrings, logging, and a command-line interface to make the analysis easier to reproduce and maintain.
