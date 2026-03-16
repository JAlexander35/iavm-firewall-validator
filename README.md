# Check Point CVE IPS Correlator

Automates correlation of CVEs and IAVM vulnerability blocks with Check Point IPS signatures to support firewall assurance, exposure analysis, and mitigation prioritization.

## Overview

This project helps reduce the manual effort required to review vulnerability data against installed IPS protections on Check Point firewalls. It is designed for workflows where a spreadsheet of CVEs or IAVM-associated vulnerability blocks must be compared against a Check Point SmartConsole IPS export.

The script can:

- ingest a CVE / IAVM workbook
- flatten multiple CVEs from a single IAVM block into individual rows
- ingest a Check Point IPS export from CSV or XLSX
- correlate CVEs to IPS signatures using available signature metadata
- optionally enrich CVEs with data from NIST NVD
- infer likely IPS posture such as Detect, Prevent, or not clearly active
- preserve the original workbook and add analysis tabs for review

## Current Script

- `checkpoint_cve_iavm_enricher_v2.py`

## Features

- Supports multiple CVEs per IAVM block
- Accepts IPS exports in CSV or XLSX format
- Adds new tabs instead of rebuilding the source workbook from scratch
- Generates flattened and grouped analyst views
- Supports NVD caching for faster reruns
- Adds manual review columns to support analyst validation

## Expected Inputs

### 1. CVE / IAVM workbook
An Excel workbook containing vulnerability blocks with fields such as:

- Related CVE(s)
- Network Exploitable (Y/N)
- IPS Signature Available (Y/N)
- IPS Mode
- Firewall Coverage
- Notes / Actions
- Recommendation

### 2. IPS signature export
A Check Point IPS export from SmartConsole, typically containing columns such as:

- Industry Release
- Protection / signature name
- profile or gateway action columns such as `Default Protection` or environment-specific profiles

## Output

The script writes an enriched Excel workbook that preserves the original content and adds analyst-friendly tabs such as:

- `Flat_CVE_View`
- `Grouped_IAVM_View`
- `Original_Row_Summary`

## Installation

Clone the repository and install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Basic example:

```bash
python checkpoint_cve_iavm_enricher_v2.py \
  --cve "CVE Block Example.xlsx" \
  --ips "IPS Sigs Export.csv" \
  --out "CVE Block Enriched v2.xlsx"
```

Use explicit profile columns when needed:

```bash
python checkpoint_cve_iavm_enricher_v2.py \
  --cve "CVE Block Example.xlsx" \
  --ips "IPS Sigs Export.csv" \
  --out "CVE Block Enriched v2.xlsx" \
  --profile-columns "Default Protection" "DCMA_NIPRNET"
```

Skip NVD enrichment:

```bash
python checkpoint_cve_iavm_enricher_v2.py \
  --cve "CVE Block Example.xlsx" \
  --ips "IPS Sigs Export.csv" \
  --out "CVE Block Enriched v2.xlsx" \
  --skip-nvd
```

Use a local NVD cache:

```bash
python checkpoint_cve_iavm_enricher_v2.py \
  --cve "CVE Block Example.xlsx" \
  --ips "IPS Sigs Export.csv" \
  --out "CVE Block Enriched v2.xlsx" \
  --cache "nvd_cache.json"
```

## Typical Workflow

1. Export installed IPS signatures from Check Point SmartConsole.
2. Prepare the CVE / IAVM workbook.
3. Run the script against both files.
4. Review the generated tabs for:
   - per-CVE correlations
   - IPS coverage
   - inferred IPS mode
   - NVD-derived context
   - analyst recommendation fields
5. Validate edge cases manually before final reporting.

## Notes

- The best matching results occur when the IPS export includes CVE references in fields such as `Industry Release`.
- Some recommendations still require analyst judgment. The script accelerates review, but does not replace firewall exposure analysis.
- Performance impact and final disposition decisions should be validated against local policy and operational context.
- Use sanitized example data only. Do not upload or publish CUI, controlled exports, or production-sensitive firewall data.

## Suggested Repository Structure

```text
checkpoint-cve-ips-correlator/
├── checkpoint_cve_iavm_enricher_v2.py
├── README.md
├── requirements.txt
├── .gitignore
├── examples/
└── docs/
```

## Roadmap

Potential next improvements:

- stronger recommendation rules engine
- fallback matching by protection text when CVE IDs are missing
- configurable YAML-based profile logic
- unit tests for parsing and matching
- CLI packaging
- structured logging and reporting summaries

## License

Add the license of your choice before public release.
