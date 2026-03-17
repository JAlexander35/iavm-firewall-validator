# Check Point CVE IPS Correlator

Automates correlation of **IAVM / CVE vulnerability data with Check Point IPS signature coverage** to support firewall assurance assessments, exposure analysis, and mitigation prioritization.

This tool is designed for firewall engineers, vulnerability analysts, and assurance teams who must quickly determine whether firewall-layer protections exist for known vulnerabilities.

---

## Problem This Tool Solves

In many environments, vulnerability teams provide large spreadsheets containing:

- IAVM notices  
- grouped CVEs  
- limited exploitability context  

Firewall teams must then manually:

- search IPS exports  
- determine enforcement mode  
- assess whether protections are active  
- identify exposure gaps  
- produce mitigation recommendations  

This process is time-consuming and inconsistent.

**This tool automates that correlation workflow.**

---

## What the Tool Does

The script:

- parses CVE / IAVM vulnerability workbooks  
- expands grouped CVEs into per-CVE analysis rows  
- correlates vulnerabilities against Check Point IPS signature exports  
- determines inferred enforcement posture:
  - Prevent  
  - Detect  
  - Inactive / not clearly active  
- optionally enriches vulnerabilities with NVD metadata:
  - CVSS score  
  - severity  
  - attack vector  
  - exploitability context  
- preserves the original workbook and generates analyst-friendly review tabs  

---

## Key Features

### Vulnerability Processing
- Supports multiple CVEs per IAVM block  
- Handles mixed formatting within CVE fields  
- Maintains original vulnerability context while enabling per-CVE analysis  

### IPS Signature Correlation
- Accepts Check Point IPS exports in CSV or XLSX format  
- Matches vulnerabilities using CVE identifiers in signature metadata  
- Infers IPS posture based on profile / gateway action columns  
- Highlights potential mitigation gaps  

### Analyst Review Views
- Generates flattened CVE view  
- Generates grouped IAVM summary view  
- Generates original-row mitigation summary  
- Adds manual review columns for analyst validation  

### NVD Enrichment
- Optional live enrichment via NIST NVD API  
- Local caching supported for repeat runs  
- Adds exploitability context to support prioritization  

### Non-Destructive Output
- Preserves the original workbook  
- Adds new tabs rather than rebuilding source content  

---

## Typical Use Cases

- Firewall Assurance Program reviews  
- vulnerability mitigation validation  
- IPS coverage gap identification  
- IAVM exposure analysis  
- change-ticket justification support  
- risk prioritization workshops  
- firewall operations coordination  

---

## Expected Inputs

### CVE / IAVM Workbook

An Excel workbook containing vulnerability blocks.  
Common fields include:

- IAVM Notice  
- Description  
- Related CVE(s)  
- STIG Severity  
- existing mitigation notes (optional)  

Grouped CVEs will be automatically flattened.

### Check Point IPS Export

Exported from SmartConsole.  
Typical relevant fields include:

- Protection name  
- Industry Reference / Industry Release (contains CVE identifiers)  
- Performance Impact  
- profile action columns such as:
  - Default Protection  
  - environment-specific profile columns (e.g. `DCMA_NIPRNET`)  

---

## Output Workbook Structure

The enriched workbook contains:

- **Original_CVE_Block** — preserved source content with added summary columns  
- **Flat_CVE_View** — one row per CVE with IPS correlation and enrichment data  
- **Grouped_IAVM_View** — IAVM-level aggregation of mitigation posture and risk indicators  
- **Original_Row_Summary** — per-row mitigation summary for quick validation  

---

## Installation

Clone the repository and install dependencies:

```bash
pip install -r requirements.txt
```

---

## Usage

### Basic execution

```bash
python checkpoint_cve_iavm_enricher_v2.py --cve "CVE Block Example.xlsx" --ips "IPS Sigs Export.csv" --out "CVE Block Enriched.xlsx"
```

### Specify profile columns

```bash
python checkpoint_cve_iavm_enricher_v2.py --cve "CVE Block Example.xlsx" --ips "IPS Sigs Export.csv" --out "CVE Block Enriched.xlsx" --profile-columns "Default Protection" "DCMA_NIPRNET"
```

### Skip NVD enrichment

```bash
python checkpoint_cve_iavm_enricher_v2.py --cve "CVE Block Example.xlsx" --ips "IPS Sigs Export.csv" --out "CVE Block Enriched.xlsx" --skip-nvd
```

### Use local NVD cache

```bash
python checkpoint_cve_iavm_enricher_v2.py --cve "CVE Block Example.xlsx" --ips "IPS Sigs Export.csv" --out "CVE Block Enriched.xlsx" --cache nvd_cache.json
```

---

## Recommended Workflow

1. Export installed IPS protections from Check Point SmartConsole  
2. Obtain vulnerability spreadsheet from vulnerability management team  
3. Run the correlator script  
4. Review generated tabs for:
   - IPS coverage  
   - enforcement posture  
   - potential exposure gaps  
   - analyst recommendation context  
5. Validate edge cases before final reporting  

---

## Matching Considerations

- Best results occur when IPS exports contain CVE identifiers in metadata fields  
- Some protections reference vendor advisories instead of CVEs  
- Final exposure determination still requires firewall path validation and operational context review  

---

## Security and Data Handling

Use sanitized data only when sharing examples.  
Do not publish:

- production firewall exports  
- CUI or export-controlled vulnerability data  
- sensitive network architecture details  

---

## Roadmap

Future improvements may include:

- fallback matching using protection text  
- configurable profile logic  
- risk scoring model  
- summary reporting dashboards  
- packaging as an installable CLI tool  
- automated unit tests  

---

## Repository Structure

```
checkpoint-cve-ips-correlator/
├── checkpoint_cve_iavm_enricher_v2.py
├── README.md
├── requirements.txt
├── examples/
└── docs/
```

---

## License

Add an appropriate license prior to public distribution.
