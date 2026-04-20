# 🔥 Check Point CVE IPS Correlator

> Automated IPS coverage analysis and mitigation recommendation engine for Firewall Assurance and Vulnerability Management workflows.

---

## 🚀 Overview

The **Check Point CVE IPS Correlator** automates the correlation of:

- IAVM vulnerability notices  
- grouped CVE datasets  
- Check Point IPS protection exports  

It enables cybersecurity teams to **rapidly determine firewall-layer mitigation posture**, identify **coverage gaps**, and generate **operationally actionable recommendations**.

This tool is built specifically for:

- Firewall Assurance Programs (FAP)
- Firewall Operations teams
- Vulnerability Management analysts
- Cybersecurity Infrastructure engineers
- Risk and RMF stakeholders

---

## 🎯 Why This Tool Matters

Manual IPS coverage validation requires:

- Searching large SmartConsole exports  
- Determining enforcement modes per gateway profile  
- Validating exploitability context  
- Writing mitigation recommendations  
- Producing ChangeGear ticket justification  

This process is:

❌ Time‑intensive  
❌ Prone to analyst inconsistency  
❌ Difficult to scale  

✅ This tool standardizes and automates the workflow.

---

## ⚙️ Core Capabilities

### 🔎 CVE Processing

- Automatically expands grouped CVEs from IAVM blocks  
- Handles inconsistent spreadsheet formatting  
- Preserves original vulnerability context  
- Produces per‑CVE actionable analysis rows  

### 🛡 IPS Coverage Correlation

- Matches CVEs against Check Point IPS metadata  
- Determines enforcement posture:
  - Prevent
  - Detect
  - Inactive
  - No IPS Coverage  
- Identifies mitigation gaps requiring patching or compensating controls  

### 📊 Findings Summary Engine

Generates executive‑ready program metrics:

| Metric | Purpose |
|--------|--------|
| Network Exploitable CVEs | Exposure prioritization |
| CISA KEV CVEs | Active threat prioritization |
| CVEs With IPS Coverage | Compensating control validation |
| CVEs Without IPS Coverage | Patch urgency indicator |
| CVEs In Prevent | Active blocking posture |
| CVEs In Detect | Monitoring posture |
| CVEs Inactive | Misconfiguration indicator |
| CVEs Recommended → Detect | Tuning actions |
| CVEs Prevent Candidates | Future blocking posture |

---

## 🧠 Operational Recommendation Logic

The tool follows **real‑world firewall engineering practice**:

| Scenario | Recommendation |
|---------|---------------|
| Signature active in Prevent | Validate traffic relevance |
| Signature inactive or Detect | Enable in Detect for tuning |
| Signature exists but unused | Enable in Detect |
| No signature exists | Patch / compensating control |
| After validation | Consider promotion to Prevent |

This reflects **safe IPS deployment methodology** used in enterprise and DoD environments.

---

## 📁 Output Workbook Tabs

| Tab | Purpose |
|-----|--------|
| Original_CVE_Block | Preserved source data with added summary |
| Flat_CVE_View | Per‑CVE technical analysis |
| Grouped_IAVM_View | Notice‑level posture aggregation |
| Original_Row_Summary | Quick validation metrics |
| Findings_Summary | Executive metrics and narrative |

---

# 📸 Example Output

## Firewall Action Queue
![Firewall Action Queue](docs/screenshots/firewall_action_queue.png)

## Flat CVE View
![Flat CVE View](docs/screenshots/flat_cve_view.png)

## Findings Summary
![Findings Summary](docs/screenshots/findings_summary.png)

---

# 📂 File Structure

```
input/
├── CVE_blocks/
│   └── <Month Folder>/
├── IPS/

output/
├── enriched/
│   └── <Month Folder>/

scripts/
└── checkpoint_cve_iavm_enricher.py
```
---

# ⚙️ How It Works

- CVE file → auto-selected by **latest date in filename**
- IPS file → auto-selected by **latest modified file**
- Output → auto-generated in:
  ```
  output/enriched/<Month Folder>/

---

## 🧰 Installation

```bash
pip install -r requirements.txt
```

---

# ▶️ Usage

## Simple Run
```
python scripts/checkpoint_cve_iavm_enricher.py
```
## Optional Arguments
```
--cve <path>        # manually specify CVE workbook
--ips <path>        # manually specify IPS export
--out <path>        # manually specify output file
--skip-nvd          # skip NVD API enrichment
--delay <seconds>   # delay between NVD requests (default: 1.2)
--cache <file>      # NVD cache file (default: nvd_cache.json)
```
---

## 🧭 Recommended Operational Workflow

1. Export IPS protections from SmartConsole  
2. Obtain vulnerability workbook from CVM  
3. Execute correlator  
4. Review Findings Summary  
5. Validate exposure paths  
6. Generate remediation tickets  
7. Coordinate tuning or patching  

---

## ⚠️ Matching Limitations

- Some IPS protections reference advisories instead of CVEs  
- Signature presence does not guarantee traffic exposure  
- Final risk determination requires architecture validation  

---

## 🔐 Security Handling Guidance

When sharing examples:

❗ Use sanitized data  
❗ Do not include production firewall exports  
❗ Do not publish CUI vulnerability datasets  
❗ Avoid internal network architecture details  

---

## 🗺 Future Roadmap

- Fuzzy IPS signature matching  
- Exposure risk scoring model  
- KEV‑weighted prioritization  
- Firewall path validation logic  
- Dashboard reporting  
- Packaged CLI distribution  

---

## 📦 Repository Structure

```
checkpoint-cve-ips-correlator/
├── checkpoint_cve_iavm_enricher_v3.py
├── README.md
├── requirements.txt
├── examples/
└── docs/
```

---

## ⭐ Contribution

Improvements, issue reports, and workflow suggestions are welcome.

---

## 📜 License

Add an appropriate license prior to public distribution.
