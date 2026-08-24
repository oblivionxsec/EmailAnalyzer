# 📧 EmailAnalyzer — Complete Technical Documentation

---

# 1. 📌 Project Overview

EmailAnalyzer is a **deterministic email forensic analysis system** designed to extract, structure, and evaluate email data for security investigation purposes.

It operates in two modes:

### 🌐 1. GitHub Pages Viewer (Static)

* Displays analysis results
* Fully offline
* No computation
* Reads `report.json`

### 💻 2. Offline Analyzer (Advanced Engine)

* Parses `.eml` files
* Extracts headers, content, attachments
* Computes cryptographic hashes
* Applies rule-based threat scoring
* Generates structured JSON report

---

# 2. 🎯 Core Objectives

* Email forensic analysis (headers, routing, content)
* Attachment extraction with recursive unpacking
* Hash-based integrity validation (SHA256/MD5)
* Rule-based threat scoring (NO AI/ML)
* Fully offline operation support
* GitHub Pages visualization layer

---

# 3. 🧱 System Architecture

```
                    ┌────────────────────┐
                    │   Email Input      │
                    │   (.eml file)      │
                    └─────────┬──────────┘
                              │
                ┌─────────────▼─────────────┐
                │   CORE ANALYZER ENGINE    │
                │   (Python / Go optional)  │
                └─────────────┬─────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
┌───────▼───────┐   ┌────────▼────────┐   ┌────────▼────────┐
│ Header Parser  │   │ Attachment     │   │ Rule Engine     │
│ SPF/DKIM/DMARC │   │ Extractor      │   │ Scoring System  │
└───────┬───────┘   └────────┬────────┘   └────────┬────────┘
        │                     │                     │
        └─────────────────────┴─────────────────────┘
                              │
                      ┌───────▼────────┐
                      │ JSON REPORT     │
                      │ BUILDER         │
                      └───────┬────────┘
                              │
              ┌───────────────┴───────────────┐
              │                               │
   ┌──────────▼──────────┐       ┌────────────▼────────────┐
   │ GitHub Pages Viewer │       │ Offline CLI Tool        │
   │ (Static UI only)    │       │ Full Analyzer Engine    │
   └─────────────────────┘       └─────────────────────────┘
```

---

# 4. 📁 Repository Structure

```
EmailAnalyzer/
│
├── analyzer/                  # Offline engine
│   ├── core/
│   │   ├── parser.py
│   │   ├── headers.py
│   │   ├── routing.py
│   │   ├── hashing.py
│   │   ├── attachments.py
│   │   ├── rules_engine.py
│   │   └── report_builder.py
│   │
│   ├── cli/
│   │   └── main.py
│   │
│   └── tests/
│
├── viewer/                    # GitHub Pages UI
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── views/
│   │   └── utils/
│   ├── public/
│   └── build/
│
├── schemas/
│   └── email_report.schema.json
│
├── samples/
│   └── report.json
│
├── docs/
│   ├── architecture.md
│   ├── report-format.md
│   ├── setup.md
│   └── threat-model.md
│
├── scripts/
│   └── export_report.py
│
└── README.md
```

---

# 5. 📊 JSON REPORT SPECIFICATION

---

## 📌 Root Structure

```
meta
email
authentication
routing
content
attachments
threat_intel
phishing_analysis
scoring
```

---

## 5.1 Meta Section

```json
{
  "report_id": "uuid",
  "generated_at": "timestamp",
  "version": "1.0.0",
  "analysis_mode": "offline",
  "processing_time_ms": 1200
}
```

---

## 5.2 Email Section

* Raw email hash
* Parsed headers
* Metadata

```json
{
  "raw_size_bytes": 58234,
  "raw_hash": {
    "sha256": "",
    "md5": ""
  },
  "headers": {
    "from": "",
    "to": [],
    "subject": "",
    "date": "",
    "message_id": ""
  }
}
```

---

## 5.3 Authentication Layer

* SPF validation
* DKIM verification
* DMARC policy check

```
pass | fail | neutral
```

---

## 5.4 Routing Layer

* Email hop chain
* Origin IP
* ASN metadata

---

## 5.5 Content Layer

* Plain text body
* HTML body
* Extracted URLs

Each URL includes:

* domain
* risk score (rule-based)

---

## 5.6 Attachments (Recursive Model)

### Key Feature: Nested analysis

Example:

```
zip → zip → exe → payload
```

Each file contains:

```json
{
  "filename": "",
  "hash": {
    "sha256": "",
    "md5": ""
  },
  "file_type": "",
  "extension_mismatch": true,
  "children": []
}
```

---

## 5.7 Threat Intelligence (Optional Offline Dataset)

* IP reputation list
* Domain blacklist
* File hash blacklist

(No live APIs required)

---

## 5.8 Rule-Based Scoring Engine (NO AI)

### Rules Example:

| Condition          | Score |
| ------------------ | ----- |
| SPF fail           | +20   |
| DKIM fail          | +20   |
| Suspicious domain  | +25   |
| Malicious file     | +40   |
| Extension mismatch | +15   |

---

## 5.9 Final Risk Score

```
0–30   = Clean
31–70  = Suspicious
71–100 = Malicious
```

---

# 6. 🔄 Processing Flow

```
1. Input email (.eml)
2. Parse MIME structure
3. Extract headers
4. Validate SPF/DKIM/DMARC
5. Extract body + URLs
6. Extract attachments
7. Recursive unpacking
8. Compute hashes
9. Apply rule engine
10. Generate JSON report
11. Save report.json
12. Viewer loads JSON (GitHub Pages)
```

---

# 7. 🌐 GitHub Pages Viewer Design

### Purpose:

Static visualization only

### Features:

* Risk dashboard
* Header inspector
* Attachment tree viewer
* URL risk table
* Routing timeline

### Data Source:

```
ONLY report.json
```

No computation allowed in UI.

---

# 8. 💻 Offline CLI Tool

### Command:

```
email-analyzer analyze sample.eml
```

### Output:

```
report.json
```

### Flags:

```
--verbose
--extract-all
--no-intel
```

---

# 9. 🔐 Rule Engine Design

Rules defined in JSON:

```json
{
  "rules": [
    {
      "id": "SPF_FAIL",
      "weight": 20,
      "condition": "spf == 'fail'"
    }
  ]
}
```

---

# 10. 🚫 System Constraints

* ❌ No AI / ML models
* ❌ No backend servers
* ❌ No cloud dependency
* ❌ No paid APIs required
* ❌ Fully offline capable
* ❌ GitHub Pages = static only

---

# 11. 🧠 Design Philosophy

> “Deterministic forensic analysis with fully explainable outputs.”

Everything is:

* Reproducible
* Transparent
* Rule-driven
* Independent of external services

---

# 12. 🚀 Final Output

This project delivers:

### ✔ Advanced offline forensic engine

### ✔ Clean GitHub Pages visualizer

### ✔ Standardized JSON forensic format

### ✔ Fully extensible rule engine

---
