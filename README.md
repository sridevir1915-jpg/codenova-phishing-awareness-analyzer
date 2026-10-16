# Phishing Awareness Analyzer & Email Auditor

A lightweight Python tool designed to evaluate raw emails and headers for phishing threat indicators, extract suspicious URLs, calculate threat scores, and generate actionable awareness reports. Developed for the **CodeNova Cybersecurity Remote Internship Program (Batch 01)**.

---

## Key Features

- **Header Inspection**: Analyzes `From`, `Reply-To`, and `Subject` headers for address mismatches and spoofing.
- **Psychological Trigger Detection**: Identifies urgency indicators (e.g., "account locked", "verify now", "immediate action").
- **Link Extraction & Analysis**: Uses regular expressions to extract URLs and detect IP-based domains or suspicious TLDs (`.xyz`, `.top`, `.club`).
- **Threat Scoring & Categorization**: Computes a total risk score ($0-100$) and assigns risk levels (**Low**, **Medium**, **High Risk**).
- **Automated Reporting**: Generates a clean awareness report detailing identified indicators and extracted URLs.

---

## Tech Stack & Tooling

- **Language**: Python 3
- **Core Modules**: `re`, `urllib.parse`, `email`, `unittest`

---

## Project Structure

```text
codenova-phishing-awareness-analyzer/
├── analyzer.py       # Core phishing analysis and scoring engine
├── test_analyzer.py  # Unit test suite validating safe and malicious email logic
├── README.md         # Technical project documentation
└── .gitignore        # Ignores Python cache files
```

---

## How to Run

### 1. Execute the Analyzer
Run the script to analyze the sample email:

```cmd
python analyzer.py
```

### 2. Run the Unit Tests
Validate scoring logic against both legitimate and phishing email test cases:

```cmd
python -m unittest test_analyzer.py
```

---

## Certificate & Internship Specifications

- **Program**: CodeNova Cybersecurity Remote Internship (Batch 01)
- **Task**: Task 2 - Phishing Awareness Analyzer
- **Submission Deadline**: 06 November 2026