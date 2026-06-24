# AWS IAM Security Scanner

A Python-based security tool that scans AWS IAM configurations for
misconfigurations, privilege escalation paths, and compliance gaps.

---

## Why I Built This

IAM misconfiguration is the **#1 cause** of AWS account compromise. Tools like this automate what a security engineer would manually check during a cloud security audit.
The goal was to understand both the **attack surface** (what misconfigurations enable privilege escalation) and the **detection logic** (how to programmatically identify them at scale).

---

## What Problem Does This Solve?

Misconfigured IAM policies remain one of the leading causes of cloud breaches. This tool
automatically detects dangerous permission patterns that manual audits
miss, and generates actionable remediation steps.

---

## Key Features

- Detects overly permissive IAM policies (wildcard actions and resources)
- Identifies users with console access but no MFA enabled
- Flags stale and unrotated access keys
- Detects privilege escalation permissions (e.g., iam:CreatePolicyVersion, iam:PassRole, iam:AttachUserPolicy)
- Analyzes role trust policies for overly permissive principals (`*`) and missing ExternalId conditions
- Checks account password policy strength
- Flags direct policy attachments to users instead of groups
- Custom CVSS-inspired risk scoring with contextual modifiers
- Colorized terminal reports + exportable JSON reports
- Support for **live AWS scanning** and **offline file-based analysis**
- Loads pre-collected IAM data (compatible with exported JSON or tools like BishopFox iam-vulnerable)
- Uses AWS paginators for reliable results on large accounts
- Fully read-only — no changes are made to your AWS environment
- Comprehensive unit tests using mocked data

---

## Tech Stack

| Tool              | Purpose                                      |
|-------------------|----------------------------------------------|
| Python 3.x        | Core language                                |
| Boto3             | AWS SDK for IAM data collection              |
| colorama          | Colored terminal output                      |
| python-dateutil   | Timezone-aware datetime handling             |
| pytest            | Unit testing with mocked IAM data            |

---

## Project Structure

iam-scanner/ ├── scanner/ │   ├── init.py │   ├── iam_collector.py       # Collects IAM data (live or from file) │   ├── policy_parser.py       # Analyzes policy documents │   ├── rule_engine.py         # Runs all 12 security rules │   ├── risk_scorer.py         # Calculates risk scores │   └── report_generator.py    # Terminal + JSON reporting ├── rules/ │   └── rules_config.json      # Rule metadata ├── output/                    # Generated reports ├── tests/ │   └── test_rules.py          # Unit tests (29 tests) ├── main.py                    # CLI entry point └── requirements.txt

---

## Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/iam-scanner.git
   cd iam-scanner

2. Install dependencies:

pip install -r requirements.txt

3. Configure AWS credentials (one of the following):
   • Run aws configure
   • Use a named profile: --profile myprofile
   • Set environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)

│ Note: The scanner is read-only. It only requires iam:* read/list permissions. The ReadOnlyAccess AWS managed policy works well.

───

Usage

Live AWS Scan (Default)

python main.py

Common options:

# Filter by severity
python main.py --severity HIGH

# Output formats
python main.py --output both
python main.py --output json

# Use a specific AWS profile
python main.py --profile production

# Filter by entity type
python main.py --entity-type USER

File Mode (Offline / Pre-collected Data)

Load data from a previously exported JSON file. Useful for:
• Offline analysis
• CI/CD pipelines
• Testing with synthetic data (e.g. from BishopFox iam-vulnerable)

python main.py --data-source file --input-file exported_data.json

# Combine with other options
python main.py --data-source file --input-file data.json --severity CRITICAL --output both

───

Available Detection Rules

The scanner implements 12 rules:

┌──────────┬────────────────────────────────────────────────┬──────────┐
│ Rule ID  │ Name                                           │ Severity │
├──────────┼────────────────────────────────────────────────┼──────────┤
│ RULE_001 │ Root account has no MFA                        │ CRITICAL │
├──────────┼────────────────────────────────────────────────┼──────────┤
│ RULE_002 │ IAM user has console access but no MFA         │ HIGH     │
├──────────┼────────────────────────────────────────────────┼──────────┤
│ RULE_003 │ Policy grants full administrative access (*:*) │ CRITICAL │
├──────────┼────────────────────────────────────────────────┼──────────┤
│ RULE_004 │ Stale access key (unused > 90 days)            │ HIGH     │
├──────────┼────────────────────────────────────────────────┼──────────┤
│ RULE_005 │ Access key older than 90 days                  │ MEDIUM   │
├──────────┼────────────────────────────────────────────────┼──────────┤
│ RULE_006 │ Inline policy with wildcard permissions        │ HIGH     │
├──────────┼────────────────────────────────────────────────┼──────────┤
│ RULE_007 │ Overly permissive role trust policy (*)        │ CRITICAL │
├──────────┼────────────────────────────────────────────────┼──────────┤
│ RULE_008 │ Privilege escalation permissions               │ HIGH     │
├──────────┼────────────────────────────────────────────────┼──────────┤
│ RULE_009 │ Weak account password policy                   │ MEDIUM   │
├──────────┼────────────────────────────────────────────────┼──────────┤
│ RULE_010 │ Direct policy attachment to user               │ LOW      │
├──────────┼────────────────────────────────────────────────┼──────────┤
│ RULE_011 │ Cross-account trust without ExternalId         │ HIGH     │
├──────────┼────────────────────────────────────────────────┼──────────┤
│ RULE_012 │ Broad permissions with no conditions           │ MEDIUM   │
└──────────┴────────────────────────────────────────────────┴──────────┘

───

Output

• Terminal Report: Color-coded by severity with descriptions and remediation steps.
• JSON Report: Saved to output/scan_report_YYYYMMDD_HHMMSS.json containing full metadata, summary counts, and all findings sorted by risk score.

Example summary:

Total Findings : 7
CRITICAL       : 2
HIGH           : 3
MEDIUM         : 2
LOW            : 0

───

Project Status

Completed — core functionality is fully implemented and tested.

• Live IAM collection with full pagination
• Policy parsing and 12 security rules
• Risk scoring
• Terminal + JSON reporting
• File-based data source support for offline use

───

Author

Vanshikha | B.Tech Cybersecurity, SSPU Pune
(https://www.linkedin.com/in/vanshikha-panwar/)

---
