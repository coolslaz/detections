# Detection Engineering Repository

A curated collection of **security detection rules, threat-hunting queries, and detection engineering research** developed, adapted, and maintained for defensive security operations.

This repository is intended to make detection logic easier to **review, test, tune, reuse, and version-control** across security platforms. Some detections may be developed or refined using [Detections.ai](https://detections.ai/), with GitHub serving as the long-term source-control and collaboration layer.

> **Defensive use only.** Detection logic in this repository should be validated and tuned for your own environment before being deployed to production.

---

## 🎯 Objectives

This repository aims to:

- Build practical, high-signal security detections.
- Convert threat intelligence into actionable detection logic.
- Improve visibility across endpoint, identity, cloud, network, and application telemetry.
- Map detections to **MITRE ATT&CK** tactics and techniques.
- Document assumptions, dependencies, and expected false positives.
- Support repeatable testing, tuning, peer review, and lifecycle management.
- Preserve detection engineering knowledge in a version-controlled format.

---

## 🛡️ Detection Coverage

Rules in this repository may cover areas such as:

- Endpoint execution and persistence
- Credential access and identity compromise
- Microsoft Entra ID / Microsoft 365 activity
- Active Directory attacks
- PowerShell and command-line abuse
- Living-off-the-land binaries and scripts
- Cloud control-plane activity
- Suspicious authentication behaviour
- Malware and post-exploitation activity
- Lateral movement
- Defense evasion
- Data collection and exfiltration
- Network and web-based threats
- Threat-actor and campaign-specific activity
- CVE exploitation and post-exploitation
- Threat hunting and behavioural analytics

---

## 🔎 Detection Languages

Depending on the individual rule and target platform, detections may be represented in one or more of the following formats:

| Format | Typical Use |
|---|---|
| **KQL** | Microsoft Sentinel, Microsoft Defender XDR |
| **Sigma** | Vendor-neutral log detection rules |
| **SPL** | Splunk |
| **YARA** | File and malware identification |
| **YARA-L** | Google SecOps / Chronicle |
| **Suricata** | Network IDS/IPS |
| **S1QL** | SentinelOne |
| **Cortex XQL / Cortex Query Language** | Palo Alto Cortex |
| **CQL** | Platform-specific detection/query use cases |

Not every detection is available in every language.

---

## 📁 Suggested Repository Structure

```text
.
├── detections/
│   ├── kql/
│   ├── sigma/
│   ├── spl/
│   ├── yara/
│   ├── suricata/
│   └── other/
├── hunting/
│   ├── endpoint/
│   ├── identity/
│   ├── cloud/
│   └── network/
├── threat-intel/
├── tests/
├── docs/
├── README.md
└── LICENSE
```

Where practical, detections should be grouped by **platform, data source, behaviour, or ATT&CK technique** rather than by threat actor alone. Behaviour-based detections are generally more reusable and resilient to changes in adversary infrastructure.

---

## 🧩 Recommended Detection Metadata

Each detection should ideally document the following:

```yaml
title: Example Detection Name
id: unique-rule-id
status: experimental
description: >
  Short explanation of the behaviour being detected.

author: Your Name
date: YYYY-MM-DD
modified: YYYY-MM-DD

severity: medium

platform:
  - windows

data_sources:
  - process_creation

mitre_attack:
  tactics:
    - execution
  techniques:
    - T1059

references:
  - https://example.com/reference

false_positives:
  - Legitimate administrative activity

testing:
  - Tested against representative telemetry

notes:
  - Environment-specific tuning may be required
```

Metadata can be adapted to the syntax required by the target detection platform.

---

## 🧠 Detection Engineering Principles

### 1. Detect behaviour, not just indicators

Hashes, IP addresses, domains, and filenames can provide valuable short-term coverage, but adversaries can change them quickly.

Where possible, detections should focus on:

- unusual process relationships;
- command-line behaviour;
- authentication sequences;
- privilege changes;
- persistence mechanisms;
- abnormal resource access;
- suspicious combinations of otherwise legitimate tools.

### 2. Document telemetry requirements

A detection is only useful when the required events are available.

Each rule should identify relevant dependencies such as:

- Microsoft Defender for Endpoint
- Microsoft Entra ID sign-in logs
- Microsoft 365 audit logs
- Windows Security Events
- Sysmon
- EDR telemetry
- firewall/proxy logs
- DNS logs
- cloud audit logs
- identity enrichment / UEBA

### 3. Expect environment-specific tuning

A detection that performs well in one organisation may be noisy in another.

Potential tuning variables include:

- privileged/admin accounts;
- known management tools;
- automation accounts;
- approved scripts;
- expected geographies;
- server roles;
- trusted paths;
- sanctioned remote-management software;
- development and build infrastructure.

### 4. Prefer explainable detections

Analysts should be able to understand:

- **what** triggered;
- **why** it is suspicious;
- **which telemetry** produced the alert;
- **what ATT&CK behaviour** it represents;
- **what to investigate next**.

---

## 🧪 Testing and Validation

Before promoting a detection into production:

1. Confirm that the required telemetry is present.
2. Validate field names and schema mappings.
3. Run the query across a representative historical period.
4. Review expected legitimate matches.
5. Test against known malicious or simulated behaviour where possible.
6. Measure alert volume and signal quality.
7. Tune exclusions conservatively.
8. Document known false positives.
9. Peer-review the detection logic.
10. Re-test after major platform or schema changes.

### Suggested Lifecycle

```text
Research
   ↓
Experimental
   ↓
Testing
   ↓
Tuning
   ↓
Production
   ↓
Monitoring
   ↓
Review / Update / Retire
```

---

## 🧭 MITRE ATT&CK Mapping

Where applicable, detections are mapped to the [MITRE ATT&CK](https://attack.mitre.org/) framework.

Example:

```text
Tactic:     Credential Access
Technique:  OS Credential Dumping
ATT&CK ID:  T1003
```

ATT&CK mapping is useful for:

- coverage analysis;
- identifying detection gaps;
- purple-team exercises;
- threat-informed defence;
- reporting detection maturity.

ATT&CK mappings should be reviewed rather than treated as automatically authoritative.

---

## 🛰️ Threat-Intelligence-to-Detection Workflow

A typical workflow used for new detections is:

```text
Threat Intelligence / Research
          ↓
Identify Observable Behaviours
          ↓
Identify Required Telemetry
          ↓
Map to MITRE ATT&CK
          ↓
Develop Detection Logic
          ↓
Validate Against Available Data
          ↓
Tune False Positives
          ↓
Document Investigation Guidance
          ↓
Peer Review
          ↓
Deploy and Monitor
```

Campaign-specific intelligence may result in both:

- **IOC-based detections** for immediate coverage; and
- **behaviour-based detections** for longer-term resilience.

---

## 🚀 Using the Rules

### Microsoft Sentinel / Defender XDR

For KQL detections:

1. Open the relevant Microsoft security portal.
2. Confirm that the tables referenced by the query exist.
3. Run the query manually first.
4. Adjust table names, thresholds, watchlists, or environment-specific exclusions.
5. Validate results.
6. Convert the query into an analytics/detection rule where appropriate.

### Sigma

Sigma detections should be treated as portable detection logic rather than guaranteed drop-in rules.

Before deployment:

1. Check the required log source.
2. Confirm field mappings.
3. Convert the rule using the appropriate Sigma backend/tooling.
4. Review the generated query.
5. Test against the destination SIEM.
6. Tune environment-specific exclusions.

---

## 🔬 Threat Hunting vs Production Detection

Not every query in this repository is intended to generate an alert.

| Type | Purpose |
|---|---|
| **Detection** | Designed for recurring automated alerting |
| **Threat Hunt** | Designed for analyst-led investigation |
| **Research Query** | Explores telemetry or validates a hypothesis |
| **IOC Sweep** | Searches for known indicators |
| **Correlation** | Combines multiple weak signals into stronger evidence |

Threat-hunting queries may intentionally favour **recall over precision** and can therefore be unsuitable for direct production alerting.

---

## ⚠️ False Positives

False positives are expected in detection engineering.

Before adding broad exclusions:

- confirm the activity is genuinely benign;
- determine whether the behaviour is expected for all users/devices or only a subset;
- prefer narrow allow-lists;
- avoid excluding entire tools or parent processes unless necessary;
- periodically review exclusions for continued validity.

An exclusion that removes noise today can create a blind spot tomorrow.

---

## 🔐 Operational Security

Do **not** commit:

- private tenant identifiers;
- customer information;
- credentials or secrets;
- production API keys;
- internal-only IP ranges unless intentionally sanitised;
- confidential threat intelligence;
- sensitive investigation artefacts;
- personally identifiable information.

Use representative placeholders in public rules where sensitive environmental values are required.

---

## 🤝 Contributions

Contributions, improvements, test results, and peer review are welcome.

When proposing a new detection, please include:

- clear title and description;
- target platform;
- required data source(s);
- detection logic;
- ATT&CK mapping where applicable;
- references;
- expected false positives;
- testing notes;
- recommended investigation steps.

For substantial changes, use a pull request so the detection can be reviewed before merging.

---

## ✅ Pull Request Checklist

Before submitting a detection:

- [ ] Query/rule syntax is valid
- [ ] Required telemetry is documented
- [ ] Detection behaviour is explained
- [ ] ATT&CK mapping has been reviewed
- [ ] References are included
- [ ] Known false positives are documented
- [ ] Environment-specific values are sanitised
- [ ] Detection has been tested where practical
- [ ] Rule is not a duplicate of an existing detection
- [ ] No credentials or sensitive organisational data are included

---

## 🔗 Detections.ai

Some rules in this repository may originate from, be researched with, or be refined using the **Detections.ai** detection engineering community and workspace.

Detections.ai supports community detection development, detection translation, MITRE ATT&CK mapping, threat-intelligence-assisted detection creation, and multiple detection languages.

Platform:

**https://detections.ai/**

Personal workspace:

**https://detections.ai/workspace/user/personal/detections**

> The personal workspace may require authentication and may contain detections that are not published publicly.

---

## 📚 Useful References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [SigmaHQ](https://sigmahq.io/)
- [Microsoft Sentinel](https://learn.microsoft.com/azure/sentinel/)
- [Microsoft Defender XDR Advanced Hunting](https://learn.microsoft.com/defender-xdr/advanced-hunting-overview)
- [Detections.ai](https://detections.ai/)

---

## ⚖️ Disclaimer

The content in this repository is provided for **defensive cybersecurity, research, detection engineering, and threat-hunting purposes**.

Detection rules should not be assumed to be production-ready without validation. Log schemas, field names, data availability, normal behaviour, and threat models differ between environments.

The repository maintainers make no guarantee that a detection will identify every instance of a technique or that it will operate without false positives.

Always test and tune rules before operational deployment.

---

## ⭐ Support

If you find a detection useful:

- star the repository;
- suggest improvements;
- submit test results;
- contribute additional mappings or platform translations;
- share defensive lessons learned.

**Better detections come from continuous testing, collaboration, and refinement.**

## License

CC BY-NC-SA 4.0

This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.
