# Detection Engineering Workflow

The detection engineering workflow is a repeatable, end-to-end process for creating, validating, deploying, and maintaining detection rules. Each phase feeds into the next, forming a continuous loop that improves detection coverage over time.

## Workflow Phases

| Phase | Input | Output |
|-------|-------|--------|
| 1. Requirements | Threat intel, incident reports, hunt findings | Prioritized detection gap |
| 2. Research | Threat reports, ATT&CK techniques, log sources | Detection hypothesis |
| 3. Development | Hypothesis, query language, TOML detection template | Draft detection rule |
| 4. Testing | Draft rule, sample data, lab environment | Validated detection rule |
| 5. Deployment | Validated rule, CI/CD pipeline | Production detection |
| 6. Tuning & Maintenance | Alert feedback, false positive data | Refined detection rule |

---

## 1. Requirements

Detection work starts with a question: **what do we need to detect, and why?**

Inputs come from across the security operations team:

- **Threat Intelligence** — new adversary TTPs, campaigns targeting your industry, or published indicators of compromise
- **Incident Response** — gaps identified during real incident investigations where existing detections failed to fire
- **Threat Hunting** — hypotheses that were manually validated and now need to be automated as persistent detections
- **Compliance / Risk** — regulatory requirements or risk assessments that mandate monitoring for specific activity

The output of this phase is a **prioritized detection gap** — a clear statement of what malicious behavior needs a detection and why it matters to the organization.

## 2. Research

With a detection gap identified, research the adversary behavior in depth:

- **Map to MITRE ATT&CK** — Identify the relevant tactic, technique, and sub-technique. This drives both the detection logic and the `[[rule.threat]]` metadata in the TOML rule file. Every detection must include valid tactic and technique IDs that pass automated validation against the official MITRE Enterprise ATT&CK dataset.
- **Identify data sources** — Determine which logs or telemetry provide visibility into the behavior. Common sources include endpoint logs (Sysmon, EDR), network traffic, authentication logs, and cloud audit trails.
- **Verify field availability in Elastic** — Confirm the relevant ECS (Elastic Common Schema) fields are present in your index. For example, `process.name`, `process.command_line`, and `process.parent.name` must be populated by your log shipper before a process-based detection can fire.
- **Study adversary tradecraft** — Review threat reports, malware samples, and red team tooling to understand how the technique is executed in practice. Look for observable artifacts like process command lines, file paths, registry keys, or network patterns.
- **Document assumptions** — Write down what conditions must be true for the detection to work (e.g., "Sysmon Process Create events are being collected from all endpoints and `process.command_line` is indexed").

The output is a **detection hypothesis**: a plain-language statement describing the observable behavior and the data source that captures it.

> **Example hypothesis**: "When an attacker uses msfvenom to generate a PowerShell payload, the default command line contains the string `powershell -w hidden -nop -c $a=`. This string appears in Sysmon Process Create events under `process.command_line`."

## 3. Development

Translate the hypothesis into a detection rule. In this repo, detections follow the **TOML** format and target the Elastic Security platform:

```toml
[metadata]
creation_date = "2024/01/15"

[rule]
author = "Your Name"
name = "PowerShell Execution with Hidden Window"
description = "Detects PowerShell launched with -WindowStyle Hidden or -w hidden, a common technique to suppress the console window during malicious execution."
rule_id = "00000000-0000-0000-0000-000000000001"
type = "query"
from = "now-6m"
risk_score = 47
severity = "medium"
query = "process.name:powershell.exe AND process.command_line:(*-w* hidden* OR *-WindowStyle* hidden*)"

[[rule.threat]]
framework = "MITRE ATT&CK"

[rule.threat.tactic]
id = "TA0002"
name = "Execution"
reference = "https://attack.mitre.org/tactics/TA0002/"

[rule.threat.technique]
id = "T1059"
name = "Command and Scripting Interpreter"
reference = "https://attack.mitre.org/techniques/T1059/"

[[rule.threat.technique.subtechnique]]
id = "T1059.001"
name = "PowerShell"
reference = "https://attack.mitre.org/techniques/T1059/001/"
```

TOML detections live in the `detections/` directory. The CI/CD pipeline validates TOML syntax and MITRE mappings on every push using `development/validation.py` and `development/mitre.py`.

### What Makes a Good Detection

- **Specific** — targets a well-defined behavior, not broad categories of activity
- **Mapped** — includes accurate MITRE ATT&CK tactic and technique references
- **Described** — the `description` field explains what the rule detects and why it matters, not just what query it runs
- **Scored** — `risk_score` (0–100 integer) and `severity` (`low`/`medium`/`high`/`critical`) reflect the actual risk to the organization, considering both impact and confidence
- **Testable** — the query logic can be triggered in a lab to verify it works

### Detection as Code

Treating detections as code means they follow software engineering practices:

- **Version control** — all rules are stored in Git as `.toml` files and changes are tracked through commits
- **Peer review** — new or modified detections go through pull requests before merging
- **Validation** — `development/validation.py` checks required TOML fields; `development/mitre.py` validates tactic and technique IDs against the live MITRE Enterprise ATT&CK dataset
- **CI/CD** — GitHub Actions workflows automate validation on every push and sync approved detections to Elastic Security (see `.github/workflows/`)
- **Export & reporting** — helper scripts in `development/` convert TOML detections to CSV, Markdown, and MITRE ATT&CK Navigator JSON for coverage visibility

## 4. Testing

Before a detection reaches production, it must be tested:

- **Unit testing** — use the validation scripts in `development/` to confirm the rule has valid TOML syntax, all required fields are present, and MITRE tactic/technique IDs are correct against the official ATT&CK dataset
- **Lab validation** — execute the adversary technique in a controlled environment and verify the detection fires. The `setup/` directory contains Terraform configurations for deploying a lab environment
- **False positive analysis** — run the query against production data (or a representative sample) to identify benign activity that would trigger the rule. Adjust the query logic or add exclusions as needed
- **Edge case review** — consider variations of the technique that might evade the detection (different tools, obfuscation, alternative execution methods)

A detection is ready for deployment when it:
1. Passes all automated validation checks
2. Successfully fires on simulated adversary behavior
3. Has an acceptable false positive rate

## 5. Deployment

Deploy the validated detection to the production SIEM or detection platform:

- Merge the detection rule into the `main` branch through a pull request
- CI/CD pipelines pick up the change and push the rule to the detection platform
- Verify the rule is active and receiving data in production
- Document the deployment in the detection's commit history

## 6. Tuning & Maintenance

Detection engineering is not a "set and forget" activity. Every deployed detection requires ongoing attention:

- **Monitor alert volume** — a sudden spike or drop in alerts may indicate a change in the environment or a problem with the detection
- **Track false positives** — when analysts flag alerts as false positives, update the detection logic to exclude the benign behavior
- **Reassess risk scores** — as the threat landscape changes, a detection's `risk_score` (0–100) and `severity` may need adjustment in the TOML file
- **Update for ATT&CK changes** — the MITRE ATT&CK framework is updated regularly; keep technique and tactic mappings current
- **Retire stale detections** — if the underlying data source is no longer available or the technique is no longer relevant, remove the detection rather than leaving it broken

## The Feedback Loop

The workflow is a cycle, not a straight line. Each phase generates feedback that improves the others:

```
Requirements ──> Research ──> Development ──> Testing ──> Deployment
     ^                                                        │
     │                                                        v
     └──────────────────── Tuning & Maintenance ──────────────┘
```

- Incidents that bypass detections create new **requirements**
- False positives from production drive **research** into better query logic
- Retired detections reveal **gaps** that restart the cycle

This continuous loop is what separates a mature detection engineering program from a static set of vendor-provided rules.