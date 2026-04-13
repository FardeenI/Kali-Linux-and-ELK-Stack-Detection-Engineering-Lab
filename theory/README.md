# Theory

Background reading for the detection engineering concepts applied in this lab. Start here if you are new to security operations or want to understand the reasoning behind how detections are built and organized.

## Reading Order

### 1. [Security Operations](security-operations.md)
The broader SecOps context detection engineering lives in — threat intelligence, threat hunting, incident response, and how they interact. Establishes why detection engineering is the connective tissue of a security operations program.

### 2. [Detection Engineering Workflow](detection-engineering.md)
The end-to-end process for building a detection: from identifying a gap through research, development, testing, deployment, and ongoing maintenance. Covers the TOML detection format used in this repo and the CI/CD validation pipeline.

### 3. [Adversary Mapping Frameworks](adversary-mapping-frameworks.md)
The three frameworks used to structure and prioritize detection work — Cyber Kill Chain, MITRE ATT&CK, and F3EAD. Explains how ATT&CK tactic and technique IDs map directly to detection rule metadata.
