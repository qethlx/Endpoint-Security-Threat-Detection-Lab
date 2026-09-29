# Endpoint Security & Threat Detection Lab

A hands-on cybersecurity lab project that simulates a lightweight Endpoint Detection and Response (EDR) pipeline.

The project ingests endpoint telemetry, detects suspicious behavior using rule-based analytics, correlates indicators of compromise (IOCs), assigns severity, and generates an incident report.

> **Portfolio / lab project:** This repository demonstrates practical security engineering skills in a controlled environment. It is not a replacement for enterprise EDR/DLP products.

## Security concepts demonstrated

- Endpoint telemetry collection
- Process and network event analysis
- IOC matching (IP, domain, file hash)
- Rule-based threat detection
- Detection severity and confidence scoring
- Incident correlation
- JSON security event format
- Incident response reporting
- MITRE ATT&CK technique mapping
- NIST CSF / ISO 27001 control alignment
- Unit testing and CI

## Architecture

```text
endpoint_events.json
        |
        v
   Event Parser
        |
        v
 Detection Engine <---- IOC Feed
        |
        v
 Correlation / Scoring
        |
        v
 Incident Report (JSON + Markdown)
```

## Detection examples

The included sample telemetry contains simulated events such as:

- PowerShell downloading an executable
- Suspicious encoded PowerShell command
- Connection to a known malicious IP
- Execution from a temporary directory
- Suspicious persistence behavior
- File hash matching an IOC

The engine maps detections to relevant MITRE ATT&CK techniques such as `T1059.001 PowerShell`, `T1105 Ingress Tool Transfer`, and `T1547.001 Registry Run Keys / Startup Folder`.

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m src.main --events data/endpoint_events.json --iocs data/iocs.json --output reports/incident_report.json
```

Generate a human-readable Markdown report:

```bash
python -m src.report --input reports/incident_report.json --output reports/incident_report.md
```

Run tests:

```bash
pytest -q
```

## Example output

The engine produces a structured incident containing:

- incident ID
- affected host
- severity
- confidence
- detection rules triggered
- indicators observed
- ATT&CK techniques
- recommended response actions

## Why this project is relevant to cybersecurity roles

This lab demonstrates the workflow behind endpoint security and threat monitoring: collect telemetry, identify suspicious behavior, enrich it with IOCs, correlate findings, prioritize incidents, and document response actions.

It can also be extended with a real log source, Sysmon, an ELK/Splunk backend, an EDR API, or a DLP event source.

## Framework alignment

| Capability | Project implementation |
|---|---|
| Endpoint security | Endpoint process/network/file telemetry |
| EDR concepts | Detection, correlation, severity and response |
| Threat intelligence | IOC feed and enrichment |
| Incident response | Incident report and recommended actions |
| NIST CSF | Detect / Respond workflow mapping |
| ISO 27001 | Logging, monitoring, incident management concepts |
| Security monitoring | Rule-based telemetry analysis |

## Disclaimer

All telemetry and indicators in this repository are synthetic. No malware is executed and no external systems are contacted by the project.
