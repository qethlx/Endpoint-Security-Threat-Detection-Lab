# Endpoint Security Incident Report

**Events processed:** 4
**Detections:** 4

## Incidents

### INC-8A572B76 — WS-FIN-014
- Severity: **CRITICAL**
- Confidence: **99%**
- Detections:
  - `EDR-001` Encoded PowerShell execution — ATT&CK `T1059.001`
  - `TI-001` IOC network match — ATT&CK `T1071.001`
  - `TI-002` IOC file-hash match — ATT&CK `T1105`
  - `EDR-002` Executable written to temporary directory — ATT&CK `T1105`
- Recommended response:
  - Isolate the affected endpoint if confirmed malicious.
  - Preserve relevant endpoint and network logs for investigation.
  - Review the parent process and user activity around the alert.
  - Block confirmed malicious indicators at appropriate controls.
  - Reset affected credentials if credential compromise is suspected.
