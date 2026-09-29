from dataclasses import dataclass, asdict
from typing import Any


@dataclass
class Detection:
    rule_id: str
    title: str
    severity: str
    confidence: int
    technique: str
    event_index: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


SEVERITY = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def detect(events: list[dict[str, Any]], iocs: dict[str, list[str]]) -> list[Detection]:
    detections: list[Detection] = []
    bad_ips = set(iocs.get("ips", []))
    bad_domains = set(iocs.get("domains", []))
    bad_hashes = set(iocs.get("sha256", []))

    for idx, event in enumerate(events):
        command = str(event.get("command_line", "")).lower()
        process = str(event.get("process", "")).lower()
        path = str(event.get("path", "")).lower()

        if process == "powershell.exe" and "-encodedcommand" in command:
            detections.append(Detection(
                "EDR-001", "Encoded PowerShell execution", "HIGH", 90,
                "T1059.001", idx, "PowerShell was launched with an encoded command."
            ))

        if event.get("destination_ip") in bad_ips or event.get("destination_domain") in bad_domains:
            detections.append(Detection(
                "TI-001", "IOC network match", "CRITICAL", 98,
                "T1071.001", idx, "Network telemetry matched a configured threat-intelligence IOC."
            ))

        if event.get("sha256") in bad_hashes:
            detections.append(Detection(
                "TI-002", "IOC file-hash match", "CRITICAL", 99,
                "T1105", idx, "Observed file hash matched a configured IOC."
            ))

        if event.get("event_type") == "file_write" and "\\temp\\" in path and path.endswith(".exe"):
            detections.append(Detection(
                "EDR-002", "Executable written to temporary directory", "MEDIUM", 78,
                "T1105", idx, "An executable was written under a temporary user directory."
            ))

    return detections
