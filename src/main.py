import argparse
import json
import uuid
from collections import defaultdict
from pathlib import Path

from .detection import SEVERITY, detect


def load_json(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def build_incident(events, detections):
    by_host = defaultdict(list)
    for d in detections:
        by_host[events[d.event_index]["host"]].append(d)

    incidents = []
    for host, host_detections in by_host.items():
        highest = max(host_detections, key=lambda x: SEVERITY[x.severity])
        incidents.append({
            "incident_id": "INC-" + uuid.uuid4().hex[:8].upper(),
            "host": host,
            "severity": highest.severity,
            "confidence": max(d.confidence for d in host_detections),
            "detections": [d.to_dict() for d in host_detections],
            "recommended_actions": [
                "Isolate the affected endpoint if confirmed malicious.",
                "Preserve relevant endpoint and network logs for investigation.",
                "Review the parent process and user activity around the alert.",
                "Block confirmed malicious indicators at appropriate controls.",
                "Reset affected credentials if credential compromise is suspected."
            ]
        })
    return incidents


def main():
    parser = argparse.ArgumentParser(description="Synthetic endpoint detection lab")
    parser.add_argument("--events", required=True)
    parser.add_argument("--iocs", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    events = load_json(args.events)
    iocs = load_json(args.iocs)
    detections = detect(events, iocs)
    report = {
        "project": "Endpoint Security & Threat Detection Lab",
        "events_processed": len(events),
        "detections": len(detections),
        "incidents": build_incident(events, detections)
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Processed {len(events)} events; generated {len(detections)} detections.")


if __name__ == "__main__":
    main()
