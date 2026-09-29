import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    report = json.loads(Path(args.input).read_text(encoding="utf-8"))
    lines = [
        "# Endpoint Security Incident Report",
        "",
        f"**Events processed:** {report['events_processed']}",
        f"**Detections:** {report['detections']}",
        "",
        "## Incidents",
        ""
    ]
    for incident in report["incidents"]:
        lines += [
            f"### {incident['incident_id']} — {incident['host']}",
            f"- Severity: **{incident['severity']}**",
            f"- Confidence: **{incident['confidence']}%**",
            "- Detections:"
        ]
        for d in incident["detections"]:
            lines.append(f"  - `{d['rule_id']}` {d['title']} — ATT&CK `{d['technique']}`")
        lines += ["- Recommended response:"]
        lines += [f"  - {action}" for action in incident["recommended_actions"]]
        lines.append("")

    Path(args.output).write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
