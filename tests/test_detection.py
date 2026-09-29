from src.detection import detect


def test_encoded_powershell_detection():
    events = [{
        "event_type": "process_start",
        "process": "powershell.exe",
        "command_line": "powershell.exe -EncodedCommand ABC",
        "host": "TEST"
    }]
    detections = detect(events, {})
    assert any(d.rule_id == "EDR-001" for d in detections)


def test_ioc_detection():
    events = [{
        "event_type": "network_connection",
        "destination_ip": "203.0.113.66",
        "host": "TEST"
    }]
    detections = detect(events, {"ips": ["203.0.113.66"]})
    assert any(d.rule_id == "TI-001" for d in detections)
