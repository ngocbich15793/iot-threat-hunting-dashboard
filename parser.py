import json
from pathlib import Path
from datetime import datetime

EVE_LOG = Path("suricata/logs/eve.json")

def parse_alerts(max_lines: int = 1000) -> list[dict]:
    """Đọc eve.json, trả về list alert dạng dict."""
    alerts = []
    if not EVE_LOG.exists():
        return alerts

    with open(EVE_LOG, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()[-max_lines:]

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
            if ev.get("event_type") != "alert":
                continue

            alert_info = ev.get("alert", {})
            flow = ev.get("flow", {})

            alerts.append({
                # Thời gian
                "timestamp": ev.get("timestamp", ""),
                # Network
                "src_ip":    ev.get("src_ip", ""),
                "dest_ip":   ev.get("dest_ip", ""),
                "src_port":  ev.get("src_port", 0),
                "dest_port": ev.get("dest_port", 0),
                "proto":     ev.get("proto", ""),
                # Suricata alert
                "signature":    alert_info.get("signature", ""),
                "severity":     alert_info.get("severity", 0),
                "category":     alert_info.get("category", ""),
                "action":       alert_info.get("action", ""),
                # Flow stats (có nếu Suricata bật flow logging)
                "pkts_toserver":  flow.get("pkts_toserver", 0),
                "pkts_toclient":  flow.get("pkts_toclient", 0),
                "bytes_toserver": flow.get("bytes_toserver", 0),
                "bytes_toclient": flow.get("bytes_toclient", 0),
            })
        except (json.JSONDecodeError, KeyError):
            continue

    return alerts


def parse_flows(max_lines: int = 2000) -> list[dict]:
    """Đọc flow events từ eve.json để dùng cho ML classification."""
    flows = []
    if not EVE_LOG.exists():
        return flows

    with open(EVE_LOG, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()[-max_lines:]

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
            if ev.get("event_type") not in ("alert", "flow", "netflow"):
                continue

            flow = ev.get("flow", {})
            flows.append({
                "timestamp":      ev.get("timestamp", ""),
                "src_ip":         ev.get("src_ip", ""),
                "dest_ip":        ev.get("dest_ip", ""),
                "src_port":       ev.get("src_port", 0),
                "dest_port":      ev.get("dest_port", 0),
                "proto":          ev.get("proto", ""),
                "pkts_toserver":  flow.get("pkts_toserver", 0),
                "pkts_toclient":  flow.get("pkts_toclient", 0),
                "bytes_toserver": flow.get("bytes_toserver", 0),
                "bytes_toclient": flow.get("bytes_toclient", 0),
                "age":            flow.get("age", 0),
            })
        except (json.JSONDecodeError, KeyError):
            continue

    return flows