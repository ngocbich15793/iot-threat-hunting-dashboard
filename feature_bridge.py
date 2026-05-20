import pickle
import numpy as np
import pandas as pd
from pathlib import Path

MODEL_PATH = Path("models/rf_model_v3.pkl")

_bundle = None

def _load_bundle():
    global _bundle
    if _bundle is None:
        with open(MODEL_PATH, "rb") as f:
            _bundle = pickle.load(f)
    return _bundle


def flow_to_features(flow: dict, feature_cols: list) -> pd.DataFrame:
    """
    Map Suricata flow fields vào feature vector khớp với FEATURE_COLS.
    Các field không map được → giữ 0 (model đã train với fillna(0)).
    """
    proto = str(flow.get("proto", "")).upper()
    dest_port = int(flow.get("dest_port", 0))
    src_port  = int(flow.get("src_port", 0))

    pkts_toserver  = float(flow.get("pkts_toserver", 0))
    pkts_toclient  = float(flow.get("pkts_toclient", 0))
    bytes_toserver = float(flow.get("bytes_toserver", 0))
    bytes_toclient = float(flow.get("bytes_toclient", 0))
    age            = float(flow.get("age", 0))

    total_pkts  = pkts_toserver + pkts_toclient
    total_bytes = bytes_toserver + bytes_toclient
    rate = total_bytes / age if age > 0 else 0.0

    # Map protocol flags
    is_tcp  = 1 if proto == "TCP"  else 0
    is_udp  = 1 if proto == "UDP"  else 0
    is_icmp = 1 if proto == "ICMP" else 0

    # Map well-known ports → protocol columns
    is_http  = 1 if dest_port in (80, 8080)   else 0
    is_https = 1 if dest_port == 443           else 0
    is_dns   = 1 if dest_port == 53            else 0
    is_ssh   = 1 if dest_port == 22            else 0
    is_smtp  = 1 if dest_port in (25, 587)     else 0
    is_telnet= 1 if dest_port == 23            else 0

    mapping = {
        "flow_duration":    age,
        "Header_Length":    0,
        "Duration":         age,
        "Rate":             rate,
        "Srate":            bytes_toserver / age if age > 0 else 0,
        "Drate":            bytes_toclient / age if age > 0 else 0,
        "fin_flag_number":  0,
        "syn_flag_number":  0,
        "rst_flag_number":  0,
        "psh_flag_number":  0,
        "ack_flag_number":  0,
        "ece_flag_number":  0,
        "cwr_flag_number":  0,
        "ack_count":        0,
        "syn_count":        0,
        "fin_count":        0,
        "urg_count":        0,
        "rst_count":        0,
        "HTTP":     is_http,
        "HTTPS":    is_https,
        "DNS":      is_dns,
        "Telnet":   is_telnet,
        "SMTP":     is_smtp,
        "SSH":      is_ssh,
        "IRC":      1 if dest_port == 6667 else 0,
        "TCP":      is_tcp,
        "UDP":      is_udp,
        "DHCP":     1 if dest_port == 67 else 0,
        "ARP":      0,
        "ICMP":     is_icmp,
        "IPv":      1,
        "LLC":      0,
        "Tot sum":  total_bytes,
        "Min":      min(bytes_toserver, bytes_toclient),
        "Max":      max(bytes_toserver, bytes_toclient),
        "AVG":      total_bytes / total_pkts if total_pkts > 0 else 0,
        "Std":      0,
        "Tot size": total_bytes,
        "IAT":      age / total_pkts if total_pkts > 0 else 0,
        "Number":   total_pkts,
        "Magnitue": np.sqrt(pkts_toserver**2 + pkts_toclient**2),
        "Radius":   abs(pkts_toserver - pkts_toclient) / 2,
        "Covariance": bytes_toserver * bytes_toclient,
        "Variance": 0,
        "Weight":   total_pkts,
    }

    row = {col: mapping.get(col, 0) for col in feature_cols}
    return pd.DataFrame([row])


def predict_flow(flow: dict) -> dict:
    bundle = _load_bundle()
    clf      = bundle["model"]
    le       = bundle["label_encoder"]
    features = bundle["features"]

    X = flow_to_features(flow, features).values  # .values → numpy array
    pred  = clf.predict(X)[0]
    proba = clf.predict_proba(X)[0]

    return {
        "class":      le.inverse_transform([pred])[0],
        "confidence": round(float(proba.max()), 4),
        "scores":     {cls: round(float(p), 4) for cls, p in zip(le.classes_, proba)},
    }


def predict_batch(flows: list[dict]) -> list[dict]:
    if not flows:
        return []

    bundle = _load_bundle()
    clf      = bundle["model"]
    le       = bundle["label_encoder"]
    features = bundle["features"]

    rows = [flow_to_features(f, features) for f in flows]
    X = pd.concat(rows, ignore_index=True).values  # .values → numpy array

    preds  = clf.predict(X)
    probas = clf.predict_proba(X)

    results = []
    for pred, proba in zip(preds, probas):
        results.append({
            "class":      le.inverse_transform([pred])[0],
            "confidence": round(float(proba.max()), 4),
            "scores":     {cls: round(float(p), 4) for cls, p in zip(le.classes_, proba)},
        })
    return results
