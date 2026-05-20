from feature_bridge import _load_bundle, flow_to_features, predict_batch
import pandas as pd

# Test với scale khớp data thực
fake_flows = [
    {   # DDoS: flow_duration ngắn, Rate cao, Header_Length nhỏ
        "proto": "TCP", "dest_port": 80, "src_port": 54321,
        "pkts_toserver": 9, "pkts_toclient": 0,
        "bytes_toserver": 9493, "bytes_toclient": 0,
        "age": 0.34
    },
    {   # BENIGN: flow_duration dài, Rate thấp
        "proto": "TCP", "dest_port": 443, "src_port": 12345,
        "pkts_toserver": 5, "pkts_toclient": 5,
        "bytes_toserver": 1000, "bytes_toclient": 977,
        "age": 38.8
    },
    {   # BruteForce: Rate thấp ~100, Header_Length lớn
        "proto": "TCP", "dest_port": 22, "src_port": 44444,
        "pkts_toserver": 9, "pkts_toclient": 0,
        "bytes_toserver": 100, "bytes_toclient": 0,
        "age": 210.0
    },
    {   # Mirai: Header_Length rất lớn ~534K
        "proto": "UDP", "dest_port": 23, "src_port": 55555,
        "pkts_toserver": 9, "pkts_toclient": 0,
        "bytes_toserver": 7553, "bytes_toclient": 0,
        "age": 2.56
    },
    {   # DoS: Rate cao ~11387, flow_duration ~1.8
        "proto": "TCP", "dest_port": 80, "src_port": 33333,
        "pkts_toserver": 9, "pkts_toclient": 0,
        "bytes_toserver": 11387, "bytes_toclient": 0,
        "age": 1.85
    },
]

results = predict_batch(fake_flows)
labels = ["DDoS", "BENIGN", "BruteForce", "Mirai", "DoS"]
for expected, flow, res in zip(labels, fake_flows, results):
    print(f"Expected={expected:12s} → Got={res['class']:12s} ({res['confidence']*100:.1f}%) port={flow['dest_port']}")