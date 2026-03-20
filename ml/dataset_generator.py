import pandas as pd
import numpy as np
import os
import sys

# ensure src.types is available
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from src.types import AppType

COLUMNS = [
    "duration", "packets", "bytes", "avg_size", "std_size", "min_size", "max_size",
    "bps", "pps", "syn_ct", "ack_ct", "fin_ct", "dst_port", "src_port", "has_tls", "entropy", "label"
]

def generate_noise(val, noise=0.1):
    return val * np.random.uniform(1 - noise, 1 + noise)

def generate_int_noise(val, noise=0.1):
    return int(max(0, generate_noise(val, noise)))

def generate_samples(base_profile, label, count=1000):
    samples = []
    for _ in range(count):
        # 0: duration, 1: packets, 2: bytes, 3: avg_size, 4: std_size, 5: min_size, 6: max_size
        # 7: bps, 8: pps, 9: syn_ct, 10: ack_ct, 11: fin_ct, 12: dst_port, 13: src_port, 14: has_tls, 15: entropy
        s = []
        for i, val in enumerate(base_profile):
            if i in [12, 14]: # Port and TLS flag should be constant usually
                s.append(val)
            elif i == 13:
                s.append(np.random.randint(1024, 65535))
            elif i == 15: # Entropy bounded
                s.append(min(8.0, generate_noise(val, 0.05)))
            else:
                s.append(generate_noise(val, 0.15)) # 15% noise
        s.append(label)
        samples.append(s)
    return samples

def main():
    np.random.seed(42)
    # Profiles mapping to the requested criteria
    profiles = {
        AppType.YOUTUBE.value:  [300.0, 5000, 6000000, 1200, 200, 60, 1460, 20000, 16.6, 2, 4500, 2, 443, 0, 1, 7.5],
        AppType.NETFLIX.value:  [600.0, 10000, 13000000, 1300, 100, 60, 1460, 21666, 16.6, 2, 9000, 2, 443, 0, 1, 7.8],
        AppType.FACEBOOK.value: [120.0, 800, 500000,    625,  400, 60, 1460,  4166,  6.6,  4,  700, 2, 443, 0, 1, 7.0],
        AppType.TIKTOK.value:   [45.0,  1500, 1800000,  1200, 300, 60, 1460, 40000, 33.3, 2, 1300, 2, 443, 0, 1, 7.6],
        AppType.GITHUB.value:   [15.0,  100,  40000,    400,  400, 60, 1460,  2666,  6.6,  2,   90, 2,  443, 0, 1, 6.0],
        AppType.DNS.value:      [0.05,  2,    160,      80,   10,  70, 90,   3200,  40.0, 0,    0, 0,   53, 0, 0, 5.0],
        AppType.HTTP.value:     [5.0,   50,   30000,    600,  300, 60, 1460,  6000, 10.0, 2,   45, 2,   80, 0, 0, 4.0],
        AppType.GAMING.value:   [3600.0,72000,28800000, 400,  50,  200, 600,  8000, 20.0, 0,    0, 0, 27015, 0, 0, 7.9],
        AppType.ZOOM.value:     [1800.0,90000,45000000, 500,  80,  100, 900, 25000, 50.0, 0,    0, 0, 8801,  0, 0, 7.9],
        AppType.UNKNOWN.value:  [60.0,  300,  200000,   666,  200, 60, 1460,  3333,  5.0, 2,  250, 2, 8080,  0, 0, 6.5]
    }

    all_samples = []
    for cls_name, profile in profiles.items():
        all_samples.extend(generate_samples(profile, cls_name, 1000))

    df = pd.DataFrame(all_samples, columns=COLUMNS)
    out_path = os.path.join(os.path.dirname(__file__), "training_data.csv")
    df.to_csv(out_path, index=False)
    print(f"Generated {len(df)} samples evenly across {len(profiles)} classes -> {out_path}")

if __name__ == "__main__":
    main()
