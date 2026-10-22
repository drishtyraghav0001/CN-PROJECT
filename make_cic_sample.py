import glob

import numpy as np
import pandas as pd

parts = []
for f in sorted(glob.glob("data/cic/*.csv")):
    df = pd.read_csv(f, encoding="latin-1", low_memory=False)
    df.columns = df.columns.str.strip()
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    benign = df[df["Label"] == "BENIGN"]
    attacks = df[df["Label"] != "BENIGN"]
    attacks = attacks.groupby("Label", group_keys=False).apply(
        lambda g: g.sample(min(len(g), 4000), random_state=42)
    )
    parts.append(benign.sample(min(len(benign), 20000), random_state=42))
    parts.append(attacks)
    print(f.split("\\")[-1][:40], "benign:", len(benign), "attacks:", len(attacks))

out = pd.concat(parts, ignore_index=True)
print(out["Label"].value_counts())
print("total rows:", len(out))
out.to_csv("cic_sample.csv", index=False)