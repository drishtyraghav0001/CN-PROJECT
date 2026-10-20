
import json
from pathlib import Path
import pandas as pd


def load_network_data(file_path):
    path = Path(file_path)

    if path.suffix.lower() == ".csv":
        df = pd.read_csv(path)

    elif path.suffix.lower() == ".json":
        with open(path, "r", encoding="utf-8") as file:
            df = pd.DataFrame(json.load(file))

    else:
        raise ValueError("Only CSV and JSON files are supported.")

    df.columns = df.columns.str.strip().str.lower()

    required = {"protocol", "packets"}
    if not required.issubset(df.columns):
        raise ValueError("Required columns: Protocol and Packets")

    df["protocol"] = df["protocol"].astype(str).str.strip()
    df["packets"] = pd.to_numeric(df["packets"], errors="coerce")

    df = df.dropna(subset=["protocol", "packets"])
    df = df[df["protocol"] != ""]

    if (df["packets"] < 0).any():
        raise ValueError("Packet counts cannot be negative.")

    return df.reset_index(drop=True)
