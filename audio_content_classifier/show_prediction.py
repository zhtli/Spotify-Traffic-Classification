#!/usr/bin/env python3
import csv
import os
import sys
import json

PRED_FILE = "predictions.csv"
CONFIG_FILE = "capture_config.json"

def detect_delimiter(path):
    with open(path, "r", encoding="utf-8") as f:
        line = f.readline()
    return "\t" if "\t" in line else ","

def load_song_map():
    if not os.path.exists(CONFIG_FILE):
        return {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            config = json.load(f)
        return config.get("song_map", {}) or {}
    except Exception:
        return {}

def pretty(label: str, song_map: dict) -> str:
    label = (label or "").strip()
    # a veces viene como track_<ID> o episode_<ID>
    label_clean = label.replace("track_", "").replace("episode_", "")
    return song_map.get(label_clean, label)

def main():
    pred_path = sys.argv[1] if len(sys.argv) > 1 else PRED_FILE

    if not os.path.exists(pred_path):
        print(f"[!] File not found: {pred_path}")
        sys.exit(1)

    song_map = load_song_map()
    delim = detect_delimiter(pred_path)

    with open(pred_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter=delim)
        rows = list(reader)

    if not rows:
        print("[!] predictions.csv is empty.")
        sys.exit(1)

    last = rows[-1]
    pcap = last.get("pcap", "").strip()
    pred = last.get("predicted_label", "").strip()

    print("\n" + "=" * 60)
    print("[✓] REAL-TIME PREDICTION")
    print("=" * 60)
    print(f"[i] PCAP: {pcap}")
    print(f"[→] Predicted ID: {pred}")
    print(f"[→] Song: {pretty(pred, song_map)}")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    main()
