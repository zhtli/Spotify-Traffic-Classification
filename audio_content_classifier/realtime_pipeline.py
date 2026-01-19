#!/usr/bin/env python3
import subprocess
import time
import sys

def run_step(description, command):
    print("\n" + "=" * 60)
    print(f"[+] {description}")
    print("=" * 60)

    result = subprocess.run(command, shell=True)

    if result.returncode != 0:
        print(f"[!] Error during step: {description}")
        sys.exit(1)

    print(f"[✓] Finished: {description}")

# =========================
# PIPELINE
# =========================

if __name__ == "__main__":

    start = time.time()

    #1. capture traffic
    run_step(
        "Capturing Spotify traffic",
        "sudo ./venv/bin/python capture_single_spotify_flow.py"
    )

    #2. extract features
    run_step(
        "Extracting features",
        "sudo ./venv/bin/python extract_features.py"
    )

    #3. predict content
    run_step(
        "Running prediction",
        "sudo ./venv/bin/python predict.py"
    )

    run_step(
	"Showing final predicion",
	"sudo ./venv/bin/python show_prediction.py predictions.csv"
    )
    end = time.time()

    print("\n" + "=" * 60)
    print("[✓] REAL-TIME PIPELINE COMPLETED")
    print(f"[i] Total time: {end - start:.2f} seconds")
    print("=" * 60)
