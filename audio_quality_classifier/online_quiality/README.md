# Spotify Audio Quality Classification

This project provides two approaches for Spotify audio quality classification:
- Machine Learning–based method
- Traffic-based analysis method

This README describes the requirements and usage of the traffic-based approach.

---

## Python Version

Python 3.9+ recommended

---

## System requirements

- Linux system
- Root privileges (required for packet capture)
- Active internet connection
- Spotify Web Player or Spotify Desktop

---

## Dependencies

The traffic-based method requires the following Python library:

- `scapy`

Install it using:

```bash
sudo apt install python3-scapy

Create and activate a virtual environment inside this folder:

```bash
cd online_quality
python3 -m venv venv
source venv/bin/activate
pip install scapy

Detect Spotify-related IPs and store them persistently.
