#!/usr/bin/env python3
import time
import os
from scapy.all import sniff, wrpcap
import spotipy
from spotipy.oauth2 import SpotifyOAuth
from dotenv import load_dotenv
import json
import re

load_dotenv()

#credentials
SPOTIFY_CLIENT_ID = os.getenv("SPOTIFY_CLIENT_ID")
SPOTIFY_CLIENT_SECRET = os.getenv("SPOTIFY_CLIENT_SECRET")
SPOTIFY_REDIRECT_URI = os.getenv("SPOTIFY_REDIRECT_URI")

CONFIG_FILE = "capture_config.json"

def extract_id_from_uri(uri: str) -> str:
    m = re.search(r"spotify:(track|episode):([A-Za-z0-9]+)", uri)
    if not m:
        return ""
    return m.group(2)


def uri_type(uri: str) -> str:
    if "spotify:episode:" in uri:
        return "episode"
    return "track"


class SpotifySingleCapture:
    def __init__(self, interface, pcap_save_dir, audio_quality, capture_duration):
        self.interface = interface
        self.pcap_save_dir = pcap_save_dir
        self.audio_quality = audio_quality
        self.capture_duration = capture_duration
        self.spotify_client = None

        os.makedirs(self.pcap_save_dir, exist_ok=True)

    def setup_spotify_client(self):
        scope = "user-modify-playback-state user-read-playback-state"
        self.spotify_client = spotipy.Spotify(
            auth_manager=SpotifyOAuth(
                client_id=SPOTIFY_CLIENT_ID,
                client_secret=SPOTIFY_CLIENT_SECRET,
                redirect_uri=SPOTIFY_REDIRECT_URI,
                scope=scope
            )
        )

    def capture(self, song_uri):
        devices = self.spotify_client.devices()["devices"]
        if not devices:
            raise RuntimeError("No active Spotify device found")

        device_id = devices[0]["id"]
        self.spotify_client.start_playback(uris=[song_uri], device_id=device_id)

        print(f"[+] Capturing {self.capture_duration}s...")

        packets = sniff(
            iface=self.interface,
            timeout=self.capture_duration,
            store=True
        )

        ts = time.strftime("%d-%m-%Y-%H%M%S")

        sid = extract_id_from_uri(song_uri)
        kind = uri_type(song_uri)
        safe_name = f"spotify_{kind}_{sid}"

        out_file = f"{ts}_{safe_name}_{self.audio_quality}.pcap"
        out_path = os.path.join(self.pcap_save_dir, out_file)

        wrpcap(out_path, packets)

        print(f"[✓] Saved: {out_path}")



if __name__ == "__main__":
    if not os.path.exists(CONFIG_FILE):
        raise Exception(f"Config file '{CONFIG_FILE}' not found")

    with open(CONFIG_FILE) as f:
        config = json.load(f)

    song_map = config.get("song_map", {})  # ID -> nombre bonito

    print("\nChoose song to capture:")
    for i, uri in enumerate(config["song_uris"]):
        sid = extract_id_from_uri(uri)
        name = song_map.get(sid, sid)
        print(f"  {i+1}. {name}")

    idx = int(input("\nSelect (1..N): ").strip()) - 1
    song_uri = config["song_uris"][idx]

    quality = config["streaming_qualities"][3]

    input("\nPress Enter to start capture...")

    capturer = SpotifySingleCapture(
        interface=config["interface"],
        pcap_save_dir=config["pcap_save_dir"],
        audio_quality=quality,
        capture_duration=config["capture_duration"]
    )

    capturer.setup_spotify_client()
    capturer.capture(song_uri)
