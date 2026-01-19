# Data Capture Process
The script `spotify_packet_capture.py` captures packets from an interface and starts playback automatically in an active and authenticated device.

We use **spotipy** to automate the playback of spotify, and we use **scapy** to sniff all the packets from an interface.

## Configuration
In file `capture_config.json` you can configure:
- `song_uris`: The URIs of music or podcast you wanna play in spotify for a session of playback.
- `streaming_qualities`: The audio quality settings you want to keep track of. This does NOT change the quality setting automatically in Spotify, because there was not way of doing so through the API.
- `pcap_save_dir`: The directory where the pcap files will be saved.
- `interface` : The interface to capture the packets.
- `capture_duration` : The duration of each playback in `song_uri`.
- `num_sessions` : The number of sessions you want to play. Each session plays the entire `song_uris` list.

Other configurations are install dependencies of the project in the `requirements.txt` file, and set up the environment variables in `.env` file, an example can be found in the `.env.example` file.

## Instructions to run the script
To run the script you will need to run it as sudo/administrator and have spotify premium (The API features used require premium accounts).

After running the script with:
```bash
python spotify_packet_capture_generator.py
```
You will be prompted to select a quality, this is only to label the captures, it does not automatically change the setting in Spotify.

Just after, you will need to start a spotify session in the same device you are running the script, make sure this is the only app running to avoid noise. If you haven't authenticated, OAuth flow will be triggered, and you will need to authenticate with your Spotify account.