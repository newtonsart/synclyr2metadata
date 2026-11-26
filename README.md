# synclyr2metadata

A lightweight command-line tool that reads local `.lrc` files or automatically downloads synchronized lyrics from [LRCLIB](https://lrclib.net) and **embeds them directly into your audio files' metadata**.

Perfect for use with **Lidarr**, **Navidrome**, **Jellyfin**, **Plex**, or any music player that reads embedded lyrics.

## What does it do?

1. Scans your audio files and reads their metadata (Artist, Title, Album, Duration).
2. Looks for a local `.lrc` sidecar file with the same name. If found, it embeds it directly to save time.
3. If no local file exists, searches for synchronized lyrics on LRCLIB. Falls back to plain lyrics when synced aren't available.
4. Embeds the lyrics permanently into the file's `LYRICS` tag — no separate `.lrc` files needed.

Supports **FLAC**, **MP3**, **OGG**, **M4A/AAC**, **OPUS**, and more (powered by [TagLib](https://taglib.org/)).

---

## LRCLIB authentication (optional)

Anonymous requests work without configuration. For large libraries, register a server-side application in the [LRCLIB developer portal](https://lrclib.net/developers) and obtain an App ID and API key.

### Native installation / Lidarr service

Create the credentials file outside the repository:

```bash
sudo install -d -m 700 /etc/synclyr2metadata
sudo touch /etc/synclyr2metadata/credentials
sudo chmod 600 /etc/synclyr2metadata/credentials
sudoedit /etc/synclyr2metadata/credentials
```

Add the following lines, replacing the placeholders with your own credentials:

```dotenv
LRCLIB_APP_ID=YOUR_APP_ID
LRCLIB_API_KEY=YOUR_API_KEY
```

The credentials file and its directory must be accessible to the user running synclyr2metadata (including the Lidarr service user). Keep the file private and adjust ownership if Lidarr runs as a dedicated user.

### Environment variables / Docker

The same variables can be supplied through the process environment instead. Environment variables override the corresponding values in the credentials file. For Docker, pass them securely to the Lidarr container, or mount the credentials file read-only at `/etc/synclyr2metadata/credentials`.

Never commit real credentials or expose them in logs. The program sends them only to the LRCLIB API over HTTPS.

### Rate limiting

- With an API key: sequential HTTP requests with a 250 ms delay after each response.
- Without an API key: a 1 second delay after each response.
- HTTP 429: global cooldown across worker threads, respecting `Retry-After` and using bounded exponential backoff with jitter. If the limit persists, remaining requests are deferred until another run.
- Existing embedded lyrics are skipped before making API requests unless `--force` is supplied. Temporary API failures are reported as errors, not missing lyrics.

Authenticated mode prints `LRCLIB: authenticated mode (250ms delay)` at startup.

---

## 🎵 Lidarr Integration

The native integration handles AlbumDownload (release imports and upgrades) using the supplied track paths, and TrackRetag using the single retagged file. It skips existing lyrics and serializes Lidarr event executions with an adjacent lock file. Ensure the service user can write that lock file and the logs. TrackRetag requires Lidarr to write audio tags; it does not guarantee a notification for every manual import.

For a non-root service account, grant a dedicated group read access to the credentials without making them world-readable. For example, on a native Linux installation, replace `SERVICE_USER` with the account running the script:

```bash
sudo groupadd --system lrclib
sudo usermod -aG lrclib SERVICE_USER
sudo chgrp lrclib /etc/synclyr2metadata /etc/synclyr2metadata/credentials
sudo chmod 750 /etc/synclyr2metadata
sudo chmod 640 /etc/synclyr2metadata/credentials
```

If the group already exists, skip its creation. Restart the affected service so it receives the supplementary group. The account also needs write access to audio metadata and the script's lock and log files. Never grant world-readable permissions to the credentials.


Auto-sync lyrics every time Lidarr imports a new album.  
**Only one file to deploy** — the binary is fully static with zero runtime dependencies.

---

### 🐳 Option A: Lidarr running in Docker

> Most common setup (Hotio or LinuxServer images on Alpine Linux).

#### 1. Build

```bash
sudo apt install build-essential docker.io   # host prerequisites
git clone https://github.com/newtonsart/synclyr2metadata.git
cd synclyr2metadata
make
```

> Builds a **static binary** (~8MB) inside an Alpine Docker container. No modifications to your `docker-compose.yml` needed.

#### 2. Deploy

Copy the binary into your Lidarr container's config volume:

```bash
cp synclyr2metadata /path/to/lidarr/config/scripts/
```

> Replace `/path/to/lidarr/config` with your actual Lidarr config mount (e.g. `./config` or `/opt/media-stack/config/lidarr`).

#### 3. Enable the Custom Script

1. Open Lidarr UI → **Settings → Connect → + → Custom Script**.
2. Configure:
   - **Name**: `Sync Lyrics`
   - **On Release Import**: ✓
   - **On Upgrade**: ✓
   - **On Track Retag**: ✓
   - **Path**: `/config/scripts/synclyr2metadata`
3. Click **Test**, then **Save**.

Logs are automatically generated in the same folder:
- `/config/scripts/synclyr2metadata.log` (General execution log)
- `/config/scripts/synclyr2metadata_plain.log` (Tracks that only got plain/unsynced lyrics)
- `/config/scripts/synclyr2metadata_missing.log` (Tracks that couldn't be found on LRCLIB)---

### 💻 Option B: Lidarr installed natively

> For bare-metal or systemd-based Lidarr installations.

#### 1. Install dependencies and build

```bash
# Debian / Ubuntu
sudo apt install build-essential libcurl4-openssl-dev libtag1-dev

# Arch
sudo pacman -S base-devel curl taglib

# Then build
git clone https://github.com/newtonsart/synclyr2metadata.git
cd synclyr2metadata
make native
```

#### 2. Deploy

```bash
sudo make install      # installs to /usr/local/bin
```

Or copy manually to a directory Lidarr can access:
```bash
cp synclyr2metadata /path/to/lidarr/scripts/
```

#### 3. Enable the Custom Script

1. Open Lidarr UI → **Settings → Connect → + → Custom Script**.
2. Configure:
   - **Name**: `Sync Lyrics`
   - **On Release Import**: ✓
   - **On Upgrade**: ✓
   - **On Track Retag**: ✓
   - **Path**: `/path/to/synclyr2metadata`
3. Click **Test**, then **Save**.

Logs are automatically generated in the same folder as the binary:
- `synclyr2metadata.log`
- `synclyr2metadata_plain.log`
- `synclyr2metadata_missing.log`

---

## 🛠 Manual CLI Usage

You can also use `synclyr2metadata` directly from the command line:

```bash
# Sync a flat folder of audio files
./synclyr2metadata --folder "/path/to/downloaded_tracks"

# Sync a single album
./synclyr2metadata --album "/path/to/Artist/Album (2024)"

# Sync all albums from an artist
./synclyr2metadata --artist "/path/to/Artist" --threads 8

# Sync your entire library (Artist/Album structure)
./synclyr2metadata --library "/path/to/music" --threads 4

# Export paths of tracks that only got plain lyrics and tracks with missing lyrics
./synclyr2metadata --library "/path/to/music" --out-plain ./plain.txt --out-missing ./missing.txt

# Sync a directory and delete original .lrc sidecar files after embedding them
./synclyr2metadata --album "/path/to/downloaded_album" --clean-lrc
```

### Options

| Option | Description |
|---|---|
| `--folder PATH` | Sync audio files directly in one folder, without requiring Artist/Album layout |
| `--album PATH` | Sync lyrics for a single album directory |
| `--artist PATH` | Sync all albums under an artist directory |
| `--library PATH` | Sync entire library (artist/album structure) |
| `--out-plain FILE` | Write paths of tracks falling back to unsynced lyrics to file |
| `--out-missing FILE` | Write paths of tracks not found on LRCLIB to file |
| `--force` | Overwrite existing embedded lyrics |
| `--clean-lrc` | Delete local `.lrc` file after successfully embedding it |
| `--threads N` | Parallel download threads (default: 4, max: 16) |
| `--help` | Show help |

### Troubleshooting native builds

If `make native` fails with `fatal error: taglib/tag_c.h: No such file or directory`,
install the native development dependencies first:

```bash
# Debian / Ubuntu
sudo apt install build-essential libcurl4-openssl-dev libtag1-dev

# Arch
sudo pacman -S base-devel curl taglib
```

The default `make` target builds in Docker and vendors/builds TagLib inside the
container, so these packages are only needed for `make native`.

### Example Output

```
═══ MF DOOM ═══

▶ MM.FOOD (2004) (26 tracks)
  [ 1/26] Beef Rapp                                ✓ synced
  [ 2/26] Hoe Cakes                                ✓ plain
  [ 3/26] Potholderz                               ⊘ already has lyrics
  [ 4/26] Unreleased Track                         ✗ not found

──────────────────────────────────────────────
  ✓ Synced:     22
  ✓ Plain:      1
  ⊘ Skipped:    1
  ✗ Not found:  2
──────────────────────────────────────────────
```

---

## License

[GPLv3](LICENSE)

## Credits

- Lyrics by [LRCLIB](https://lrclib.net)
- Built with [libcurl](https://curl.se/), [TagLib](https://taglib.org/), and [cJSON](https://github.com/DaveGamble/cJSON)
