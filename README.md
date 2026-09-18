# TANDEM — offline pcap triage

A self-contained Docker tool that runs **Suricata** and **Zeek** over a pcap you
upload, parses both engines into one triage view, and serves it through a
drop-a-file web UI. Neither engine ever touches a live interface — both read the
capture in offline mode (`suricata -r`, `zeek -r`) only. Everything stays inside
the container; nothing is installed on the host.

```
 upload .pcap────►Suricata (-r, signatures)───┐                             
                  Zeek   (-r, protocol logs)──┴─►parsed summary + raw logs  
                                                  └─► web UI / /data volume 
```

## Demo
<p align="center">
  <video src="media/pcap-final.mp4" width="100%" controls playsinline>
    Your browser does not support the video tag. <a href="media/pcap-final.mp4">Watch demo (MP4, 3.2 MB)</a>
  </video>
</p>

> Fallback: [▶ Watch demo video](media/pcap-final.mp4) — if the player doesn't load, open/download the MP4 directly.

## What you get per capture

- **Suricata**: alert totals, severity breakdown, top signatures, individual alerts (`eve.json`, `fast.log`).
- **Zeek**: connections, top talkers, services/protocols, DNS queries, HTTP hosts, TLS SNIs, **files with md5/sha1/sha256** (drop a hash into VirusTotal), notices, weird activity.
- **Raw logs** for both engines, downloadable, and also written to the `./data` volume on disk.

## Run it

```bash
docker compose build
```

Then reach it at `http://127.0.0.1:8080` — over Tailscale from your laptop/phone,
point your browser at `http://<tailscale-ip-or-name>:8080`. By default the port is
bound to `127.0.0.1`, so it is **not** exposed to your WAN/No-IP. Put a Caddy/nginx
reverse proxy in front if you want a subdomain.

### Headless (no browser)

```bash
docker compose run --rm --entrypoint python3 tandem -m app.cli /data/uploads/capture.pcap
```

## Configuration (env in `docker-compose.yml`)

| Variable          | Default            | Meaning                              |
|-------------------|--------------------|--------------------------------------|
| `MAX_UPLOAD_MB`   | `2048`             | reject pcaps larger than this        |
| `GUNICORN_TIMEOUT`| `3600`             | hard ceiling for one analysis run    |
| `TZ`              | `Asia/Ho_Chi_Minh` | timestamps                           |

## Notes & tuning

- **Rules**: ET Open is pulled at build time. Refresh later with
  `docker compose exec tandem suricata-update` then rebuild or restart.
- **Resources**: on the i5-4760 / 8 GB box, one pcap at a time is comfortable.
  Suricata loading full ET Open uses a few hundred MB; very large pcaps are
  CPU-bound, not RAM-bound. If you want it lighter, enable only the rule
  categories you care about via `suricata-update --enable-source`.
- **Zeek package**: if `apt install zeek` ever fails to resolve, switch the
  package name to `zeek-lts` in the Dockerfile.
- **Checksums**: `suricata -k none` and `zeek -C` are set because captures from
  virtual interfaces routinely carry bad checksums that would otherwise be
  dropped silently.

## Safety

The compose service runs `read_only: true`, `cap_drop: ALL`, and
`no-new-privileges`. The only writable path is the `/data` volume (plus a tmpfs
`/tmp`). This is a deliberately boxed-in analysis appliance, not a monitoring
sensor.
