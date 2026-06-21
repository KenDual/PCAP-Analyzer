"""Headless analysis — same engines, no browser.

Usage (inside the container):
    docker compose run --rm --entrypoint python3 tandem \
        -m app.cli /data/uploads/capture.pcap

Writes suricata/ + zeek/ output and a summary.json next to a results dir,
and prints a short text summary to stdout.
"""
import json
import shutil
import sys
import uuid
from pathlib import Path

from app.analyzer import analyze_pcap
from app.parsers import load_summary


def main(argv):
    if len(argv) < 2:
        print("usage: python3 -m app.cli <path-to-pcap> [output-dir]", file=sys.stderr)
        return 2

    pcap = Path(argv[1]).resolve()
    if not pcap.is_file():
        print(f"error: no such file: {pcap}", file=sys.stderr)
        return 1

    out_root = Path(argv[2]) if len(argv) > 2 else Path("/data/results")
    # Overwrite mode: keep only the newest scan.
    if out_root.exists():
        for d in out_root.iterdir():
            if d.is_dir():
                shutil.rmtree(d, ignore_errors=True)
    job_id = uuid.uuid4().hex[:12]
    job_dir = out_root / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    (job_dir / "status.json").write_text(json.dumps({
        "id": job_id, "filename": pcap.name, "state": "queued", "phase": "queued",
    }))

    print(f"[*] analyzing {pcap.name}  ->  {job_dir}")
    analyze_pcap(job_id, str(pcap), str(job_dir))  # runs synchronously

    summary = load_summary(job_dir)
    if not summary:
        print("[!] analysis produced no summary (see status.json)", file=sys.stderr)
        return 1

    s, z = summary["suricata"], summary["zeek"]
    print(f"[+] suricata alerts : {s.get('alerts_total', 0)}")
    print(f"[+] zeek connections: {z.get('conn', {}).get('total', 0)}")
    print(f"[+] dns queries     : {z.get('dns', {}).get('total', 0)}")
    print(f"[+] files seen      : {z.get('files', {}).get('total', 0)}")
    print(f"[+] output written  : {job_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
