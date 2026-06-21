"""Offline pcap analysis orchestration.

Neither engine touches a live interface. Suricata reads the pcap with -r,
Zeek reads it with -r. Output is written under <job_dir>/{suricata,zeek}/ and
a combined summary.json is produced for the web UI.
"""
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from app.parsers import parse_suricata, parse_zeek

APP_ROOT = Path(__file__).resolve().parent.parent  # /opt/app
ZEEK_LOCAL = APP_ROOT / "zeek" / "local.zeek"
RUN_TIMEOUT = 3600  # seconds, per engine


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _patch_status(job_dir: Path, **fields) -> None:
    """Merge fields into status.json on disk (the cross-request source of truth)."""
    sp = job_dir / "status.json"
    data = {}
    if sp.exists():
        try:
            data = json.loads(sp.read_text())
        except Exception:
            data = {}
    data.update(fields)
    sp.write_text(json.dumps(data, indent=2))


def _run(cmd, cwd=None) -> dict:
    """Run a subprocess, capture result, never raise on non-zero exit."""
    started = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=RUN_TIMEOUT,
        )
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout[-4000:],
            "stderr": proc.stderr[-4000:],
            "seconds": round(time.time() - started, 1),
        }
    except subprocess.TimeoutExpired:
        return {"returncode": -1, "stdout": "", "stderr": "timed out", "seconds": RUN_TIMEOUT}
    except FileNotFoundError as exc:
        return {"returncode": -1, "stdout": "", "stderr": str(exc), "seconds": 0}


def analyze_pcap(job_id: str, pcap_path: str, job_dir_str: str) -> None:
    """Background entry point. Drives both engines, then parses results."""
    job_dir = Path(job_dir_str)
    pcap = Path(pcap_path)
    suri_dir = job_dir / "suricata"
    zeek_dir = job_dir / "zeek"
    suri_dir.mkdir(parents=True, exist_ok=True)
    zeek_dir.mkdir(parents=True, exist_ok=True)

    started = time.time()
    _patch_status(job_dir, state="running", phase="suricata", started=_now())

    # --- Suricata -----------------------------------------------------------
    # -k none : skip checksum validation (offline / virtual-iface captures
    #           frequently carry bad checksums and would be dropped silently).
    suri_run = _run(
        ["suricata", "-r", str(pcap), "-l", str(suri_dir), "-k", "none"],
    )
    _patch_status(job_dir, phase="zeek", suricata_run=suri_run)

    # --- Zeek ---------------------------------------------------------------
    # -C : ignore checksum errors. Logs land in cwd, so cwd = zeek output dir.
    zeek_run = _run(
        ["zeek", "-C", "-r", str(pcap), str(ZEEK_LOCAL)],
        cwd=zeek_dir,
    )
    _patch_status(job_dir, phase="parsing", zeek_run=zeek_run)

    # --- Parse both into a combined summary --------------------------------
    try:
        summary = {
            "suricata": parse_suricata(suri_dir),
            "zeek": parse_zeek(zeek_dir),
        }
        (job_dir / "summary.json").write_text(json.dumps(summary, indent=2))

        suri_alerts = summary["suricata"].get("alerts_total", 0)
        zeek_conns = summary["zeek"].get("conn", {}).get("total", 0)

        _patch_status(
            job_dir,
            state="done",
            phase="done",
            finished=_now(),
            duration=round(time.time() - started, 1),
            alerts_total=suri_alerts,
            conn_total=zeek_conns,
            error=None,
        )
    except Exception as exc:  # parsing should be resilient, but never hang the job
        _patch_status(
            job_dir,
            state="error",
            phase="parsing",
            finished=_now(),
            error=f"{type(exc).__name__}: {exc}",
        )
