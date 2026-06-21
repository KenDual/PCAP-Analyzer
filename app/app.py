"""TANDEM — offline pcap triage web layer.

Single-process Flask app served by gunicorn. Uploads land on a mounted volume,
analysis runs in a background thread, and per-job status.json on disk is the
source of truth so a restart never loses a completed job.
"""
import json
import os
import shutil
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import (
    Flask, abort, jsonify, redirect, render_template,
    request, send_file, url_for,
)
from werkzeug.utils import secure_filename

from app.analyzer import analyze_pcap
from app.parsers import load_summary

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
UPLOAD_DIR = DATA_DIR / "uploads"
RESULTS_DIR = DATA_DIR / "results"
MAX_MB = int(os.environ.get("MAX_UPLOAD_MB", "2048"))
ALLOWED_EXT = {".pcap", ".pcapng", ".cap"}

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_MB * 1024 * 1024


# --- helpers ---------------------------------------------------------------
def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def job_dir(job_id: str) -> Path:
    return RESULTS_DIR / job_id


def read_status(job_id: str):
    p = job_dir(job_id) / "status.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def purge_results():
    """Overwrite mode: keep only the newest scan by removing all prior job dirs."""
    if RESULTS_DIR.exists():
        for d in RESULTS_DIR.iterdir():
            if d.is_dir():
                shutil.rmtree(d, ignore_errors=True)


def list_jobs():
    jobs = []
    if RESULTS_DIR.exists():
        for d in RESULTS_DIR.iterdir():
            if d.is_dir():
                s = read_status(d.name)
                if s:
                    jobs.append(s)
    jobs.sort(key=lambda s: s.get("created", ""), reverse=True)
    return jobs


def _human_size(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "-"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


app.jinja_env.filters["humansize"] = _human_size


# --- routes ----------------------------------------------------------------
@app.get("/")
def index():
    return render_template("index.html", jobs=list_jobs(), max_mb=MAX_MB)


@app.post("/upload")
def upload():
    f = request.files.get("pcap")
    if not f or f.filename == "":
        return render_template("index.html", jobs=list_jobs(), max_mb=MAX_MB,
                               error="No file selected."), 400

    name = secure_filename(f.filename) or "capture.pcap"
    ext = Path(name).suffix.lower()
    if ext not in ALLOWED_EXT:
        return render_template(
            "index.html", jobs=list_jobs(), max_mb=MAX_MB,
            error=f"Unsupported file type '{ext}'. Use .pcap, .pcapng or .cap.",
        ), 400

    # Overwrite mode: drop previous results so only this scan remains.
    purge_results()

    job_id = uuid.uuid4().hex[:12]
    jd = job_dir(job_id)
    jd.mkdir(parents=True, exist_ok=True)
    pcap_path = jd / f"input{ext}"
    f.save(pcap_path)

    status = {
        "id": job_id,
        "filename": name,
        "size": pcap_path.stat().st_size,
        "state": "queued",
        "phase": "queued",
        "created": _now(),
        "error": None,
    }
    (jd / "status.json").write_text(json.dumps(status, indent=2))

    threading.Thread(
        target=analyze_pcap,
        args=(job_id, str(pcap_path), str(jd)),
        daemon=True,
    ).start()

    return redirect(url_for("job", job_id=job_id))


@app.get("/job/<job_id>")
def job(job_id):
    s = read_status(job_id)
    if not s:
        abort(404)
    summary = load_summary(job_dir(job_id)) if s.get("state") == "done" else None
    raw_files = {"suricata": [], "zeek": []}
    for engine in raw_files:
        d = job_dir(job_id) / engine
        if d.exists():
            raw_files[engine] = sorted(
                p.name for p in d.iterdir() if p.is_file()
            )
    return render_template("results.html", job=s, summary=summary, raw_files=raw_files)


@app.get("/job/<job_id>/status.json")
def job_status(job_id):
    s = read_status(job_id)
    if not s:
        abort(404)
    return jsonify(s)


@app.get("/job/<job_id>/raw/<engine>/<path:fname>")
def raw(job_id, engine, fname):
    if engine not in ("suricata", "zeek"):
        abort(404)
    base = (job_dir(job_id) / engine).resolve()
    target = (base / fname).resolve()
    # path-traversal guard: target must live under base
    if base != target and base not in target.parents:
        abort(404)
    if not target.is_file():
        abort(404)
    return send_file(target, as_attachment=True, download_name=fname)


@app.post("/job/<job_id>/delete")
def delete(job_id):
    jd = job_dir(job_id)
    if jd.exists() and jd.resolve().parent == RESULTS_DIR.resolve():
        shutil.rmtree(jd, ignore_errors=True)
    return redirect(url_for("index"))


@app.errorhandler(413)
def too_large(_e):
    return render_template(
        "index.html", jobs=list_jobs(), max_mb=MAX_MB,
        error=f"That file exceeds the {MAX_MB} MB limit.",
    ), 413


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("FLASK_PORT", "8080")))
