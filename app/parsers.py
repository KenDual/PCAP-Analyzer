"""Parse raw engine output into compact, UI-friendly summaries.

Everything here is defensive: files may be absent, lines may be malformed,
fields may be missing. Nothing in this module should ever raise on bad input.
"""
import json
from collections import Counter
from pathlib import Path

ALERT_CAP = 1000     # individual alerts shown/stored in summary (raw file has all)
REQUEST_CAP = 200    # http requests / files listed in summary


def _iter_json_lines(path: Path):
    """Yield parsed objects from a newline-delimited JSON file, skipping junk."""
    if not path.exists():
        return
    with path.open("r", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line[0] != "{":
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


# ---------------------------------------------------------------------------
# Suricata
# ---------------------------------------------------------------------------
def parse_suricata(suri_dir: Path) -> dict:
    eve = suri_dir / "eve.json"
    out = {
        "available": eve.exists(),
        "alerts_total": 0,
        "by_severity": {},
        "event_types": {},
        "signatures": [],
        "alerts": [],
        "alerts_truncated": False,
    }
    if not eve.exists():
        return out

    sigs = Counter()
    sev = Counter()
    etypes = Counter()
    sig_meta = {}
    alerts = []

    for ev in _iter_json_lines(eve):
        et = ev.get("event_type", "")
        etypes[et] += 1
        if et != "alert":
            continue
        a = ev.get("alert", {})
        signature = a.get("signature", "(unknown)")
        severity = a.get("severity", 0)
        category = a.get("category", "")
        sigs[signature] += 1
        sev[str(severity)] += 1
        sig_meta[signature] = {
            "category": category,
            "severity": severity,
            "sid": a.get("signature_id"),
        }
        if len(alerts) < ALERT_CAP:
            alerts.append({
                "ts": ev.get("timestamp", ""),
                "signature": signature,
                "category": category,
                "severity": severity,
                "src": f'{ev.get("src_ip", "")}:{ev.get("src_port", "")}',
                "dest": f'{ev.get("dest_ip", "")}:{ev.get("dest_port", "")}',
                "proto": ev.get("proto", ""),
            })

    total = sum(sigs.values())
    out["alerts_total"] = total
    out["by_severity"] = {k: sev[k] for k in sorted(sev)}
    out["event_types"] = dict(etypes.most_common())
    out["signatures"] = [
        {"signature": s, "count": c, **sig_meta.get(s, {})}
        for s, c in sigs.most_common(100)
    ]
    out["alerts"] = alerts
    out["alerts_truncated"] = total > len(alerts)
    return out


# ---------------------------------------------------------------------------
# Zeek
# ---------------------------------------------------------------------------
def _log(zeek_dir: Path, name: str) -> Path:
    return zeek_dir / name


def parse_zeek(zeek_dir: Path) -> dict:
    out = {"available": False}
    out["available"] = any(
        _log(zeek_dir, n).exists() for n in ("conn.log", "dns.log", "http.log")
    )

    # conn.log -----------------------------------------------------------
    services, protos, talkers = Counter(), Counter(), Counter()
    conn_total = 0
    bytes_total = 0
    for r in _iter_json_lines(_log(zeek_dir, "conn.log")):
        conn_total += 1
        services[r.get("service") or "-"] += 1
        protos[r.get("proto") or "-"] += 1
        talkers[f'{r.get("id.orig_h", "?")} \u2192 {r.get("id.resp_h", "?")}'] += 1
        try:
            bytes_total += int(r.get("orig_bytes") or 0) + int(r.get("resp_bytes") or 0)
        except (TypeError, ValueError):
            pass
    out["conn"] = {
        "total": conn_total,
        "bytes_total": bytes_total,
        "services": dict(services.most_common(15)),
        "protos": dict(protos.most_common()),
        "top_talkers": [{"pair": k, "count": v} for k, v in talkers.most_common(20)],
    }

    # dns.log ------------------------------------------------------------
    dns = Counter()
    for r in _iter_json_lines(_log(zeek_dir, "dns.log")):
        q = r.get("query")
        if q:
            dns[q] += 1
    out["dns"] = {
        "total": sum(dns.values()),
        "top": [{"q": k, "count": v} for k, v in dns.most_common(25)],
    }

    # http.log -----------------------------------------------------------
    hosts, methods, requests = Counter(), Counter(), []
    http_total = 0
    for r in _iter_json_lines(_log(zeek_dir, "http.log")):
        http_total += 1
        if r.get("host"):
            hosts[r["host"]] += 1
        if r.get("method"):
            methods[r["method"]] += 1
        if len(requests) < REQUEST_CAP:
            requests.append({
                "host": r.get("host", ""),
                "uri": r.get("uri", ""),
                "method": r.get("method", ""),
                "status": r.get("status_code", ""),
            })
    out["http"] = {
        "total": http_total,
        "methods": dict(methods.most_common()),
        "top_hosts": [{"host": k, "count": v} for k, v in hosts.most_common(20)],
        "requests": requests,
    }

    # ssl.log ------------------------------------------------------------
    snis = Counter()
    ssl_total = 0
    for r in _iter_json_lines(_log(zeek_dir, "ssl.log")):
        ssl_total += 1
        if r.get("server_name"):
            snis[r["server_name"]] += 1
    out["ssl"] = {
        "total": ssl_total,
        "top_sni": [{"name": k, "count": v} for k, v in snis.most_common(20)],
    }

    # files.log (with hashes from hash-all-files) ------------------------
    ftypes, files = Counter(), []
    files_total = 0
    for r in _iter_json_lines(_log(zeek_dir, "files.log")):
        files_total += 1
        ftypes[r.get("mime_type") or "-"] += 1
        if len(files) < REQUEST_CAP:
            tx = r.get("tx_hosts", "")
            if isinstance(tx, list):
                tx = ", ".join(tx)
            files.append({
                "mime": r.get("mime_type", ""),
                "md5": r.get("md5", ""),
                "sha256": r.get("sha256", ""),
                "bytes": r.get("total_bytes", ""),
                "src": tx,
            })
    out["files"] = {
        "total": files_total,
        "types": dict(ftypes.most_common()),
        "entries": files,
    }

    # notice.log ---------------------------------------------------------
    notices = []
    for r in _iter_json_lines(_log(zeek_dir, "notice.log")):
        notices.append({
            "note": r.get("note", ""),
            "msg": r.get("msg", ""),
            "src": r.get("src", ""),
            "dst": r.get("dst", ""),
        })
    out["notices"] = notices[:REQUEST_CAP]

    # weird.log ----------------------------------------------------------
    weird = Counter()
    for r in _iter_json_lines(_log(zeek_dir, "weird.log")):
        weird[r.get("name", "")] += 1
    out["weird"] = [{"name": k, "count": v} for k, v in weird.most_common(25)]

    return out


# ---------------------------------------------------------------------------
# Loader for the web layer
# ---------------------------------------------------------------------------
def load_summary(job_dir: Path):
    sp = Path(job_dir) / "summary.json"
    if not sp.exists():
        return None
    try:
        return json.loads(sp.read_text())
    except Exception:
        return None
