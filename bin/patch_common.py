"""Shared collection logic for the TA-patch scripted inputs (apt / dnf)."""
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime

TIMEOUT = 120
OS_RELEASE = "/etc/os-release"
APT_HISTORY = "/var/log/apt/history.log"
DNF_LOGS = ("/var/log/dnf.log", "/var/log/hawkey.log")

PRETTY_RE = re.compile(r'^PRETTY_NAME="(.*)"\s*$', re.MULTILINE)
START_DATE_RE = re.compile(r"^Start-Date:\s*(.+)$")
DNF_TS_RE = re.compile(r"^\s*(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})")
DNF_PKG_RE = re.compile(r"^\s*\.?(\w[\w.+-]*)\s+(\S+)\s+")
DNF_HEADER_WORDS = {"package", "name", "last", "repo", "repository", "error"}


def read_file(path):
    try:
        with open(path) as fh:
            return fh.read()
    except OSError:
        return None


def _on_path(name):
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if d and os.access(os.path.join(d, name), os.X_OK):
            return True
    return False


def detect_pm():
    for p in ("/usr/bin/apt-get", "/usr/sbin/apt-get"):
        if os.path.isfile(p):
            return "apt"
    if _on_path("apt-get"):
        return "apt"
    for p in ("/usr/bin/dnf", "/usr/sbin/dnf"):
        if os.path.isfile(p):
            return "dnf"
    if _on_path("dnf"):
        return "dnf"
    return None


def read_release():
    text = read_file(OS_RELEASE)
    if not text:
        return None
    m = PRETTY_RE.search(text)
    return m.group(1) if m else None


def _apt_upgradable():
    try:
        p = subprocess.run(
            ["apt-get", "-s", "-o", "Debug::NoLocking=1", "-y", "upgrade"],
            capture_output=True, text=True, timeout=TIMEOUT)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None
    if p.returncode != 0:
        return None
    inst = [ln[5:] for ln in (p.stdout or "").splitlines() if ln.startswith("Inst ")]
    sec = [ln for ln in inst if "-security " in ln or "/security " in ln]
    return len(inst), len(sec)


def _dnf_upgradable():
    try:
        p = subprocess.run(["dnf", "check-update", "-q", "-y"],
                           capture_output=True, text=True, timeout=TIMEOUT)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None
    upg = []
    for ln in (p.stdout or "").splitlines():
        s = ln.strip()
        if not s or "No packages need updating" in s:
            continue
        if not DNF_PKG_RE.match(s):
            continue
        if s.split()[0].lower() in DNF_HEADER_WORDS:
            continue
        upg.append(s)
    return len(upg), len(s for s in upg if "security" in s)


def _apt_last_update():
    text = read_file(APT_HISTORY)
    if not text:
        return None
    stamps = [m.group(1).strip() for m in START_DATE_RE.finditer(text, re.MULTILINE)]
    last = None
    for s in stamps:
        try:
            last = datetime.strptime(s, "%a, %d %b %Y %H:%M:%S %z")
        except ValueError:
            continue
    return last


def _dnf_last_update():
    last = None
    for path in DNF_LOGS:
        text = read_file(path)
        if not text:
            continue
        for m in DNF_TS_RE.finditer(text, re.MULTILINE):
            ts = m.group(1)
            try:
                dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S") if "T" in ts else datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue
            if dt.tzinfo is None and last is not None and last.tzinfo is not None:
                continue
            if last is None or dt > last:
                last = dt
    return last


def discover():
    data = {"status": "absent", "pm": None}
    rel = read_release()
    if rel:
        data["release"] = rel
    pm = detect_pm()
    if pm is None:
        return data
    data["pm"] = pm
    data["status"] = "ok"
    if pm == "apt":
        counts = _apt_upgradable()
        last = _apt_last_update()
    else:
        counts = _dnf_upgradable()
        last = _dnf_last_update()
    if counts is not None:
        data["upgradable"] = counts[0]
        data["security_upgradable"] = counts[1]
    if last is not None:
        try:
            data["last_update"] = last.isoformat()
            data["days_since_update"] = round((time.time() - last.timestamp()) / 86400.0, 2)
        except (ValueError, OverflowError, OSError):
            pass
    return data


def metrics_payload(data):
    payload = {}
    for key in ("upgradable", "security_upgradable", "days_since_update"):
        v = data.get(key)
        if v is not None:
            payload[key] = v
    payload["pm_known"] = 1 if data.get("pm") else 0
    return payload


def emit(payload):
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    sys.stdout.flush()


def fail(message):
    sys.stderr.write("TA-patch collection error: %s\n" % message)
    return 1
