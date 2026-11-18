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
START_DATE_RE = re.compile(r"^Start-Date:\s*(.+)$", re.MULTILINE)
DNF_TS_RE = re.compile(r"^\s*(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})", re.MULTILINE)
DNF_PKG_RE = re.compile(r"^\s*\.?(\w[\w.+-]*)\s+(\S+)\s+")
DNF_HEADER_WORDS = {"package", "name", "last", "repo", "repository", "error"}
NOT_UPGRADED_RE = re.compile(r"and (\d+) not upgraded")
APT_STAMP_FORMATS = ("%Y-%m-%d  %H:%M:%S", "%Y-%m-%d %H:%M:%S",
                     "%a, %d %b %Y %H:%M:%S %z")


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


def _apt_list_upgradable():
    """Parse `apt list --upgradable` (authoritative for total/security).

    Unlike `apt-get -s upgrade` this includes phased updates (the fleet
    ground truth) and runs unprivileged.
    """
    try:
        p = subprocess.run(["apt", "list", "--upgradable"],
                           capture_output=True, text=True, timeout=TIMEOUT)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None
    if p.returncode != 0:
        return None
    pkgs = []
    seen = set()
    for ln in (p.stdout or "").splitlines():
        if "[upgradable from:" not in ln:
            continue
        name = ln.split()[0].split("/")[0]
        if name in seen:
            continue
        seen.add(name)
        pkgs.append(ln)
    sec = [ln for ln in pkgs if _has_security_component(ln.split()[0])]
    return len(pkgs), len(sec)


def _apt_upgradable():
    # `apt list --upgradable` is authoritative for total + security: it
    # includes phased/held updates. `apt-get -s upgrade` prints no Inst lines
    # for phased packages, so its Inst counts are only a fallback here, and
    # its "N not upgraded" banner is emitted as not_upgraded.
    listed = _apt_list_upgradable()
    sim = None
    try:
        p = subprocess.run(
            ["apt-get", "-s", "-o", "Debug::NoLocking=1", "-y", "upgrade"],
            capture_output=True, text=True, timeout=TIMEOUT)
        if p.returncode == 0:
            stdout = p.stdout or ""
            inst = [ln[5:] for ln in stdout.splitlines() if ln.startswith("Inst ")]
            sec = [ln for ln in inst if "-security " in ln or "/security " in ln]
            m = NOT_UPGRADED_RE.search(stdout)
            sim = (len(inst), len(sec), int(m.group(1)) if m else None)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        sim = None
    if listed is None and sim is None:
        return None
    if listed is not None and sim is not None and sim[2] is not None:
        # Periodic metadata refreshes can make the two views disagree
        # transiently; whichever sees more is closer to the truth.
        total = max(listed[0], sim[2])
        sec, not_upgraded = listed[1], sim[2]
    elif listed is not None:
        total, sec, not_upgraded = listed[0], listed[1], listed[0]
    else:
        total, sec, not_upgraded = sim[0], sim[1], sim[2]
    return total, sec, not_upgraded


def _has_security_component(field):
    """True if any component token of a repo/series field is 'security'.

    For deb-style 'name/suite1,suite2' fields only the suite part is
    inspected (a package titled e.g. 'oscap-security-guide' must not match).
    Token-based ('noble-security', 'baseos-security', 'security') instead of
    a bare substring match.
    """
    if "/" in field:
        field = field.split("/", 1)[1]
    return any(part == "security"
               for tok in re.split(r"[\s,]+", field)
               for part in tok.split("-"))


def _apt_last_update():
    text = read_file(APT_HISTORY)
    if not text:
        return None
    stamps = [m.group(1).strip() for m in START_DATE_RE.finditer(text)]
    last = None
    for s in stamps:
        for fmt in APT_STAMP_FORMATS:
            try:
                dt = datetime.strptime(s, fmt)
            except ValueError:
                continue
            last = _newer(last, dt)
            break
    return last


def _newer(last, dt):
    """Max of two datetimes, never mixing naive and aware values."""
    if dt is None:
        return last
    if last is None:
        return dt
    if (dt.tzinfo is None) != (last.tzinfo is None):
        return last if dt.tzinfo is None else dt
    return dt if dt > last else last


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
    sec = [s for s in upg
           if len(s.split()) > 1 and _has_security_component(s.split()[1])]
    return len(upg), len(sec), None


def _dnf_last_update():
    last = None
    for path in DNF_LOGS:
        text = read_file(path)
        if not text:
            continue
        for m in DNF_TS_RE.finditer(text):
            ts = m.group(1)
            try:
                dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S") if "T" in ts else datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue
            last = _newer(last, dt)
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
        if len(counts) > 2 and counts[2] is not None:
            data["not_upgraded"] = counts[2]
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
