#!/usr/bin/env python3
"""Mac 보안 관리 대시보드.

macOS 기본 보안 기능(방화벽, Gatekeeper, SIP, FileVault, XProtect)과
오픈소스 백신 ClamAV를 한 화면에서 점검·관리하는 로컬 웹 도구.

사용법:
    python3 security_dashboard.py            # 대시보드 실행 (브라우저 자동 열림)
    python3 security_dashboard.py --check    # 터미널에 보안 상태만 출력
    python3 security_dashboard.py --no-browser --port 8765

서버는 127.0.0.1 에만 열리며, 변경 요청은 페이지에 심어진 일회용 토큰이 있어야 처리된다.
관리자 권한이 필요한 작업은 macOS 기본 암호 창으로 사용자에게 직접 묻는다.
"""

import argparse
import faulthandler
import glob
import json
import os
import plistlib
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"
XPROTECT_PLIST = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
DATA_DIR = os.path.expanduser("~/Library/Application Support/MacSecurityDashboard")
QUARANTINE_DIR = os.path.join(DATA_DIR, "quarantine")
QUARANTINE_INDEX = os.path.join(QUARANTINE_DIR, "index.json")
HISTORY_FILE = os.path.join(DATA_DIR, "scan_history.json")
CLAM_SEARCH_DIRS = ["/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin"]
LAUNCH_DIRS = [
    ("사용자 LaunchAgents", os.path.expanduser("~/Library/LaunchAgents")),
    ("시스템 LaunchAgents", "/Library/LaunchAgents"),
    ("시스템 LaunchDaemons", "/Library/LaunchDaemons"),
]
SUSPICIOUS_DIRS = ("/tmp/", "/private/tmp/", "/var/tmp/", "/Users/Shared/")

APP_ID = "MacSecurityDashboard"
IDLE_EXIT_SECONDS = 1800  # --launch 모드: 대시보드 탭이 닫힌 뒤 이 시간이 지나면 서버 종료
LOG_FILE = os.path.join(DATA_DIR, "server.log")
CHILDREN_FILE = os.path.join(DATA_DIR, "children.json")  # 실행 중인 검사 프로세스 (비정상 종료 후 정리용)
CHILD_NAMES = ("clamscan", "freshclam")
CLAM_DB_MAX_AGE_DAYS = 7
MAX_SKIPPED_LISTED = 200
PRIVACY_PANE = "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"

TOKEN = secrets.token_urlsafe(24)
quarantine_lock = threading.Lock()
history_lock = threading.Lock()
last_seen = time.time()


# ---------------------------------------------------------------- 공통 유틸

def run(cmd, timeout=60):
    """명령을 실행하고 (returncode, stdout, stderr)를 돌려준다."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "명령을 찾을 수 없음: %s" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "", "시간 초과"


def run_as_admin(shell_cmd):
    """macOS 기본 관리자 암호 창을 띄워 명령을 실행한다. 암호는 이 프로그램이 보지 않는다."""
    escaped = shell_cmd.replace("\\", "\\\\").replace('"', '\\"')
    script = 'do shell script "%s" with administrator privileges' % escaped
    code, out, err = run(["osascript", "-e", script], timeout=300)
    if code != 0 and "-128" in err:
        return code, out, "사용자가 취소했습니다."
    return code, out, err


def find_tool(name):
    path = shutil.which(name)
    if path:
        return path
    for d in CLAM_SEARCH_DIRS:
        cand = os.path.join(d, name)
        if os.access(cand, os.X_OK):
            return cand
    return None


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = "%s.%d.tmp" % (path, threading.get_ident())
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def now_str():
    return time.strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------- 보안 상태 점검

def firewall_status():
    _, out, _ = run([SOCKETFILTERFW, "--getglobalstate", "--getstealthmode",
                     "--getblockall", "--getallowsigned"])
    low = out.lower()
    return {
        "enabled": "state = 1" in low or "state = 2" in low or "firewall is enabled" in low,
        "stealth": "stealth mode is on" in low or "stealth mode enabled" in low,
        "block_all": "block all state set to enabled" in low or "block all is enabled" in low,
        "allow_signed": "automatically allow signed built-in software enabled" in low
                        or "allow built-in signed software enabled" in low,
        "raw": out.strip(),
    }


def firewall_apps():
    _, out, _ = run([SOCKETFILTERFW, "--listapps"])
    apps, current = [], None
    for line in out.splitlines():
        m = re.match(r"^\s*\d+\s*:\s*(.+?)\s*$", line)
        if m:
            current = {"path": m.group(1), "allowed": None}
            apps.append(current)
        elif current is not None and "connections" in line.lower():
            current["allowed"] = "allow" in line.lower()
    return apps


def xprotect_version():
    try:
        with open(XPROTECT_PLIST, "rb") as f:
            return plistlib.load(f).get("CFBundleShortVersionString")
    except (OSError, plistlib.InvalidFileException):
        return None


def software_update_settings():
    try:
        with open("/Library/Preferences/com.apple.SoftwareUpdate.plist", "rb") as f:
            p = plistlib.load(f)
    except (OSError, plistlib.InvalidFileException):
        p = {}
    # 키가 없으면 macOS 기본값(켜짐)으로 본다.
    return {
        "auto_check": bool(p.get("AutomaticCheckEnabled", True)),
        "auto_download": bool(p.get("AutomaticDownload", True)),
        "security_data": bool(p.get("ConfigDataInstall", True)),
        "critical_updates": bool(p.get("CriticalUpdateInstall", True)),
    }


def clamav_info():
    clamscan, freshclam = find_tool("clamscan"), find_tool("freshclam")
    info = {"installed": bool(clamscan), "clamscan": clamscan, "freshclam": freshclam,
            "version": None, "db_date": None, "db_age_days": None, "brew": find_tool("brew")}
    if clamscan:
        _, out, _ = run([clamscan, "--version"], timeout=30)
        # 예: ClamAV 1.4.1/27450/Mon Nov  2 09:22:01 2026
        parts = out.strip().split("/")
        info["version"] = parts[0].replace("ClamAV", "").strip() if parts else None
        info["db_date"] = parts[2].strip() if len(parts) > 2 else None
        if info["db_date"]:
            try:
                db_time = time.mktime(time.strptime(info["db_date"], "%a %b %d %H:%M:%S %Y"))
                info["db_age_days"] = max(0, int((time.time() - db_time) // 86400))
            except ValueError:
                pass
    return info


def clamav_check(clam):
    if not clam["installed"]:
        return False, "설치되지 않음 — 바이러스 검사 탭에서 설치 방법을 확인하세요."
    if not clam["db_date"]:
        return False, "버전 %s · DB 없음 — DB 업데이트가 필요합니다" % clam["version"]
    age = clam["db_age_days"]
    if age is not None and age > CLAM_DB_MAX_AGE_DAYS:
        return False, "버전 %s · DB가 %d일 지남 — DB 업데이트가 필요합니다" % (clam["version"], age)
    return True, "버전 %s · DB %s%s" % (clam["version"], clam["db_date"],
                                       " (%d일 전)" % age if age else " (오늘)" if age == 0 else "")


def security_status():
    fw = firewall_status()
    _, gk, _ = run(["spctl", "--status"])
    _, sip, _ = run(["csrutil", "status"])
    _, fv, _ = run(["fdesetup", "status"])
    su = software_update_settings()
    clam = clamav_info()
    clam_ok, clam_detail = clamav_check(clam)
    checks = [
        {"id": "firewall", "name": "방화벽", "ok": fw["enabled"],
         "detail": "켜짐" if fw["enabled"] else "꺼짐 — 외부에서 들어오는 연결을 막지 못합니다."},
        {"id": "stealth", "name": "스텔스 모드", "ok": fw["stealth"],
         "detail": "켜짐 (ping 등 탐색에 응답 안 함)" if fw["stealth"] else "꺼짐 — 네트워크 탐색에 응답합니다."},
        {"id": "gatekeeper", "name": "Gatekeeper", "ok": "enabled" in gk,
         "detail": "확인된 개발자 앱만 실행" if "enabled" in gk else "꺼짐 — 서명 안 된 앱도 실행됩니다."},
        {"id": "sip", "name": "시스템 무결성 보호(SIP)", "ok": "enabled" in sip.lower(),
         "detail": sip.strip().replace("System Integrity Protection status:", "").strip()},
        {"id": "filevault", "name": "FileVault 디스크 암호화", "ok": "On" in fv,
         "detail": "켜짐" if "On" in fv else "꺼짐 — 분실 시 데이터가 노출될 수 있습니다."},
        {"id": "xprotect", "name": "XProtect (내장 악성코드 차단)", "ok": su["security_data"],
         "detail": "버전 %s · 보안 데이터 자동 설치 %s" % (
             xprotect_version() or "?", "켜짐" if su["security_data"] else "꺼짐")},
        {"id": "updates", "name": "보안 업데이트 자동 설치", "ok": su["critical_updates"] and su["auto_check"],
         "detail": "자동 확인 %s · 보안 응답 자동 설치 %s" % (
             "켜짐" if su["auto_check"] else "꺼짐", "켜짐" if su["critical_updates"] else "꺼짐")},
        {"id": "clamav", "name": "ClamAV 백신", "ok": clam_ok, "detail": clam_detail},
    ]
    score = round(100 * sum(1 for c in checks if c["ok"]) / len(checks))
    return {"checks": checks, "score": score, "firewall": fw, "clamav": clam,
            "host": os.uname().nodename, "checked_at": now_str()}


# ---------------------------------------------------------------- 방화벽 제어

FIREWALL_ACTIONS = {
    "enable": ["--setglobalstate", "on"],
    "disable": ["--setglobalstate", "off"],
    "stealth_on": ["--setstealthmode", "on"],
    "stealth_off": ["--setstealthmode", "off"],
    "blockall_on": ["--setblockall", "on"],
    "blockall_off": ["--setblockall", "off"],
}
FIREWALL_APP_ACTIONS = {"block": "--blockapp", "allow": "--unblockapp", "remove": "--remove"}


def firewall_action(action, app_path=None):
    if action in FIREWALL_ACTIONS:
        args = FIREWALL_ACTIONS[action]
    elif action in FIREWALL_APP_ACTIONS:
        if not app_path or not os.path.exists(app_path):
            return {"ok": False, "error": "앱 경로가 올바르지 않습니다."}
        args = [FIREWALL_APP_ACTIONS[action], app_path]
        if action == "allow":
            # 목록에 없으면 먼저 추가해야 허용 설정이 먹는다.
            args = ["--add", app_path, "&&", SOCKETFILTERFW, "--unblockapp", app_path]
    else:
        return {"ok": False, "error": "알 수 없는 작업"}
    cmd = SOCKETFILTERFW + " " + " ".join(a if a == "&&" else shlex.quote(a) for a in args)
    code, out, err = run_as_admin(cmd)
    return {"ok": code == 0, "output": out.strip(), "error": err.strip() if code else None}


# ---------------------------------------------------------------- 자동 실행 항목 점검

def code_signature(path):
    code, _, err = run(["codesign", "-dv", "--verbose=2", path], timeout=20)
    if code != 0:
        return {"signed": False, "valid": False, "authority": None, "team": None,
                "note": "서명 없음" if "not signed" in err else err.strip()[:120]}
    authority = re.search(r"^Authority=(.+)$", err, re.M)
    team = re.search(r"^TeamIdentifier=(.+)$", err, re.M)
    # -dv 는 서명 정보만 읽는다. 파일이 변조되지 않았는지는 --verify 로 따로 확인해야 한다.
    vcode, _, verr = run(["codesign", "--verify", path], timeout=60)
    return {"signed": True, "valid": vcode == 0,
            "authority": authority.group(1) if authority else "ad-hoc 서명",
            "team": team.group(1) if team and team.group(1) != "not set" else None,
            "note": None if vcode == 0 else (verr.strip().splitlines() or ["검증 실패"])[0][:160]}


def signature_warnings(path, sig):
    if not sig["signed"]:
        return ["코드 서명이 없음"]
    if not sig["valid"]:
        return ["서명이 손상·변조됨"]
    if not sig["team"] and not path.startswith(("/System/", "/usr/")):
        return ["개발자 ID 서명이 아님 (ad-hoc)"]
    return []


def launch_items():
    items = []
    for scope, d in LAUNCH_DIRS:
        for plist_path in sorted(glob.glob(os.path.join(d, "*.plist"))):
            item = {"scope": scope, "plist": plist_path, "label": os.path.basename(plist_path),
                    "program": None, "warnings": [], "signature": None}
            try:
                with open(plist_path, "rb") as f:
                    p = plistlib.load(f)
                item["label"] = p.get("Label", item["label"])
                prog = p.get("Program") or (p.get("ProgramArguments") or [None])[0]
                item["program"] = prog
                item["run_at_load"] = bool(p.get("RunAtLoad"))
                item["keep_alive"] = bool(p.get("KeepAlive"))
            except Exception as e:  # 손상되었거나 읽을 수 없는 plist
                item["warnings"].append("plist를 읽을 수 없음: %s" % e)
                items.append(item)
                continue
            prog = item["program"]
            if not p:
                item["warnings"].append("내용이 빈 plist (실행되지 않음, 정리해도 무방)")
            elif not prog:
                item["warnings"].append("실행 파일이 지정되지 않음")
            elif not os.path.exists(prog):
                item["warnings"].append("실행 파일이 없음 (삭제된 프로그램의 잔재일 수 있음)")
            else:
                sig = code_signature(prog)
                item["signature"] = sig
                item["warnings"] += signature_warnings(prog, sig)
                if prog.startswith(SUSPICIOUS_DIRS) or "/." in prog:
                    item["warnings"].append("임시·숨김 폴더에서 실행됨")
            items.append(item)
    return items


LOGIN_ITEMS_SCRIPT = '''
tell application "System Events"
    set out to ""
    repeat with li in login items
        set out to out & (name of li) & tab & (path of li) & linefeed
    end repeat
end tell
return out
'''


def login_items():
    """시스템 설정 > 일반 > 로그인 항목 의 '로그인 시 열기' 목록. 처음 한 번 자동화 권한을 묻는다."""
    code, out, err = run(["osascript", "-e", LOGIN_ITEMS_SCRIPT], timeout=30)
    if code != 0:
        note = ("System Events 제어 권한이 없습니다. 시스템 설정 > 개인정보 보호 및 보안 > 자동화 에서 허용하세요."
                if "-1743" in err or "not allowed" in err.lower() else "로그인 항목을 읽지 못했습니다: %s" % err.strip()[:160])
        return {"items": [], "error": note}
    items = []
    for line in out.splitlines():
        if not line.strip():
            continue
        name, _, path = line.partition("\t")
        item = {"scope": "로그인 항목", "label": name, "program": path or None, "plist": path or None,
                "warnings": [], "signature": None}
        if not path or not os.path.exists(path):
            item["warnings"].append("앱이 없음 (삭제된 프로그램의 잔재일 수 있음)")
        else:
            item["signature"] = code_signature(path)
            item["warnings"] += signature_warnings(path, item["signature"])
        items.append(item)
    return {"items": items, "error": None}


# ---------------------------------------------------------------- 백그라운드 작업 (검사)

jobs = {}
jobs_lock = threading.Lock()
children_lock = threading.Lock()


def spawn_child(cmd):
    """검사 프로세스를 띄우고 PID를 기록해 둔다. 서버가 강제 종료돼도 다음 실행 때 정리할 수 있게."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
    with children_lock:
        pids = load_json(CHILDREN_FILE, [])
        save_json(CHILDREN_FILE, pids + [proc.pid])
    return proc


def forget_child(proc):
    with children_lock:
        save_json(CHILDREN_FILE, [p for p in load_json(CHILDREN_FILE, []) if p != proc.pid])


def kill_orphaned_children():
    """지난번 서버가 갑자기 꺼지며 남긴 clamscan/freshclam 을 멈춘다. 우리가 띄운 PID만 대상으로 한다."""
    killed = []
    for pid in load_json(CHILDREN_FILE, []):
        _, comm, _ = run(["ps", "-p", str(pid), "-o", "comm="])
        if os.path.basename(comm.strip()) in CHILD_NAMES:
            try:
                os.kill(pid, signal.SIGTERM)
                killed.append(pid)
            except OSError:
                pass
    save_json(CHILDREN_FILE, [])
    return killed


def stop_all_jobs():
    for job_id in list(jobs):
        cancel_job(job_id)


def new_job(kind, target):
    """jobs_lock 을 잡은 상태에서 호출한다."""
    job = {"id": uuid.uuid4().hex[:12], "kind": kind, "target": target, "state": "running",
           "started": now_str(), "finished": None, "scanned": 0, "current": "",
           "findings": [], "skipped": 0, "skipped_paths": [], "log": [], "error": None, "proc": None}
    jobs[job["id"]] = job
    return job


def public_job(job):
    return {k: v for k, v in job.items() if k != "proc"}


def finish_job(job, state="done"):
    job["state"] = state if job["state"] != "cancelled" else "cancelled"
    job["finished"] = now_str()
    with history_lock:
        history = load_json(HISTORY_FILE, [])
        history.insert(0, {"kind": job["kind"], "target": job["target"], "started": job["started"],
                           "finished": job["finished"], "state": job["state"], "scanned": job["scanned"],
                           "found": len(job["findings"]), "skipped": job["skipped"]})
        try:
            save_json(HISTORY_FILE, history[:50])
        except OSError as e:
            job["log"].append("검사 기록 저장 실패: %s" % e)


def add_skipped(job, path):
    job["skipped"] += 1
    if len(job["skipped_paths"]) < MAX_SKIPPED_LISTED:
        job["skipped_paths"].append(path)


def clamav_scan_worker(job, clamscan):
    cmd = [clamscan, "-r", "--stdout", "--max-filesize=200M", "--max-scansize=400M",
           "--exclude-dir=^%s" % re.escape(QUARANTINE_DIR), job["target"]]
    proc = None
    try:
        proc = spawn_child(cmd)
        job["proc"] = proc
        summary = False
        for line in proc.stdout:
            line = line.rstrip("\n")
            if line.startswith("----------- SCAN SUMMARY"):
                summary = True
            if summary:
                job["log"].append(line)
                continue
            if line.endswith(" FOUND"):
                path, _, sig = line[:-6].rpartition(": ")
                job["findings"].append({"path": path, "threat": sig})
                job["scanned"] += 1
            elif line.endswith(": OK") or line.endswith(": Empty file") or line.endswith(": Excluded"):
                job["scanned"] += 1
                job["current"] = line.rsplit(": ", 1)[0]
            elif SKIP_LINE.search(line):
                # 예: "/path: Access denied", "/path: Can't open file or directory ERROR"
                #     macOS 개인정보 보호(TCC)로 막힌 폴더도 여기로 온다. 검사되지 않은 파일이다.
                path = re.sub(r"^(WARNING|ERROR):\s*", "", line).rsplit(": ", 1)[0]
                add_skipped(job, path)
            elif line.strip() and not line.startswith("LibClamAV"):
                job["log"].append(line)
        proc.wait()
        # clamscan 종료 코드: 0 = 깨끗함, 1 = 감염 발견, 2 = 오류
        if proc.returncode == 2 and not job["scanned"] and not job["skipped"] and job["state"] != "cancelled":
            job["error"] = "검사 중 오류가 발생했습니다. 로그를 확인하세요."
        finish_job(job)
    except Exception as e:
        job["error"] = str(e)
        finish_job(job, "error")
    finally:
        if proc:
            forget_child(proc)


SKIP_LINE = re.compile(r"(: Access denied$|\sERROR$|Can't open|Operation not permitted|Permission denied)")


def own_app_bundle():
    """앱으로 설치되어 실행 중이면 그 .app 경로 (…/X.app/Contents/Resources/이 파일)."""
    bundle = os.path.dirname(os.path.dirname(HERE))
    return os.path.realpath(bundle) if bundle.endswith(".app") else None


def app_signature_worker(job):
    apps = sorted(glob.glob("/Applications/*.app") + glob.glob(os.path.expanduser("~/Applications/*.app")))
    for app in apps:
        if job["state"] == "cancelled":
            break
        job["current"] = app
        if os.path.realpath(app) == own_app_bundle():
            job["scanned"] += 1
            job["log"].append("%s — 이 대시보드 (이 Mac에서 직접 설치한 앱, 검사 제외)" % os.path.basename(app))
            continue
        code, _, err = run(["spctl", "--assess", "--type", "execute", "-vv", app], timeout=60)
        job["scanned"] += 1
        source = re.search(r"source=(.+)", err)
        origin = re.search(r"origin=(.+)", err)
        if code != 0:
            job["findings"].append({"path": app, "threat": "Gatekeeper 거부: %s" % (
                source.group(1) if source else err.strip().splitlines()[-1] if err.strip() else "알 수 없음")})
        else:
            job["log"].append("%s — %s%s" % (os.path.basename(app), source.group(1) if source else "통과",
                                            (" (%s)" % origin.group(1)) if origin else ""))
    finish_job(job)


def freshclam_worker(job, freshclam):
    conf_note = ensure_freshclam_conf(freshclam)
    if conf_note:
        job["log"].append(conf_note)
    proc = None
    try:
        proc = spawn_child([freshclam])
        job["proc"] = proc
        for line in proc.stdout:
            job["log"].append(line.rstrip())
        proc.wait()
        if proc.returncode != 0 and job["state"] != "cancelled":
            job["error"] = "업데이트 실패 (종료 코드 %d)" % proc.returncode
        finish_job(job, "done" if proc.returncode == 0 else "error")
    except Exception as e:
        job["error"] = str(e)
        finish_job(job, "error")
    finally:
        if proc:
            forget_child(proc)


def ensure_freshclam_conf(freshclam):
    """Homebrew 설치 직후에는 freshclam.conf 가 없어서 업데이트가 실패한다. 샘플에서 만들어 준다."""
    etc = os.path.join(os.path.dirname(os.path.dirname(freshclam)), "etc", "clamav")
    conf, sample = os.path.join(etc, "freshclam.conf"), os.path.join(etc, "freshclam.conf.sample")
    if os.path.exists(conf) or not os.path.exists(sample):
        return None
    with open(sample, "r", encoding="utf-8", errors="replace") as f:
        text = re.sub(r"^Example\s*$", "# Example", f.read(), flags=re.M)
    try:
        with open(conf, "w", encoding="utf-8") as f:
            f.write(text)
        return "freshclam.conf 를 샘플에서 생성했습니다: %s" % conf
    except OSError as e:
        return "freshclam.conf 생성 실패: %s" % e


def start_job(kind, target=None):
    """새 작업을 시작한다. 같은 종류가 이미 진행 중이면 그 작업을 돌려준다 (already=True)."""
    if kind == "clamav":
        tool = find_tool("clamscan")
        if not tool:
            return None, False, "ClamAV가 설치되어 있지 않습니다."
        target = os.path.abspath(os.path.expanduser(target or "~/Downloads"))
        if not os.path.exists(target):
            return None, False, "경로가 존재하지 않습니다: %s" % target
        worker, args = clamav_scan_worker, (tool,)
    elif kind == "apps":
        target, worker, args = "/Applications", app_signature_worker, ()
    elif kind == "freshclam":
        tool = find_tool("freshclam")
        if not tool:
            return None, False, "freshclam 을 찾을 수 없습니다."
        target, worker, args = "ClamAV 바이러스 DB", freshclam_worker, (tool,)
    else:
        return None, False, "알 수 없는 작업"
    with jobs_lock:
        running = next((j for j in jobs.values() if j["kind"] == kind and j["state"] == "running"), None)
        if running:
            return running, True, None
        job = new_job(kind, target)
    threading.Thread(target=worker, args=(job,) + args, daemon=True).start()
    return job, False, None


def cancel_job(job_id):
    with jobs_lock:
        job = jobs.get(job_id)
    if not job or job["state"] != "running":
        return False
    job["state"] = "cancelled"
    proc = job.get("proc")
    if proc and proc.poll() is None:
        proc.terminate()
    return True


# ---------------------------------------------------------------- 격리함

def quarantine_list():
    return load_json(QUARANTINE_INDEX, [])


def quarantine_file(path, threat=""):
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        return {"ok": False, "error": "파일이 없습니다: %s" % path}
    if path.startswith(QUARANTINE_DIR):
        return {"ok": False, "error": "이미 격리된 파일입니다."}
    with quarantine_lock:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        os.chmod(QUARANTINE_DIR, 0o700)
        qid = uuid.uuid4().hex[:12]
        stored = os.path.join(QUARANTINE_DIR, qid + ".quarantined")
        mode = os.stat(path).st_mode & 0o7777
        try:
            shutil.move(path, stored)
        except OSError as e:
            return {"ok": False, "error": "이동 실패 (권한 문제일 수 있음): %s" % e}
        os.chmod(stored, 0o400)  # 실행 권한 제거, 읽기 전용
        index = quarantine_list()
        index.insert(0, {"id": qid, "original": path, "stored": stored, "threat": threat,
                         "mode": mode, "date": now_str()})
        save_json(QUARANTINE_INDEX, index)
    return {"ok": True, "id": qid}


MISSING_STORED = "격리 보관 파일이 없어져서 목록에서 정리했습니다."


def drop_missing(index, entry):
    """보관 파일이 사라진 항목이면 목록에서 지우고 True. (지울 수 없는 항목이 남지 않도록)"""
    if os.path.exists(entry["stored"]):
        return False
    save_json(QUARANTINE_INDEX, [e for e in index if e["id"] != entry["id"]])
    return True


def quarantine_restore(qid):
    with quarantine_lock:
        index = quarantine_list()
        entry = next((e for e in index if e["id"] == qid), None)
        if not entry:
            return {"ok": False, "error": "항목을 찾을 수 없습니다."}
        if drop_missing(index, entry):
            return {"ok": False, "error": MISSING_STORED}
        if os.path.exists(entry["original"]):
            return {"ok": False, "error": "원래 위치에 같은 이름의 파일이 이미 있습니다."}
        try:
            os.makedirs(os.path.dirname(entry["original"]), exist_ok=True)
            shutil.move(entry["stored"], entry["original"])
            os.chmod(entry["original"], entry.get("mode", 0o644))
        except OSError as e:
            return {"ok": False, "error": "복원 실패: %s" % e}
        save_json(QUARANTINE_INDEX, [e for e in index if e["id"] != qid])
    return {"ok": True}


def quarantine_trash(qid):
    """격리 파일을 휴지통으로 보낸다. 영구 삭제는 사용자가 휴지통에서 직접 한다."""
    with quarantine_lock:
        index = quarantine_list()
        entry = next((e for e in index if e["id"] == qid), None)
        if not entry:
            return {"ok": False, "error": "항목을 찾을 수 없습니다."}
        if drop_missing(index, entry):
            return {"ok": False, "error": MISSING_STORED}
        trash = os.path.expanduser("~/.Trash")
        name = "[격리] " + os.path.basename(entry["original"])
        dest = os.path.join(trash, name)
        if os.path.exists(dest):
            dest = os.path.join(trash, "%s_%s" % (entry["id"], name))
        try:
            shutil.move(entry["stored"], dest)
        except OSError as e:
            return {"ok": False, "error": "휴지통 이동 실패: %s" % e}
        save_json(QUARANTINE_INDEX, [e for e in index if e["id"] != qid])
    return {"ok": True}


# ---------------------------------------------------------------- 웹 서버

class Handler(BaseHTTPRequestHandler):
    server_version = "MacSecurityDashboard/1.0"

    def log_message(self, fmt, *args):
        pass  # 조용히

    def _host_ok(self):
        port = self.server.server_address[1]
        return self.headers.get("Host") in ("127.0.0.1:%d" % port, "localhost:%d" % port)

    def _send(self, status, body, ctype="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _safely(self, fn):
        # 처리 중 예외가 나도 응답 없이 끊기지 않고 화면에 오류가 보이게 한다.
        try:
            fn()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            print("[%s] 요청 처리 오류 %s: %r" % (now_str(), self.path, e))
            try:
                self._send(500, {"ok": False, "error": "내부 오류: %s" % e})
            except OSError:
                pass

    def do_GET(self):
        self._safely(self._get)

    def do_POST(self):
        self._safely(self._post)

    def _get(self):
        global last_seen
        if not self._host_ok():
            return self._send(403, {"error": "forbidden"})
        last_seen = time.time()
        path = urlparse(self.path).path
        if path == "/api/health":
            return self._send(200, {"app": APP_ID})
        if path == "/":
            with open(os.path.join(HERE, "dashboard.html"), "r", encoding="utf-8") as f:
                html = f.read().replace("__TOKEN__", TOKEN)
            return self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
        # 조회 API도 토큰을 요구해 다른 사이트가 정보를 읽지 못하게 한다.
        if self.headers.get("X-Token") != TOKEN:
            return self._send(403, {"error": "invalid token"})
        if path == "/api/ping":
            return self._send(200, {"ok": True})
        if path == "/api/status":
            return self._send(200, security_status())
        if path == "/api/firewall/apps":
            return self._send(200, firewall_apps())
        if path == "/api/launch-items":
            return self._send(200, {"launch": launch_items(), "login": login_items()})
        if path == "/api/quarantine":
            return self._send(200, quarantine_list())
        if path == "/api/history":
            return self._send(200, load_json(HISTORY_FILE, []))
        if path == "/api/jobs":
            # 이번 실행 동안의 작업 목록 (최신순). 화면을 새로 열어도 진행 상황을 이어 볼 수 있게 한다.
            with jobs_lock:
                listed = list(jobs.values())[::-1]  # dict 는 추가된 순서를 유지한다
            return self._send(200, [public_job(j) for j in listed])
        if path.startswith("/api/jobs/"):
            with jobs_lock:
                job = jobs.get(path.rsplit("/", 1)[-1])
            return self._send(200, public_job(job)) if job else self._send(404, {"error": "없음"})
        return self._send(404, {"error": "not found"})

    def _post(self):
        if not self._host_ok() or self.headers.get("X-Token") != TOKEN:
            return self._send(403, {"error": "forbidden"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._send(400, {"error": "잘못된 요청"})
        path = urlparse(self.path).path
        if path == "/api/shutdown":
            print("[%s] 종료 버튼으로 종료 요청" % now_str())
            stop_all_jobs()
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return self._send(200, {"ok": True})
        if path == "/api/firewall":
            return self._send(200, firewall_action(body.get("action"), body.get("app")))
        if path == "/api/jobs":
            job, already, err = start_job(body.get("kind"), body.get("target"))
            if not job:
                return self._send(400, {"error": err})
            return self._send(200, dict(public_job(job), already=already))
        if path == "/api/open-privacy":
            run(["open", PRIVACY_PANE])
            return self._send(200, {"ok": True})
        if path == "/api/jobs/cancel":
            return self._send(200, {"ok": cancel_job(body.get("id"))})
        if path == "/api/quarantine/add":
            return self._send(200, quarantine_file(body.get("path", ""), body.get("threat", "")))
        if path == "/api/quarantine/restore":
            return self._send(200, quarantine_restore(body.get("id")))
        if path == "/api/quarantine/trash":
            return self._send(200, quarantine_trash(body.get("id")))
        if path == "/api/reveal":
            target = body.get("path", "")
            if os.path.exists(target):
                run(["open", "-R", target])
                return self._send(200, {"ok": True})
            return self._send(200, {"ok": False, "error": "경로가 없습니다."})
        return self._send(404, {"error": "not found"})


# ---------------------------------------------------------------- 진입점

def print_check():
    st = security_status()
    print("\n  Mac 보안 점검 — %s (%s)\n" % (st["host"], st["checked_at"]))
    for c in st["checks"]:
        print("  %s  %-28s %s" % ("✅" if c["ok"] else "⚠️ ", c["name"], c["detail"]))
    print("\n  보안 점수: %d / 100\n" % st["score"])
    warned = [i for i in launch_items() + login_items()["items"] if i["warnings"]]
    if warned:
        print("  주의가 필요한 자동 실행 항목:")
        for i in warned:
            print("   - %s: %s" % (i["label"], ", ".join(i["warnings"])))
        print()


def running_instance(port):
    """해당 포트에서 이 대시보드가 이미 실행 중이면 True."""
    # urllib 대신 http.client: 프록시 조회용 시스템 프레임워크를 불러오지 않아 이후 fork 가 안전하다.
    from http.client import HTTPConnection
    try:
        # 검사 중에는 컴퓨터가 바빠 응답이 늦을 수 있다. 너무 짧으면 서버를 하나 더 띄우게 된다.
        conn = HTTPConnection("127.0.0.1", port, timeout=4)
        conn.request("GET", "/api/health", headers={"Host": "127.0.0.1:%d" % port})
        ok = json.loads(conn.getresponse().read() or b"{}").get("app") == APP_ID
        conn.close()
        return ok
    except Exception:
        return False


def detach_to_background():
    """앱에서 실행했을 때: 부모는 바로 끝나 앱에 성공을 알리고, 자식이 서버를 계속 돌린다."""
    if os.fork() > 0:
        return False
    os.setsid()
    os.makedirs(DATA_DIR, exist_ok=True)
    devnull = os.open(os.devnull, os.O_RDONLY)
    log_fd = os.open(LOG_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.dup2(devnull, 0)
    os.dup2(log_fd, 1)  # 앱이 기다리는 출력 파이프를 닫아야 앱이 바로 끝난다
    os.dup2(log_fd, 2)
    sys.stdout = sys.stderr = os.fdopen(1, "w", buffering=1, encoding="utf-8")
    return True


def idle_watchdog(server):
    """앱으로 실행했을 때: 대시보드 탭이 닫혀 ping 이 끊기고 진행 중인 작업이 없으면 종료한다."""
    while True:
        time.sleep(15)
        busy = any(j["state"] == "running" for j in list(jobs.values()))
        if not busy and time.time() - last_seen > IDLE_EXIT_SECONDS:
            print("[%s] 대시보드 탭이 %d분 동안 없어 자동 종료" % (now_str(), IDLE_EXIT_SECONDS // 60))
            server.shutdown()
            return


def main():
    ap = argparse.ArgumentParser(description="Mac 보안 관리 대시보드")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--check", action="store_true", help="터미널에 보안 상태만 출력하고 종료")
    ap.add_argument("--launch", action="store_true",
                    help="앱 모드: 이미 실행 중이면 브라우저만 열고, 탭을 닫으면 자동 종료")
    args = ap.parse_args()

    if sys.platform != "darwin":
        sys.exit("이 프로그램은 macOS 전용입니다.")
    if args.check:
        return print_check()

    server = None
    for port in range(args.port, args.port + 10 if args.launch else args.port + 1):
        if args.launch and running_instance(port):
            webbrowser.open("http://127.0.0.1:%d/" % port)
            return
        try:
            server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
            break
        except OSError:
            continue
    if server is None:
        sys.exit("포트 %d~%d 가 모두 사용 중이라 시작할 수 없습니다." % (args.port, port))

    url = "http://127.0.0.1:%d/" % server.server_address[1]
    if args.launch:
        if not detach_to_background():
            server.socket.close()  # 자식 프로세스가 같은 소켓으로 계속 서비스한다
            if not args.no_browser:
                webbrowser.open(url)
            return
        threading.Thread(target=idle_watchdog, args=(server,), daemon=True).start()
    elif not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    faulthandler.enable(file=sys.stderr)  # 비정상 종료 시 원인을 로그에 남긴다

    def on_signal(signum, _frame):
        # 설치·제거 스크립트나 시스템이 서버를 끌 때도 검사 프로세스를 함께 멈춘다.
        print("[%s] 종료 신호(%s) 받음" % (now_str(), signal.Signals(signum).name))
        stop_all_jobs()
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGHUP, on_signal)

    print("[%s] Mac 보안 대시보드 실행 중: %s  (종료: Ctrl+C)" % (now_str(), url))
    killed = kill_orphaned_children()
    if killed:
        print("[%s] 지난 실행에서 남은 검사 프로세스 정리: %s" % (now_str(), killed))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        stop_all_jobs()
    finally:
        print("[%s] 종료합니다." % now_str())


if __name__ == "__main__":
    main()
