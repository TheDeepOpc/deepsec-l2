#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, Response, abort, jsonify, request, send_from_directory

import core as pentest_core


APP_ROOT = Path(__file__).parent
CORE_FILE = APP_ROOT / "core.py"
STATIC_DIR = APP_ROOT / "web_static"
REPORT_DIR = Path(getattr(pentest_core, "REPORT_DIR", APP_ROOT / "pentest_reports"))
MEMORY_FILE = getattr(pentest_core.FailureMemory, "MEMORY_FILE", REPORT_DIR / "failure_memory.json")
KB_FILE = getattr(pentest_core.KnowledgeBase, "KB_FILE", REPORT_DIR / "knowledge.json")
LEAKBASE_PATH = getattr(pentest_core.LeakBaseScanner, "LEAKBASE_PATH", APP_ROOT / "authbypass" / "Auth_Database.txt")

# uzCERT authorized pentest — WEB_SAFE_REPORTS is DISABLED
# All fields including payload, request_raw, response_raw, exploit_cmd are exposed
WEB_SAFE_REPORTS = False

CORE_META = pentest_core.web_panel_metadata() if hasattr(pentest_core, "web_panel_metadata") else {}
TOOLS = CORE_META.get("tools") or (
    pentest_core.tool_purposes() if hasattr(pentest_core, "tool_purposes") else {}
)
STAGES = [
    (item.get("token", ""), item.get("label", item.get("token", "")), int(item.get("progress", 0)))
    for item in (CORE_META.get("pipeline_stages") or (
        pentest_core.pipeline_stage_hints() if hasattr(pentest_core, "pipeline_stage_hints") else []
    ))
]

FINAL_STATUSES = {"done", "failed", "stopped"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_log_text(line: str) -> str:
    text = str(line or "").upper()
    text = re.sub(r"[^A-Z0-9]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def safe_slug(value: str) -> str:
    return re.sub(r"[^\w.]", "_", value or "")


def read_json(path: Path, default: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return default


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def expose_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Return finding as-is — authorized pentest, no field masking."""
    return dict(finding)


def expose_findings_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Full payload exposure for authorized pentest."""
    clean = dict(payload or {})
    findings = clean.get("findings")
    clean["findings"] = [expose_finding(item) for item in findings] if isinstance(findings, list) else []
    clean["suppressed"] = clean.get("suppressed") if isinstance(clean.get("suppressed"), list) else []
    clean["scan_log"] = clean.get("scan_log") if isinstance(clean.get("scan_log"), list) else []
    clean["endpoint_analysis"] = clean.get("endpoint_analysis") if isinstance(clean.get("endpoint_analysis"), list) else []
    clean["reports"] = clean.get("reports") if isinstance(clean.get("reports"), list) else []
    clean["ai_analysis"] = str(clean.get("ai_analysis") or "")
    return clean


def tools_status() -> Dict[str, Any]:
    return {
        "tools": {
            name: {"available": shutil.which(name) is not None, "purpose": purpose}
            for name, purpose in TOOLS.items()
        },
        "wordlists": pentest_core.WordlistScanner.summary(),
    }


def default_memory() -> Dict[str, Any]:
    return {
        "false_positives": [],
        "wrong_actions": [],
        "failed_payloads": [],
        "last_updated": "",
        "total_lessons": 0,
    }


def default_kb() -> Dict[str, Any]:
    return {
        "lessons": [],
        "global_rules": [],
        "last_updated": "",
        "total_lessons": 0,
    }


def update_stage_from_line(scan: "ScanRuntime", line: str) -> None:
    normalized = normalize_log_text(line)
    for token, label, pct in STAGES:
        if normalized == token:
            scan.active_stage = label
            scan.progress = max(scan.progress, pct)
            return


def capture_report_files(scan: "ScanRuntime", line: str) -> None:
    patterns = {
        "findings": r"(findings_[^\s]+\.json)",
        "html": r"(report_[^\s]+\.html)",
        "md": r"(pentest_[^\s]+\.md)",
    }
    for key, pattern in patterns.items():
        if key in scan.report_files:
            continue
        match = re.search(pattern, line)
        if match:
            scan.report_files[key] = REPORT_DIR / Path(match.group(1)).name


def latest_findings_file(target: str, started_at: float) -> Optional[Path]:
    slug = safe_slug(target)
    preferred = sorted(REPORT_DIR.glob(f"findings_{slug}_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for path in preferred:
        try:
            if path.stat().st_mtime >= started_at - 3:
                return path
        except Exception:
            continue
    candidates = sorted(REPORT_DIR.glob("findings_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for path in candidates:
        try:
            if path.stat().st_mtime >= started_at - 3:
                return path
        except Exception:
            continue
    return None


@dataclass
class ScanRuntime:
    id: str
    target: str
    cmd: List[str]
    process: subprocess.Popen
    created_at: str
    status: str = "queued"
    message: str = "queued"
    logs: List[str] = field(default_factory=list)
    findings_payload: Dict[str, Any] = field(default_factory=dict)
    report_files: Dict[str, Path] = field(default_factory=dict)
    active_stage: str = ""
    progress: int = 0
    returncode: Optional[int] = None
    started_monotonic: float = field(default_factory=time.time)
    finished_at: str = ""
    stop_requested: bool = False
    mode: str = "full"
    deep: bool = False
    test_env: str = "Dev"
    log_lock: threading.Lock = field(default_factory=threading.Lock)

    def append_log(self, line: str) -> None:
        with self.log_lock:
            self.logs.append(line)
            if len(self.logs) > 8000:
                self.logs = self.logs[-8000:]
        update_stage_from_line(self, line)
        capture_report_files(self, line)

    def snapshot(self) -> Dict[str, Any]:
        findings = self.findings_payload.get("findings", []) if isinstance(self.findings_payload, dict) else []
        summary = self.findings_payload.get("summary", {}) if isinstance(self.findings_payload, dict) else {}
        risk_counts = summary.get("by_risk", {}) if isinstance(summary, dict) else {}
        return {
            "id": self.id,
            "target": self.target,
            "status": self.status,
            "message": self.message,
            "progress": self.progress,
            "active_stage": self.active_stage,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "mode": self.mode,
            "deep": self.deep,
            "test_env": self.test_env,
            "returncode": self.returncode,
            "reports": [p.name for p in self.report_files.values() if isinstance(p, Path) and p.exists()],
            "findings_total": len(findings),
            "summary": summary,
            "critical": int(risk_counts.get("Critical", 0)),
            "high": int(risk_counts.get("High", 0)),
            "medium": int(risk_counts.get("Medium", 0)),
            "low": int(risk_counts.get("Low", 0)),
        }


app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="")
scans: Dict[str, ScanRuntime] = {}
scans_lock = threading.RLock()


def get_scan(scan_id: str) -> ScanRuntime:
    with scans_lock:
        scan = scans.get(scan_id)
    if not scan:
        abort(404, description="scan not found")
    return scan


def persist_findings(scan: ScanRuntime) -> None:
    findings_path = scan.report_files.get("findings")
    if not findings_path or not findings_path.exists():
        findings_path = latest_findings_file(scan.target, scan.started_monotonic)
        if findings_path:
            scan.report_files["findings"] = findings_path
    if not findings_path or not findings_path.exists():
        return

    payload = read_json(findings_path, {})
    if isinstance(payload, dict):
        scan.findings_payload = expose_findings_payload(payload)
        scan.report_files.setdefault("findings", findings_path)
        for name in scan.findings_payload.get("reports", []):
            report_path = REPORT_DIR / str(name)
            if report_path.exists():
                suffix = report_path.suffix.lower()
                key = "html" if suffix == ".html" else "md" if suffix == ".md" else "findings"
                scan.report_files[key] = report_path


def build_command(payload: Dict[str, Any]) -> List[str]:
    target = str(payload.get("target") or "").strip()
    if not target:
        raise ValueError("target required")
    cmd = [sys.executable, "-u", str(CORE_FILE), "--target", target]

    mode = str(payload.get("mode") or "full").strip() or "full"
    cmd += ["--mode", mode]

    # String arguments
    mapping = {
        "auth_url": "--auth-url",
        "user": "--user",
        "username": "--user",
        "password": "--password",
        "admin_user": "--admin-user",
        "admin_pass": "--admin-pass",
        "model": "--model",
        "report_template": "--report-template",
    }
    already = set()
    for key, flag in mapping.items():
        value = str(payload.get(key) or "").strip()
        if value and flag not in already:
            cmd += [flag, value]
            already.add(flag)

    # Boolean flags — all CLI flags supported
    bool_flags = {
        "deep":       "--deep",
        "ctf":        "--ctf",
        "oob":        "--oob",
        "no_nuclei":  "--no-nuclei",
        "no_403":     "--no-403",
        "no_upload":  "--no-upload",
        "chat":       "--chat",
        "advisor":    "--advisor",
        "tools":      "--tools",
    }
    for key, cli_flag in bool_flags.items():
        if bool(payload.get(key)):
            cmd.append(cli_flag)

    return cmd


def masked_command(cmd: List[str]) -> List[str]:
    out: List[str] = []
    mask_next = False
    for item in cmd:
        value = str(item)
        if mask_next:
            out.append("********")
            mask_next = False
            continue
        out.append(value)
        if value in {"--password", "--admin-pass"}:
            mask_next = True
    return out


def finalize_scan(scan: ScanRuntime) -> None:
    persist_findings(scan)
    if scan.returncode == 0 and scan.status not in FINAL_STATUSES:
        scan.status = "done"
        scan.message = "completed"
    elif scan.returncode not in (None, 0) and scan.status not in FINAL_STATUSES:
        scan.status = "failed"
        scan.message = f"failed (exit {scan.returncode})"
    if scan.status == "done":
        scan.progress = 100
        scan.active_stage = scan.active_stage or "Completed"
    scan.finished_at = now_iso()


def scan_reader(scan: ScanRuntime) -> None:
    scan.status = "running"
    scan.message = "running"
    scan.progress = 1
    try:
        if scan.process.stdout:
            for raw_line in scan.process.stdout:
                line = raw_line.rstrip("\r\n")
                if line:
                    scan.append_log(line)
                if scan.stop_requested:
                    break
        rc = scan.process.wait()
        scan.returncode = rc
    except Exception as exc:
        scan.returncode = -1
        scan.append_log(f"[web-panel] reader error: {exc}")
    finally:
        if scan.stop_requested:
            scan.status = "stopped"
            scan.message = "stopped"
        finalize_scan(scan)


def kb_instance() -> pentest_core.KnowledgeBase:
    ai = pentest_core.AIEngine()
    return pentest_core.KnowledgeBase(ai)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
def root() -> Response:
    return send_from_directory(STATIC_DIR, "index.html")


@app.get("/reports/<path:name>")
def report_file(name: str) -> Response:
    path = REPORT_DIR / name
    if not path.exists():
        abort(404)
    return send_from_directory(REPORT_DIR, name, as_attachment=False)


@app.post("/api/scan/start")
def api_scan_start() -> Response:
    payload = request.get_json(silent=True) or {}
    try:
        cmd = build_command(payload)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    scan_id = uuid.uuid4().hex[:12]
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"

    env.pop("WEB_SAFE_REPORTS", None)

    if payload.get("ollama_host"):
        env["OLLAMA_HOST"] = str(payload["ollama_host"])
    if payload.get("model"):
        env["OLLAMA_MODEL"] = str(payload["model"])

    proc = subprocess.Popen(
        cmd,
        cwd=str(APP_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        env=env,
    )

    # ✅ ENG MUHIM FIX — runtime avval yaratiladi
    runtime = ScanRuntime(
        id=scan_id,
        target=str(payload.get("target") or "").strip(),
        cmd=masked_command(cmd),
        process=proc,
        created_at=now_iso(),
        mode=str(payload.get("mode") or "full"),
        deep=bool(payload.get("deep")),
        test_env=str(payload.get("test_env") or payload.get("test_environment") or "Dev"),
    )

    ascii_banner = """
\033[31m
 /$$$$$$$  /$$$$$$$$ /$$$$$$$$ /$$$$$$$   /$$$$$$  /$$$$$$$$  /$$$$$$ 
| $$__  $$| $$_____/| $$_____/| $$__  $$ /$$__  $$| $$_____/ /$$__  $$
| $$  \ $$| $$      | $$      | $$  \ $$| $$  \__/| $$      | $$  \__/
| $$  | $$| $$$$$   | $$$$$   | $$$$$$$/|  $$$$$$ | $$$$$   | $$      
| $$  | $$| $$__/   | $$__/   | $$____/  \____  $$| $$__/   | $$      
| $$  | $$| $$      | $$      | $$       /$$  \ $$| $$      | $$    $$
| $$$$$$$/| $$$$$$$$| $$$$$$$$| $$      |  $$$$$$/| $$$$$$$$|  $$$$$$/
|_______/ |________/|________/|__/       \______/ |________/ \______/ 

                        [  C O - P I L O T  ]
                    ----AI based Pentest Agent----
                 
Name: DeepSec MARK 2
Type: Black Box Web Application Pentest Agent
AI model: minmax-m2:cloud(Ollama)
REPO: https://github.com/TheDeepOpc/deepsec-l2
\033[0m
"""

    # ✅ endi bemalol ishlaydi
    runtime.append_log(ascii_banner)
  

    with scans_lock:
        scans[scan_id] = runtime

    threading.Thread(target=scan_reader, args=(runtime,), daemon=True).start()

    return jsonify({
        "ok": True,
        "id": scan_id,
        "scan": runtime.snapshot()
    })

@app.post("/api/scan/<scan_id>/stop")
def api_scan_stop(scan_id: str) -> Response:
    scan = get_scan(scan_id)
    scan.stop_requested = True
    scan.status = "stopping"
    scan.message = "stop requested"
    try:
        if scan.process.poll() is None:
            if os.name == "nt":
                scan.process.terminate()
            else:
                scan.process.send_signal(signal.SIGINT)
    except Exception as exc:
        scan.append_log(f"[web-panel] stop error: {exc}")
    return jsonify({"ok": True, "id": scan_id, "status": scan.status})


@app.get("/api/scan/<scan_id>/logs")
def api_scan_logs(scan_id: str) -> Response:
    scan = get_scan(scan_id)
    if request.args.get("stream") in {"1", "true", "yes"}:
        def generate() -> Any:
            offset = 0
            while True:
                with scan.log_lock:
                    lines = scan.logs[offset:]
                    total = len(scan.logs)
                if lines:
                    payload = {
                        "offset": total,
                        "lines": lines,
                        "status": scan.status,
                        "active_stage": scan.active_stage,
                        "progress": scan.progress,
                    }
                    yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
                    offset = total
                if scan.status in FINAL_STATUSES and offset >= total:
                    break
                time.sleep(0.6)

        return Response(
            generate(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    try:
        offset = max(0, int(request.args.get("offset", "0")))
    except Exception:
        offset = 0
    with scan.log_lock:
        lines = scan.logs[offset:]
        total = len(scan.logs)
    return jsonify(
        {
            "id": scan.id,
            "offset": total,
            "lines": lines,
            "status": scan.status,
            "active_stage": scan.active_stage,
            "progress": scan.progress,
        }
    )


@app.get("/api/scan/<scan_id>/findings")
def api_scan_findings(scan_id: str) -> Response:
    scan = get_scan(scan_id)
    persist_findings(scan)
    return jsonify(
        {
            "id": scan.id,
            "target": scan.target,
            "status": scan.status,
            "summary": scan.findings_payload.get("summary", {}),
            "findings": scan.findings_payload.get("findings", []),
            "suppressed": scan.findings_payload.get("suppressed", []),
            "scan_log": scan.findings_payload.get("scan_log", []),
            "endpoint_analysis": scan.findings_payload.get("endpoint_analysis", []),
            "ai_analysis": scan.findings_payload.get("ai_analysis", ""),
            "reports": scan.findings_payload.get("reports", []),
        }
    )


@app.get("/api/scans")
def api_scans() -> Response:
    with scans_lock:
        payload = [scan.snapshot() for scan in scans.values()]
    payload.sort(key=lambda item: item.get("created_at") or "", reverse=True)
    return jsonify({"scans": payload})


# ── AI Repeater — full authorized mutation replay ─────────────────────────────

@app.post("/api/repeater/run")
def api_repeater_run() -> Response:
    """
    Full AI Repeater mutation engine.
    uzCERT authorized pentest — all mutation types enabled:
    AUTH_REMOVE, IDOR, METHOD_SWITCH, PARAM_TAMPER, PATH_ESCALATE,
    HEADER_INJECT, OBJECT_LEVEL, PRIV_ESCALATE
    """
    payload = request.get_json(silent=True) or {}
    scan_id = str(payload.get("scan_id") or "")
    ep_data = payload.get("endpoint") or {}

    if not ep_data.get("url"):
        return jsonify({"error": "endpoint.url required"}), 400

    # Build SessionContext from provided cookies/jwt
    session = pentest_core.SessionContext()
    session.cookies = dict(payload.get("cookies") or {})
    session.jwt_token = str(payload.get("jwt_token") or "")
    session.csrf_token = str(payload.get("csrf_token") or "")

    client = pentest_core.HTTPClient(session)
    ai = pentest_core.AIEngine()
    ctx = pentest_core.ScanContext()
    ctx.target = ep_data.get("url", "")

    # Build Endpoint object
    ep = pentest_core.Endpoint(
        url=ep_data.get("url", ""),
        method=str(ep_data.get("method", "GET")).upper(),
        params=dict(ep_data.get("params") or {}),
        body_type=str(ep_data.get("body_type") or "form"),
        discovered_by="repeater_web",
    )
    ep.score = float(ep_data.get("score") or 50)

    interceptor = pentest_core.RequestInterceptor(client, ai, ctx)

    findings: List[pentest_core.Finding] = []
    try:
        findings = interceptor.analyze_endpoints([ep])
    except Exception as exc:
        return jsonify({"error": str(exc), "findings": []}), 500

    return jsonify({
        "ok": True,
        "scan_id": scan_id,
        "endpoint": ep.url,
        "findings": [f.to_dict(safe=False) for f in findings],
        "total": len(findings),
    })


@app.post("/api/repeater/fuzz")
def api_repeater_fuzz() -> Response:
    """
    Direct OWASP fuzz on a single endpoint.
    Runs full AgenticFuzzEngine loop.
    """
    payload = request.get_json(silent=True) or {}
    ep_data = payload.get("endpoint") or {}
    if not ep_data.get("url"):
        return jsonify({"error": "endpoint.url required"}), 400

    session = pentest_core.SessionContext()
    session.cookies = dict(payload.get("cookies") or {})
    session.jwt_token = str(payload.get("jwt_token") or "")

    client = pentest_core.HTTPClient(session)
    ai = pentest_core.AIEngine()
    ctx = pentest_core.ScanContext()
    ctx.target = ep_data.get("url", "")
    ctx.site_tech = dict(payload.get("tech") or {})

    ep = pentest_core.Endpoint(
        url=ep_data.get("url", ""),
        method=str(ep_data.get("method", "GET")).upper(),
        params=dict(ep_data.get("params") or {}),
        body_type=str(ep_data.get("body_type") or "form"),
        discovered_by="manual_fuzz",
    )

    baseline = pentest_core.BaselineEngine(client)
    kali = pentest_core.KaliToolRunner(session)
    fuzzer = pentest_core.OWASPFuzzEngine(client, baseline, kali, ai, ctx)

    findings: List[pentest_core.Finding] = []
    try:
        findings = fuzzer.test_endpoint(ep)
    except Exception as exc:
        return jsonify({"error": str(exc), "findings": []}), 500

    return jsonify({
        "ok": True,
        "endpoint": ep.url,
        "findings": [f.to_dict(safe=False) for f in findings],
        "total": len(findings),
    })


# ── Knowledge Base ────────────────────────────────────────────────────────────

@app.post("/api/kb/chat")
def api_kb_chat() -> Response:
    payload = request.get_json(silent=True) or {}
    message = str(payload.get("message") or "").strip()
    if not message:
        return jsonify({"error": "message required"}), 400

    target = str(payload.get("target") or "").strip()
    scan_id = str(payload.get("scan_id") or "").strip()
    history = payload.get("history") if isinstance(payload.get("history"), list) else []

    kb = kb_instance()
    context = kb._build_context(target) if hasattr(kb, "_build_context") else kb.build_scan_context(target)
    reply, rule_data = kb._ai_respond(message, history, context, target, scan_id)

    saved_lesson = None
    if rule_data:
        saved_lesson = {
            "id": uuid.uuid4().hex[:12],
            "ts": datetime.now().isoformat(),
            "target": target,
            "scan_id": scan_id,
            "type": rule_data.get("type", "custom"),
            "finding_title": rule_data.get("finding_title", ""),
            "user_feedback": message[:500],
            "ai_analysis": str(reply)[:500],
            "rule": rule_data.get("rule", ""),
            "applied_count": 0,
            "applies_to": rule_data.get("applies_to", "this_target"),
        }
        kb.lessons.append(saved_lesson)
        kb.save()

    return jsonify({"reply": reply, "learned": bool(saved_lesson), "lesson": saved_lesson})


@app.get("/api/kb/lessons")
def api_kb_lessons() -> Response:
    return jsonify(read_json(KB_FILE, default_kb()))


@app.post("/api/kb/lessons")
def api_kb_lessons_add() -> Response:
    payload = request.get_json(silent=True) or {}
    data = read_json(KB_FILE, default_kb())
    lesson = {
        "id": str(payload.get("id") or uuid.uuid4().hex[:12]),
        "ts": str(payload.get("ts") or datetime.now().isoformat()),
        "target": str(payload.get("target") or ""),
        "scan_id": str(payload.get("scan_id") or ""),
        "type": str(payload.get("type") or "custom"),
        "finding_title": str(payload.get("finding_title") or ""),
        "user_feedback": str(payload.get("user_feedback") or ""),
        "ai_analysis": str(payload.get("ai_analysis") or ""),
        "rule": str(payload.get("rule") or ""),
        "applied_count": int(payload.get("applied_count") or 0),
        "applies_to": str(payload.get("applies_to") or "this_target"),
    }
    lessons = data.get("lessons", [])
    lessons.append(lesson)
    data["lessons"] = lessons[-500:]
    data["last_updated"] = datetime.now().isoformat()
    data["total_lessons"] = len(data["lessons"])
    write_json(KB_FILE, data)
    return jsonify({"ok": True, "lesson": lesson})


@app.delete("/api/kb/lessons/<lesson_id>")
def api_kb_lessons_delete(lesson_id: str) -> Response:
    data = read_json(KB_FILE, default_kb())
    lessons = data.get("lessons", [])
    data["lessons"] = [item for item in lessons if str(item.get("id")) != lesson_id]
    data["last_updated"] = datetime.now().isoformat()
    data["total_lessons"] = len(data["lessons"])
    write_json(KB_FILE, data)
    return jsonify({"ok": True, "id": lesson_id})


@app.get("/api/kb/rules")
def api_kb_rules() -> Response:
    data = read_json(KB_FILE, default_kb())
    return jsonify({"global_rules": data.get("global_rules", [])})


# ── AI Memory ─────────────────────────────────────────────────────────────────

@app.get("/api/memory")
def api_memory() -> Response:
    return jsonify(read_json(MEMORY_FILE, default_memory()))


@app.delete("/api/memory")
def api_memory_clear() -> Response:
    write_json(MEMORY_FILE, default_memory())
    return jsonify({"ok": True})


# ── Tools & Meta ──────────────────────────────────────────────────────────────

@app.get("/api/tools")
def api_tools() -> Response:
    return jsonify(tools_status())


@app.get("/api/core/meta")
def api_core_meta() -> Response:
    return jsonify(
        {
            "finding_fields": CORE_META.get("finding_fields")
            or (pentest_core.finding_field_names() if hasattr(pentest_core, "finding_field_names") else []),
            "cli_args": CORE_META.get("cli_args")
            or (pentest_core.cli_argument_schema() if hasattr(pentest_core, "cli_argument_schema") else []),
            "pipeline_stages": CORE_META.get("pipeline_stages")
            or (pentest_core.pipeline_stage_hints() if hasattr(pentest_core, "pipeline_stage_hints") else []),
            "tools": TOOLS,
            "web_safe": False,
        }
    )


@app.get("/api/settings")
def api_settings() -> Response:
    return jsonify(
        {
            "ollama_host": os.environ.get("OLLAMA_HOST", getattr(pentest_core, "OLLAMA_HOST", "http://localhost:11434")),
            "ollama_model": os.environ.get(
                "OLLAMA_MODEL",
                pentest_core.active_model_name() if hasattr(pentest_core, "active_model_name")
                else getattr(pentest_core, "MODEL_NAME", "llama3.1:8b"),
            ),
            "leakbase_path": str(LEAKBASE_PATH),
            "report_dir": str(REPORT_DIR),
            "core_file": str(CORE_FILE),
            "web_safe_reports": False,
            "authorized_mode": "uzCERT",
            "finding_fields": CORE_META.get("finding_fields")
            or (pentest_core.finding_field_names() if hasattr(pentest_core, "finding_field_names") else []),
        }
    )


@app.get("/api/reports")
def api_reports() -> Response:
    REPORT_DIR.mkdir(exist_ok=True)
    files = []
    for path in sorted(REPORT_DIR.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True):
        if not path.is_file():
            continue
        stat = path.stat()
        files.append(
            {
                "name": path.name,
                "size": stat.st_size,
                "mtime": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                "kind": path.suffix.lower().lstrip("."),
                "url": f"/reports/{path.name}",
            }
        )
    return jsonify({"reports": files})


def main() -> int:
    STATIC_DIR.mkdir(exist_ok=True)
    REPORT_DIR.mkdir(exist_ok=True)
    host = os.environ.get("WEB_PANEL_HOST", "127.0.0.1")
    port = int(os.environ.get("WEB_PANEL_PORT", "8088"))
    print(f"[uzCERT Pentest AI] Web Panel → http://{host}:{port}")
    print("[uzCERT Pentest AI] Authorized mode — all fields exposed, no safe-mode restrictions")
    app.run(host=host, port=port, threaded=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
