from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
from urllib import error, parse, request
from uuid import UUID, uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field, SecretStr


APP_DIR = Path(__file__).resolve().parent
PROJECT_DIR = APP_DIR.parent
STATIC_DIR = APP_DIR / "static"
REPORT_DIR = Path(os.getenv("REPORT_DIR", PROJECT_DIR / "reports")).resolve()
REPORT_DIR.mkdir(parents=True, exist_ok=True)
BROWSER_SECRET = os.getenv("APP_BROWSER_SECRET", "")
if len(BROWSER_SECRET) < 32:
    raise RuntimeError("APP_BROWSER_SECRET must contain at least 32 characters")

BROWSER_COOKIE = "gpt56_browser"
BROWSER_COOKIE_MAX_AGE = 365 * 24 * 60 * 60
app = FastAPI(title="GPT-5.6 Detector", docs_url=None, redoc_url=None)


def sign_browser_id(browser_id: str) -> str:
    signature = hmac.new(
        BROWSER_SECRET.encode(), browser_id.encode(), hashlib.sha256
    ).hexdigest()
    return f"{browser_id}.{signature}"


def browser_id_from_token(token: str | None) -> str | None:
    if not token:
        return None
    try:
        browser_id, signature = token.rsplit(".", 1)
        if UUID(browser_id).hex != browser_id:
            return None
    except (ValueError, AttributeError):
        return None
    expected = hmac.new(
        BROWSER_SECRET.encode(), browser_id.encode(), hashlib.sha256
    ).hexdigest()
    return browser_id if hmac.compare_digest(signature, expected) else None


@app.middleware("http")
async def ensure_browser_identity(request: Request, call_next: Any) -> Any:
    browser_id = browser_id_from_token(request.cookies.get(BROWSER_COOKIE))
    is_new = browser_id is None
    if browser_id is None:
        browser_id = uuid4().hex
    request.state.browser_id = browser_id
    response = await call_next(request)
    if is_new and request.url.path != "/healthz":
        response.set_cookie(
            BROWSER_COOKIE,
            sign_browser_id(browser_id),
            max_age=BROWSER_COOKIE_MAX_AGE,
            httponly=True,
            secure=True,
            samesite="strict",
            path="/",
        )
    return response


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def mask_api_key(value: str) -> str:
    if len(value) > 12:
        return f"{value[:6]}...{value[-6:]}"
    if len(value) <= 3:
        return "..."
    visible = min(3, max(1, (len(value) - 3) // 2))
    return f"{value[:visible]}...{value[-visible:]}"


def metadata_path_for(report_path: Path) -> Path:
    return report_path.with_name(f"{report_path.stem}.meta.json")


def validate_public_https_url(value: str) -> str:
    normalized = value.strip().rstrip("/")
    parsed = parse.urlsplit(normalized)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("API 地址必须是公网 HTTPS URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("API 地址不能包含凭据、查询参数或片段")
    if parsed.port not in (None, 443):
        raise ValueError("API 地址只允许使用 HTTPS 默认端口")

    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
        }
    except socket.gaierror as exc:
        raise ValueError("API 域名无法解析") from exc
    if not addresses:
        raise ValueError("API 域名没有可用地址")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ValueError("API 地址不能解析到内网或保留地址")
    return normalized


class EndpointInput(BaseModel):
    base_url: str = Field(min_length=8, max_length=500)
    claimed_model: Literal["gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"]
    request_model: str = Field(min_length=1, max_length=200)
    api_key: SecretStr


class JobInput(BaseModel):
    preset: Literal["low", "medium", "high"] = "low"
    candidate: EndpointInput


class ModelsInput(BaseModel):
    base_url: str = Field(min_length=8, max_length=500)
    api_key: SecretStr


@dataclass
class Job:
    id: str
    owner_id: str
    status: str
    created_at: str
    config: dict[str, Any]
    started_at: str | None = None
    finished_at: str | None = None
    exit_code: int | None = None
    error: str | None = None
    logs: list[str] = field(default_factory=list)
    report_json: Path | None = None
    report_html: Path | None = None
    process: subprocess.Popen[str] | None = field(default=None, repr=False)

    def append_log(self, line: str) -> None:
        self.logs.append(line.rstrip("\r\n"))
        if len(self.logs) > 3000:
            del self.logs[:500]

    def public(self) -> dict[str, Any]:
        summary: dict[str, Any] | None = None
        if self.report_json and self.report_json.exists():
            try:
                report = json.loads(self.report_json.read_text(encoding="utf-8"))
                combined = report.get("combined_summary") or {
                    "status": report.get("outcome_code"),
                    "title_cn": report.get("title_cn"),
                    "explanation_cn": report.get("subtitle_cn"),
                    "passed_cn": _outcome_label(report.get("outcome_code")),
                }
                summary = {
                    "combined_verdict": report.get("combined_verdict") or report.get("outcome_code"),
                    "combined_summary": combined,
                    "juice_summary": report.get("juice_summary"),
                    "network_summary": report.get("network_summary"),
                    "fingerprint_summary": report.get("fingerprint_summary"),
                    "output_literal_control_summary": report.get(
                        "output_literal_control_summary"
                    ),
                }
            except (OSError, json.JSONDecodeError):
                summary = None
        return {
            "id": self.id,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "exit_code": self.exit_code,
            "error": self.error,
            "config": self.config,
            "summary": summary,
            "has_report": bool(self.report_json and self.report_json.exists()),
        }


class JobManager:
    def __init__(self) -> None:
        self.jobs: dict[str, Job] = {}
        self.active_ids: dict[str, str] = {}
        self.lock = asyncio.Lock()
        self.tasks: set[asyncio.Task[None]] = set()
        self._load_reports()

    def _load_reports(self) -> None:
        loaded_per_owner: dict[str, int] = {}
        for report_path in sorted(REPORT_DIR.glob("*.json"), reverse=True):
            if report_path.name.endswith(".meta.json"):
                continue
            owner_path = report_path.with_suffix(".owner")
            try:
                owner_id = owner_path.read_text(encoding="utf-8").strip()
                if UUID(owner_id).hex != owner_id:
                    continue
                if loaded_per_owner.get(owner_id, 0) >= 100:
                    continue
                report = json.loads(report_path.read_text(encoding="utf-8"))
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            metadata: dict[str, Any] = {}
            try:
                loaded_metadata = json.loads(
                    metadata_path_for(report_path).read_text(encoding="utf-8")
                )
                if isinstance(loaded_metadata, dict):
                    metadata = loaded_metadata
            except (OSError, json.JSONDecodeError):
                pass
            config = report.get("configuration", {})
            candidate = report.get("candidate_configuration_without_key", {})
            job_id = report_path.stem
            created_at = datetime.fromtimestamp(
                report_path.stat().st_mtime, timezone.utc
            ).isoformat()
            self.jobs[job_id] = Job(
                id=job_id,
                owner_id=owner_id,
                status="completed",
                created_at=created_at,
                started_at=created_at,
                finished_at=created_at,
                exit_code=0,
                config={
                    "preset": report.get("preset") or metadata.get("preset"),
                    "mode": config.get("detection_mode", "v4"),
                    "candidate_base_url": candidate.get("base_url") or config.get("candidate_base_url"),
                    "candidate_claimed_model": candidate.get("claimed_model") or candidate.get("model") or config.get("candidate_claimed_model") or config.get("candidate_model"),
                    "candidate_request_model": candidate.get("request_model") or candidate.get("model") or config.get("candidate_request_model") or config.get("candidate_model"),
                    "candidate_api_key_hint": metadata.get(
                        "candidate_api_key_hint"
                    ),
                    "trusted_base_url": config.get("trusted_base_url"),
                    "trusted_model": config.get("trusted_model"),
                    "trusted_api_key_hint": metadata.get("trusted_api_key_hint"),
                    "workers": (report.get("normalized_config") or {}).get("workers") or config.get("single_request_workers"),
                },
                report_json=report_path,
                report_html=report_path.with_suffix(".html"),
            )
            loaded_per_owner[owner_id] = loaded_per_owner.get(owner_id, 0) + 1

    def owned_job(self, job_id: str, owner_id: str) -> Job:
        job = self.jobs.get(job_id)
        if not job or not hmac.compare_digest(job.owner_id, owner_id):
            raise HTTPException(404, "任务不存在")
        return job

    async def start(self, payload: JobInput, owner_id: str) -> Job:
        async with self.lock:
            active_id = self.active_ids.get(owner_id)
            if active_id:
                active = self.jobs.get(active_id)
                if active and active.status in {"queued", "running", "stopping"}:
                    raise HTTPException(409, "已有检测任务正在运行")

            candidate_url = await asyncio.to_thread(
                validate_public_https_url, payload.candidate.base_url
            )
            job_id = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid4().hex[:8]
            config = {
                "mode": "v4",
                "preset": payload.preset,
                "candidate_base_url": candidate_url,
                "candidate_claimed_model": payload.candidate.claimed_model,
                "candidate_request_model": payload.candidate.request_model.strip(),
                "candidate_api_key_hint": mask_api_key(
                    payload.candidate.api_key.get_secret_value()
                ),
            }
            secrets = {
                "candidate": payload.candidate.api_key.get_secret_value(),
            }
            job = Job(
                id=job_id,
                owner_id=owner_id,
                status="queued",
                created_at=utc_now(),
                config=config,
            )
            self.jobs[job_id] = job
            self.active_ids[owner_id] = job_id
            task = asyncio.create_task(self._run(job, secrets))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
            return job

    def _command(self, job: Job, output_path: Path) -> list[str]:
        config = job.config
        command = [
            sys.executable,
            str(PROJECT_DIR / "v4_runner.py"),
            "--base-url",
            config["candidate_base_url"],
            "--claimed-model",
            config["candidate_claimed_model"],
            "--request-model",
            config["candidate_request_model"],
            "--preset",
            config["preset"],
            "--output",
            str(output_path),
            "--run-dir",
            str(REPORT_DIR / "runs" / job.id),
        ]
        return command

    async def _run(self, job: Job, secrets: dict[str, str]) -> None:
        output_path = REPORT_DIR / f"{job.id}.json"
        owner_path = output_path.with_suffix(".owner")
        metadata_path = metadata_path_for(output_path)
        env = os.environ.copy()
        env["CANDIDATE_API_KEY"] = secrets["candidate"]
        command = self._command(job, output_path)
        try:
            owner_path.write_text(job.owner_id, encoding="utf-8")
            owner_path.chmod(0o600)
            metadata_path.write_text(
                json.dumps(
                    {
                        "candidate_api_key_hint": job.config.get(
                            "candidate_api_key_hint"
                        ),
                        "preset": job.config.get("preset"),
                    },
                    ensure_ascii=True,
                ),
                encoding="utf-8",
            )
            metadata_path.chmod(0o600)
            job.status = "running"
            job.started_at = utc_now()
            process = subprocess.Popen(
                command,
                cwd=PROJECT_DIR,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                start_new_session=True,
            )
            job.process = process
            env.pop("CANDIDATE_API_KEY", None)
            secrets.clear()

            assert process.stdout is not None
            while True:
                line = await asyncio.to_thread(process.stdout.readline)
                if line:
                    job.append_log(line)
                    continue
                if process.poll() is not None:
                    break
                await asyncio.sleep(0.05)
            job.exit_code = await asyncio.to_thread(process.wait)
            job.report_json = output_path if output_path.exists() else None
            html_path = output_path.with_suffix(".html")
            job.report_html = html_path if html_path.exists() else None
            if job.status == "stopping" or job.exit_code == 130:
                job.status = "stopped"
            elif job.report_json:
                job.status = "completed"
            else:
                job.status = "failed"
                job.error = f"检测器退出，未生成报告（退出码 {job.exit_code}）"
        except Exception as exc:
            job.status = "failed"
            job.error = str(exc)
            job.append_log(f"Web 服务错误：{exc}")
        finally:
            secrets.clear()
            env.pop("CANDIDATE_API_KEY", None)
            job.process = None
            job.finished_at = utc_now()
            if not job.report_json:
                for sidecar_path in (owner_path, metadata_path):
                    try:
                        sidecar_path.unlink(missing_ok=True)
                    except OSError:
                        pass
            async with self.lock:
                if self.active_ids.get(job.owner_id) == job.id:
                    self.active_ids.pop(job.owner_id, None)

    async def stop(self, job_id: str, owner_id: str) -> Job:
        job = self.owned_job(job_id, owner_id)
        if job.status not in {"queued", "running"} or not job.process:
            raise HTTPException(409, "任务当前不能停止")
        job.status = "stopping"
        try:
            os.killpg(job.process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        return job


manager = JobManager()


def _outcome_label(outcome: Any) -> str:
    value = str(outcome or "")
    if value == "possible_non_gpt" or "mismatch" in value:
        return "异常"
    if "pass" in value:
        return "通过"
    if "insufficient" in value or "unclear" in value:
        return "证据不足"
    return "未知"


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def fetch_models(base_url: str, api_key: str) -> list[str]:
    endpoint = base_url.rstrip("/") + "/models"
    req = request.Request(
        endpoint,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
            "User-Agent": "gpt56-detector-web/1.0",
        },
    )
    opener = request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=30) as response:
            payload = json.load(response)
    except error.HTTPError as exc:
        raise ValueError(f"模型列表请求失败：HTTP {exc.code}") from exc
    except (error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise ValueError("模型列表请求失败或返回格式无效") from exc
    data = payload.get("data", []) if isinstance(payload, dict) else []
    return sorted(
        {
            str(item.get("id"))
            for item in data
            if isinstance(item, dict) and item.get("id")
        }
    )


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/assets/{filename}")
async def asset(filename: str) -> FileResponse:
    if filename not in {
        "styles.css",
        "app.js",
        "favicon.svg",
    }:
        raise HTTPException(404)
    return FileResponse(STATIC_DIR / filename)


@app.post("/api/models")
async def list_models(payload: ModelsInput) -> dict[str, Any]:
    try:
        base_url = await asyncio.to_thread(validate_public_https_url, payload.base_url)
        models = await asyncio.to_thread(
            fetch_models, base_url, payload.api_key.get_secret_value()
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"models": models}


@app.get("/api/jobs")
async def list_jobs(request: Request) -> dict[str, Any]:
    owner_id = request.state.browser_id
    jobs = sorted(
        (job for job in manager.jobs.values() if job.owner_id == owner_id),
        key=lambda item: item.created_at,
        reverse=True,
    )
    return {
        "jobs": [job.public() for job in jobs[:100]],
        "active_id": manager.active_ids.get(owner_id),
    }


@app.post("/api/jobs", status_code=202)
async def create_job(payload: JobInput, request: Request) -> dict[str, Any]:
    try:
        job = await manager.start(payload, request.state.browser_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return job.public()


@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str, request: Request) -> dict[str, Any]:
    job = manager.owned_job(job_id, request.state.browser_id)
    return job.public()


@app.get("/api/jobs/{job_id}/logs")
async def get_logs(job_id: str, request: Request, offset: int = 0) -> dict[str, Any]:
    job = manager.owned_job(job_id, request.state.browser_id)
    safe_offset = max(0, min(offset, len(job.logs)))
    return {"lines": job.logs[safe_offset:], "next_offset": len(job.logs)}


@app.post("/api/jobs/{job_id}/stop", status_code=202)
async def stop_job(job_id: str, request: Request) -> dict[str, Any]:
    job = await manager.stop(job_id, request.state.browser_id)
    return job.public()


@app.get("/api/jobs/{job_id}/report.html")
async def report_html(job_id: str, request: Request) -> FileResponse:
    job = manager.owned_job(job_id, request.state.browser_id)
    if not job.report_html or not job.report_html.exists():
        raise HTTPException(404, "HTML 报告不存在")
    return FileResponse(job.report_html, media_type="text/html")


@app.get("/api/jobs/{job_id}/report.json")
async def report_json(job_id: str, request: Request) -> FileResponse:
    job = manager.owned_job(job_id, request.state.browser_id)
    if not job.report_json or not job.report_json.exists():
        raise HTTPException(404, "JSON 报告不存在")
    return FileResponse(
        job.report_json,
        media_type="application/json",
        filename=job.report_json.name,
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(_: Any, exc: HTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=exc.headers,
    )
