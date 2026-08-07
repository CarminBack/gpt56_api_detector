from __future__ import annotations

import asyncio
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
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field, SecretStr, model_validator


APP_DIR = Path(__file__).resolve().parent
PROJECT_DIR = APP_DIR.parent
STATIC_DIR = APP_DIR / "static"
REPORT_DIR = Path(os.getenv("REPORT_DIR", PROJECT_DIR / "reports")).resolve()
REPORT_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="GPT-5.6 Detector", docs_url=None, redoc_url=None)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    model: str = Field(min_length=1, max_length=200)
    api_key: SecretStr


class JobInput(BaseModel):
    mode: Literal["juice", "cot"] = "juice"
    candidate: EndpointInput
    trusted: EndpointInput | None = None
    workers: int = Field(default=4, ge=1, le=8)
    trials: int = Field(default=20, ge=4, le=20)
    juice_repeats: int = Field(default=3, ge=1, le=5)

    @model_validator(mode="after")
    def trusted_required_for_cot(self) -> "JobInput":
        if self.mode == "cot" and self.trusted is None:
            raise ValueError("COT 模式需要可信参照端")
        return self


class ModelsInput(BaseModel):
    base_url: str = Field(min_length=8, max_length=500)
    api_key: SecretStr


@dataclass
class Job:
    id: str
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
                summary = {
                    "combined_verdict": report.get("combined_verdict"),
                    "combined_summary": report.get("combined_summary"),
                    "juice_summary": report.get("juice_summary"),
                    "network_summary": report.get("network_summary"),
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
        self.active_id: str | None = None
        self.lock = asyncio.Lock()
        self.tasks: set[asyncio.Task[None]] = set()
        self._load_reports()

    def _load_reports(self) -> None:
        for report_path in sorted(REPORT_DIR.glob("*.json"), reverse=True)[:100]:
            try:
                report = json.loads(report_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            config = report.get("configuration", {})
            job_id = report_path.stem
            created_at = datetime.fromtimestamp(
                report_path.stat().st_mtime, timezone.utc
            ).isoformat()
            self.jobs[job_id] = Job(
                id=job_id,
                status="completed",
                created_at=created_at,
                started_at=created_at,
                finished_at=created_at,
                exit_code=0,
                config={
                    "mode": config.get("detection_mode", "unknown"),
                    "candidate_base_url": config.get("candidate_base_url"),
                    "candidate_model": config.get("candidate_model"),
                    "trusted_base_url": config.get("trusted_base_url"),
                    "trusted_model": config.get("trusted_model"),
                    "workers": config.get("single_request_workers"),
                },
                report_json=report_path,
                report_html=report_path.with_suffix(".html"),
            )

    async def start(self, payload: JobInput) -> Job:
        async with self.lock:
            if self.active_id:
                active = self.jobs.get(self.active_id)
                if active and active.status in {"queued", "running", "stopping"}:
                    raise HTTPException(409, "已有检测任务正在运行")

            candidate_url = await asyncio.to_thread(
                validate_public_https_url, payload.candidate.base_url
            )
            trusted_url = None
            if payload.trusted:
                trusted_url = await asyncio.to_thread(
                    validate_public_https_url, payload.trusted.base_url
                )

            job_id = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid4().hex[:8]
            config = {
                "mode": payload.mode,
                "candidate_base_url": candidate_url,
                "candidate_model": payload.candidate.model.strip(),
                "trusted_base_url": trusted_url,
                "trusted_model": payload.trusted.model.strip() if payload.trusted else None,
                "workers": payload.workers,
                "trials": payload.trials,
                "juice_repeats": payload.juice_repeats,
            }
            secrets = {
                "candidate": payload.candidate.api_key.get_secret_value(),
                "trusted": (
                    payload.trusted.api_key.get_secret_value() if payload.trusted else ""
                ),
            }
            job = Job(id=job_id, status="queued", created_at=utc_now(), config=config)
            self.jobs[job_id] = job
            self.active_id = job_id
            task = asyncio.create_task(self._run(job, secrets))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
            return job

    def _command(self, job: Job, output_path: Path) -> list[str]:
        config = job.config
        command = [
            sys.executable,
            str(PROJECT_DIR / "gpt56_reasoning_probe.py"),
            "--candidate-base-url",
            config["candidate_base_url"],
            "--candidate-model",
            config["candidate_model"],
            "--workers",
            str(config["workers"]),
            "--juice-repeats",
            str(config["juice_repeats"]),
            "--output",
            str(output_path),
        ]
        if config["mode"] == "juice":
            command.append("--juice-only")
        else:
            command.extend(
                [
                    "--trusted-base-url",
                    config["trusted_base_url"],
                    "--trusted-model",
                    config["trusted_model"],
                    "--trials",
                    str(config["trials"]),
                ]
            )
        return command

    async def _run(self, job: Job, secrets: dict[str, str]) -> None:
        output_path = REPORT_DIR / f"{job.id}.json"
        env = os.environ.copy()
        env["CANDIDATE_API_KEY"] = secrets["candidate"]
        if secrets["trusted"]:
            env["TRUSTED_API_KEY"] = secrets["trusted"]
        command = self._command(job, output_path)
        try:
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
            env.pop("TRUSTED_API_KEY", None)
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
            if job.status == "stopping":
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
            env.pop("TRUSTED_API_KEY", None)
            job.process = None
            job.finished_at = utc_now()
            async with self.lock:
                if self.active_id == job.id:
                    self.active_id = None

    async def stop(self, job_id: str) -> Job:
        job = self.jobs.get(job_id)
        if not job:
            raise HTTPException(404, "任务不存在")
        if job.status not in {"queued", "running"} or not job.process:
            raise HTTPException(409, "任务当前不能停止")
        job.status = "stopping"
        try:
            os.killpg(job.process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        return job


manager = JobManager()


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
async def list_jobs() -> dict[str, Any]:
    jobs = sorted(manager.jobs.values(), key=lambda item: item.created_at, reverse=True)
    return {"jobs": [job.public() for job in jobs[:100]], "active_id": manager.active_id}


@app.post("/api/jobs", status_code=202)
async def create_job(payload: JobInput) -> dict[str, Any]:
    try:
        job = await manager.start(payload)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return job.public()


@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str) -> dict[str, Any]:
    job = manager.jobs.get(job_id)
    if not job:
        raise HTTPException(404, "任务不存在")
    return job.public()


@app.get("/api/jobs/{job_id}/logs")
async def get_logs(job_id: str, offset: int = 0) -> dict[str, Any]:
    job = manager.jobs.get(job_id)
    if not job:
        raise HTTPException(404, "任务不存在")
    safe_offset = max(0, min(offset, len(job.logs)))
    return {"lines": job.logs[safe_offset:], "next_offset": len(job.logs)}


@app.post("/api/jobs/{job_id}/stop", status_code=202)
async def stop_job(job_id: str) -> dict[str, Any]:
    job = await manager.stop(job_id)
    return job.public()


@app.get("/api/jobs/{job_id}/report.html")
async def report_html(job_id: str) -> FileResponse:
    job = manager.jobs.get(job_id)
    if not job or not job.report_html or not job.report_html.exists():
        raise HTTPException(404, "HTML 报告不存在")
    return FileResponse(job.report_html, media_type="text/html")


@app.get("/api/jobs/{job_id}/report.json")
async def report_json(job_id: str) -> FileResponse:
    job = manager.jobs.get(job_id)
    if not job or not job.report_json or not job.report_json.exists():
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
