import asyncio
import os
from pathlib import Path
import sys

os.environ.setdefault("APP_USERNAME", "tester")
os.environ.setdefault("APP_PASSWORD", "test-password")
os.environ.setdefault("REPORT_DIR", "/tmp/gpt56-detector-test-reports")

from fastapi.testclient import TestClient

from webapp.main import Job, JobManager, app, validate_public_https_url


client = TestClient(app)
AUTH = ("tester", "test-password")


def test_health_check_does_not_require_auth() -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_dashboard_requires_basic_auth() -> None:
    unauthorized = client.get("/")
    assert unauthorized.status_code == 401
    assert unauthorized.headers["www-authenticate"] == "Basic"

    authorized = client.get("/", auth=AUTH)
    assert authorized.status_code == 200
    assert "GPT-5.6 路由检测" in authorized.text


def test_private_or_non_https_targets_are_rejected() -> None:
    for value in (
        "http://api.example.com/v1",
        "https://127.0.0.1/v1",
        "https://localhost/v1",
        "https://user:pass@example.com/v1",
    ):
        try:
            validate_public_https_url(value)
        except ValueError:
            pass
        else:
            raise AssertionError(f"unsafe URL accepted: {value}")


def test_detector_command_contains_no_api_keys(tmp_path) -> None:
    manager = JobManager()
    job = Job(
        id="test",
        status="queued",
        created_at="2026-08-07T00:00:00+00:00",
        config={
            "mode": "juice",
            "candidate_base_url": "https://api.example.com/v1",
            "candidate_model": "gpt-5.6-sol",
            "trusted_base_url": None,
            "trusted_model": None,
            "workers": 4,
            "trials": 20,
            "juice_repeats": 3,
        },
    )
    command = manager._command(job, tmp_path / "report.json")
    assert "--juice-only" in command
    assert not any(part.startswith("sk-") for part in command)


def test_job_process_completes_when_report_exists(monkeypatch) -> None:
    manager = JobManager()
    job = Job(
        id="fake-process-job",
        status="queued",
        created_at="2026-08-07T00:00:00+00:00",
        config={
            "mode": "juice",
            "candidate_base_url": "https://api.example.com/v1",
            "candidate_model": "gpt-5.6-sol",
            "trusted_base_url": None,
            "trusted_model": None,
            "workers": 1,
            "trials": 4,
            "juice_repeats": 1,
        },
    )
    manager.jobs[job.id] = job
    manager.active_id = job.id

    def fake_command(_: Job, output_path: Path) -> list[str]:
        code = (
            "from pathlib import Path; import json; "
            f"p=Path({str(output_path)!r}); "
            "p.write_text(json.dumps({'combined_verdict':'test'})); "
            "p.with_suffix('.html').write_text('<html></html>'); "
            "print('fake detector complete')"
        )
        return [sys.executable, "-c", code]

    monkeypatch.setattr(manager, "_command", fake_command)
    asyncio.run(manager._run(job, {"candidate": "sk-test", "trusted": ""}))

    assert job.status == "completed"
    assert job.report_json and job.report_json.exists()
    assert "fake detector complete" in job.logs
    job.report_json.unlink(missing_ok=True)
    job.report_html.unlink(missing_ok=True)
