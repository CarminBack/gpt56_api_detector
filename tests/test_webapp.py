import asyncio
import json
import os
from pathlib import Path
import sys
from uuid import uuid4

os.environ.setdefault("APP_BROWSER_SECRET", "test-browser-secret-with-at-least-32-characters")
os.environ.setdefault("REPORT_DIR", "/tmp/gpt56-detector-test-reports")

from fastapi import HTTPException
from fastapi.testclient import TestClient
import pytest

import webapp.main as main_module
from webapp.main import (
    BROWSER_COOKIE,
    REPORT_DIR,
    Job,
    JobInput,
    JobManager,
    app,
    browser_id_from_token,
    manager,
    mask_api_key,
    validate_public_https_url,
)


client = TestClient(app, base_url="https://testserver")


def test_health_check_does_not_require_auth() -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_dashboard_and_api_require_no_authentication() -> None:
    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert "GPT-5.6 路由检测" in dashboard.text
    cookie = dashboard.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "secure" in cookie
    assert "samesite=strict" in cookie

    jobs = client.get("/api/jobs")
    assert jobs.status_code == 200

    login = client.get("/login")
    assert login.status_code == 404


def test_browser_histories_and_job_access_are_isolated() -> None:
    with (
        TestClient(app, base_url="https://testserver") as browser_a,
        TestClient(app, base_url="https://testserver") as browser_b,
    ):
        browser_a.get("/")
        browser_b.get("/")
        owner_a = browser_id_from_token(browser_a.cookies.get(BROWSER_COOKIE))
        owner_b = browser_id_from_token(browser_b.cookies.get(BROWSER_COOKIE))
        assert owner_a and owner_b and owner_a != owner_b

        job_a = make_job("browser-a", owner_a, status="running")
        job_b = make_job("browser-b", owner_b, status="running")
        report_a = REPORT_DIR / f"{job_a.id}.json"
        report_b = REPORT_DIR / f"{job_b.id}.json"
        report_a.write_text('{"combined_verdict":"a"}', encoding="utf-8")
        report_b.write_text('{"combined_verdict":"b"}', encoding="utf-8")
        job_a.report_json = report_a
        job_b.report_json = report_b
        manager.jobs[job_a.id] = job_a
        manager.jobs[job_b.id] = job_b
        manager.active_ids[owner_a] = job_a.id
        manager.active_ids[owner_b] = job_b.id
        try:
            jobs_a = browser_a.get("/api/jobs").json()
            jobs_b = browser_b.get("/api/jobs").json()
            assert [job["id"] for job in jobs_a["jobs"]] == [job_a.id]
            assert [job["id"] for job in jobs_b["jobs"]] == [job_b.id]
            assert "owner_id" not in jobs_a["jobs"][0]
            assert "owner_id" not in jobs_b["jobs"][0]
            assert (
                jobs_a["jobs"][0]["config"]["candidate_base_url"]
                == "https://api.example.com/v1"
            )
            assert (
                jobs_a["jobs"][0]["config"]["candidate_api_key_hint"]
                == "sk-exa...secret"
            )
            assert jobs_a["active_id"] == job_a.id
            assert jobs_b["active_id"] == job_b.id

            assert browser_a.get(f"/api/jobs/{job_b.id}").status_code == 404
            assert browser_a.get(f"/api/jobs/{job_b.id}/logs").status_code == 404
            assert browser_a.post(f"/api/jobs/{job_b.id}/stop").status_code == 404
            assert browser_a.get(f"/api/jobs/{job_b.id}/report.json").status_code == 404
            assert browser_a.get(f"/api/jobs/{job_a.id}/report.json").status_code == 200
            assert browser_b.get(f"/api/jobs/{job_b.id}/report.json").status_code == 200
        finally:
            manager.jobs.pop(job_a.id, None)
            manager.jobs.pop(job_b.id, None)
            manager.active_ids.pop(owner_a, None)
            manager.active_ids.pop(owner_b, None)
            report_a.unlink(missing_ok=True)
            report_b.unlink(missing_ok=True)


def test_different_browsers_can_start_jobs_concurrently(monkeypatch) -> None:
    job_manager = JobManager()
    payload = JobInput(
        candidate={
            "base_url": "https://api.example.com/v1",
            "model": "gpt-5.6-sol",
            "api_key": "sk-test",
        }
    )

    async def fake_run(_: Job, secrets: dict[str, str]) -> None:
        secrets.clear()

    monkeypatch.setattr(main_module, "validate_public_https_url", lambda value: value)
    monkeypatch.setattr(job_manager, "_run", fake_run)

    async def scenario() -> None:
        first = await job_manager.start(payload, "a" * 32)
        second = await job_manager.start(payload, "b" * 32)
        assert first.id != second.id
        assert first.config["candidate_api_key_hint"] == mask_api_key("sk-test")
        assert "sk-test" not in json.dumps(first.public())
        assert job_manager.active_ids["a" * 32] == first.id
        assert job_manager.active_ids["b" * 32] == second.id
        with pytest.raises(HTTPException) as exc_info:
            await job_manager.start(payload, "a" * 32)
        assert exc_info.value.status_code == 409
        await asyncio.gather(*list(job_manager.tasks))

    asyncio.run(scenario())


def test_dashboard_has_visible_model_selectors() -> None:
    dashboard = client.get("/")
    assert 'id="candidate-model-select"' in dashboard.text
    assert 'data-preset="low"' in dashboard.text
    assert 'data-preset="medium"' in dashboard.text
    assert 'data-preset="high"' in dashboard.text
    assert "<datalist" not in dashboard.text


def test_api_key_masking_never_returns_the_complete_key() -> None:
    api_key = "test-api-key-1234567890abcdef"
    assert mask_api_key(api_key) == f"{api_key[:6]}...{api_key[-6:]}"
    for short_key in ("a", "sk-test", "123456789012"):
        assert mask_api_key(short_key) != short_key


def test_start_job_keeps_api_key_inputs() -> None:
    script = (main_module.STATIC_DIR / "app.js").read_text(encoding="utf-8")
    assert 'el("candidate-key").value = ""' not in script
    assert 'el("trusted-key").value = ""' not in script


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
        owner_id="a" * 32,
        status="queued",
        created_at="2026-08-07T00:00:00+00:00",
        config={
            "mode": "v4",
            "preset": "low",
            "candidate_base_url": "https://api.example.com/v1",
            "candidate_model": "gpt-5.6-sol",
            "candidate_api_key_hint": "sk-tes...secret",
        },
    )
    command = manager._command(job, tmp_path / "report.json")
    assert command[command.index("--preset") + 1] == "low"
    assert command[1].endswith("v4_runner.py")
    assert not any(part.startswith("sk-") for part in command)


def test_job_process_completes_when_report_exists(monkeypatch) -> None:
    manager = JobManager()
    job = Job(
        id="fake-process-job",
        owner_id="a" * 32,
        status="queued",
        created_at="2026-08-07T00:00:00+00:00",
        config={
            "mode": "v4",
            "preset": "low",
            "candidate_base_url": "https://api.example.com/v1",
            "candidate_model": "gpt-5.6-sol",
            "candidate_api_key_hint": "sk-tes...secret",
        },
    )
    manager.jobs[job.id] = job
    manager.active_ids[job.owner_id] = job.id

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
    complete_key = "sk-test-complete-secret"
    asyncio.run(manager._run(job, {"candidate": complete_key}))

    assert job.status == "completed"
    assert job.report_json and job.report_json.exists()
    assert "fake detector complete" in job.logs
    owner_path = job.report_json.with_suffix(".owner")
    metadata_path = job.report_json.with_name(f"{job.id}.meta.json")
    assert owner_path.read_text(encoding="utf-8") == job.owner_id
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata == {
        "candidate_api_key_hint": "sk-tes...secret",
        "preset": "low",
    }
    assert complete_key not in metadata_path.read_text(encoding="utf-8")
    reloaded = JobManager()
    assert reloaded.jobs[job.id].owner_id == job.owner_id
    assert (
        reloaded.jobs[job.id].config["candidate_api_key_hint"]
        == "sk-tes...secret"
    )
    job.report_json.unlink(missing_ok=True)
    job.report_html.unlink(missing_ok=True)
    owner_path.unlink(missing_ok=True)
    metadata_path.unlink(missing_ok=True)


def make_job(job_id: str, owner_id: str, status: str = "completed") -> Job:
    return Job(
        id=f"{job_id}-{uuid4().hex[:8]}",
        owner_id=owner_id,
        status=status,
        created_at="2026-08-07T00:00:00+00:00",
        config={
            "mode": "v4",
            "preset": "low",
            "candidate_base_url": "https://api.example.com/v1",
            "candidate_model": "gpt-5.6-sol",
            "candidate_api_key_hint": "sk-exa...secret",
        },
    )
