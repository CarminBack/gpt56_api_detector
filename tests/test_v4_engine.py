from pathlib import Path
import threading

from gpt56_vnext.detector import DetectorSession
from gpt56_vnext.presets import get_preset


def test_v4_low_preset_builds_schema3_report(tmp_path: Path) -> None:
    session = DetectorSession(
        base_url="https://api.example.com/v1",
        model="gpt-5.6-sol",
        api_key="test-key",
        config=get_preset("single", "low"),
        directory=tmp_path / "run",
    )

    def requester(job: dict) -> dict:
        probe_id = job["probe_id"]
        if probe_id == "output_luna_48":
            answer = "48"
        elif probe_id == "output_terra_32":
            answer = "32"
        elif probe_id == "juice_coverage":
            answer = str(job["synthetic_value"])
        elif job["effort"] == "low":
            answer = "8"
        else:
            answer = "40855"
        return {"answer": answer, "streaming": True, "http_status": 200}

    try:
        report = session.run_single(requester=requester)
    finally:
        session.close()

    assert report["schema_version"] == 3
    assert report["preset"] == "low"
    assert report["official"] is True
    assert report["outcome_code"] == "juice_pass_fingerprint_unclear"
    assert report["network_summary"]["logical_tasks"] == 14
    assert report["network_summary"]["final_errors"] == 0
    assert report["auth_values_persisted"] is False


def test_v4_stop_cancels_remaining_jobs_and_keeps_report(tmp_path: Path) -> None:
    session = DetectorSession(
        base_url="https://api.example.com/v1",
        model="gpt-5.6-sol",
        api_key="test-key",
        config=get_preset("single", "low"),
        directory=tmp_path / "stopped-run",
    )
    started = threading.Event()
    release = threading.Event()

    def requester(_job: dict) -> dict:
        started.set()
        release.wait(timeout=2)
        return {"answer": "40855", "streaming": True, "http_status": 200}

    result: dict = {}

    def run() -> None:
        result.update(session.run_single(requester=requester))

    worker = threading.Thread(target=run)
    worker.start()
    assert started.wait(timeout=2)
    stop = session.stop()
    release.set()
    worker.join(timeout=5)
    try:
        assert not worker.is_alive()
        assert stop["accepted"] is True
        assert result["run_stopped"] is True
        assert result["network_summary"]["cancelled"] > 0
    finally:
        session.close()
