import asyncio
import json

import httpx
import pytest

from telegram_bot import (
    BotConfig,
    CheckRequest,
    DetectorClient,
    RequestParseError,
    build_user_mention,
    format_model_result,
    message_targets_bot,
    chat_is_allowed,
    parse_chat_ids,
    parse_check_request,
)


def test_parse_message_with_mention_and_labels() -> None:
    parsed = parse_check_request(
        "检测\n地址: https://api.example.com/v1\n密钥: sk-test", "detector_bot"
    )
    assert parsed == CheckRequest("https://api.example.com/v1", "sk-test")


def test_parse_message_strips_command_and_url_punctuation() -> None:
    parsed = parse_check_request(
        "/check@detector_bot https://api.example.com/v1, sk-test", "detector_bot"
    )
    assert parsed.base_url == "https://api.example.com/v1"
    assert parsed.api_key == "sk-test"


def test_parse_message_requires_one_key() -> None:
    with pytest.raises(RequestParseError):
        parse_check_request("@detector_bot https://api.example.com/v1", "detector_bot")
    with pytest.raises(RequestParseError):
        parse_check_request(
            "@detector_bot https://api.example.com/v1 key-a key-b", "detector_bot"
        )


def test_group_requires_mention_but_private_chat_does_not() -> None:
    assert message_targets_bot("@detector_bot https://x.test key", "group", "detector_bot")
    assert not message_targets_bot("https://x.test key", "group", "detector_bot")
    assert message_targets_bot("https://x.test key", "private", "detector_bot")


def test_chat_allowlist_accepts_negative_group_ids() -> None:
    allowed = parse_chat_ids("-100123, 42")
    assert allowed == frozenset({-100123, 42})
    assert chat_is_allowed(-100123, allowed)
    assert not chat_is_allowed(-100999, allowed)
    assert chat_is_allowed(-100999, frozenset())


def test_chat_allowlist_rejects_invalid_ids() -> None:
    with pytest.raises(RuntimeError):
        parse_chat_ids("-100123,not-a-chat")


def test_user_mention_is_html_escaped() -> None:
    class User:
        id = 42
        full_name = "A <B>"

    assert build_user_mention(User()) == '<a href="tg://user?id=42">A &lt;B&gt;</a>'


def test_model_result_does_not_include_raw_report_details() -> None:
    result = format_model_result(
        "gpt-5.6-sol",
        {
            "combined_summary": {
                "title_cn": "综合检测通过",
                "passed_cn": "通过",
                "explanation_cn": "线路流畅",
            },
            "juice_summary": {
                "likely_model_cn": "GPT-5.6 Sol",
                "confidence": "high",
            },
            "network_summary": {"title_cn": "流畅"},
            "candidate_api_key": "must-not-be-rendered",
        },
    )
    assert "GPT-5.6 Sol" in result
    assert "must-not-be-rendered" not in result


def test_detector_client_polls_and_fetches_report() -> None:
    calls: list[str] = []
    submitted_jobs: list[dict] = []
    statuses = iter(("running", "completed"))

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.method == "POST":
            submitted_jobs.append(json.loads(request.read()))
            return httpx.Response(202, json={"id": "job-1"})
        if request.url.path == "/api/jobs/job-1":
            return httpx.Response(200, json={"status": next(statuses)})
        return httpx.Response(200, json={"combined_summary": {"passed_cn": "通过"}})

    async def scenario() -> dict:
        transport = httpx.MockTransport(handler)
        http_client = httpx.AsyncClient(transport=transport, base_url="https://detector.test")
        config = BotConfig("token", "https://detector.test", poll_interval_seconds=0.01, job_timeout_seconds=1)
        client = DetectorClient(config, http_client)
        try:
            return await client.run_model(CheckRequest("https://api.example.com/v1", "secret"), "gpt-5.6-sol")
        finally:
            await http_client.aclose()

    report = asyncio.run(scenario())
    assert report["combined_summary"]["passed_cn"] == "通过"
    assert submitted_jobs[0]["preset"] == "medium"
    assert submitted_jobs[0]["candidate"]["claimed_model"] == "gpt-5.6-sol"
    assert submitted_jobs[0]["candidate"]["request_model"] == "gpt-5.6-sol"
    assert calls == ["/api/jobs", "/api/jobs/job-1", "/api/jobs/job-1", "/api/jobs/job-1/report.json"]
