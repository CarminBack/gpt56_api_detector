"""Telegram adapter for the public GPT-5.6 detector service.

The bot accepts a message containing an API URL and key, submits one
Juice-only job for each supported GPT-5.6 variant, and replies with the
sanitized report summaries. Credentials stay in the detector request body and
are never included in logs or Telegram messages.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import html
import logging
import os
import re
import time
from typing import Any
from urllib.parse import urlsplit

import httpx


LOGGER = logging.getLogger(__name__)
MODEL_TESTS = ("gpt-5.6-sol", "gpt-5.6-terra")
URL_RE = re.compile(r"https://[^\s<>\"']+", re.IGNORECASE)
BOT_MENTION_RE = re.compile(r"@[A-Za-z0-9_]{5,32}")
IGNORED_LABEL_RE = re.compile(
    r"(?<!\S)(?:url|地址|key|api[-_ ]?key|密钥|检测)\s*[:：=]?",
    re.IGNORECASE,
)


class RequestParseError(ValueError):
    """The Telegram message does not contain exactly one URL and key."""


class DetectorError(RuntimeError):
    """The detector service rejected or failed to complete a job."""


@dataclass(frozen=True)
class CheckRequest:
    base_url: str
    api_key: str


@dataclass(frozen=True)
class BotConfig:
    telegram_token: str
    detector_api_url: str = "https://check.mewinyou.shop"
    poll_interval_seconds: float = 3.0
    job_timeout_seconds: float = 30 * 60
    max_concurrent_checks: int = 2
    allowed_chat_ids: frozenset[int] = frozenset()

    @classmethod
    def from_env(cls) -> "BotConfig":
        token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        if not token:
            raise RuntimeError("TELEGRAM_BOT_TOKEN is required")
        detector_url = os.getenv(
            "DETECTOR_API_URL", "https://check.mewinyou.shop"
        ).strip().rstrip("/")
        parsed = urlsplit(detector_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise RuntimeError("DETECTOR_API_URL must be an HTTPS URL without credentials")
        return cls(
            telegram_token=token,
            detector_api_url=detector_url,
            poll_interval_seconds=_env_float(
                "BOT_POLL_INTERVAL_SECONDS", 3.0, minimum=0.5, maximum=30
            ),
            job_timeout_seconds=_env_float(
                "BOT_JOB_TIMEOUT_SECONDS", 30 * 60, minimum=60, maximum=4 * 60 * 60
            ),
            max_concurrent_checks=_env_int(
                "BOT_MAX_CONCURRENT_CHECKS", 2, minimum=1, maximum=8
            ),
            allowed_chat_ids=parse_chat_ids(os.getenv("TELEGRAM_ALLOWED_CHAT_IDS", "")),
        )


def _env_float(name: str, default: float, *, minimum: float, maximum: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a number") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}")
    return value


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}")
    return value


def parse_chat_ids(value: str) -> frozenset[int]:
    """Parse a comma-separated Telegram chat ID allowlist."""

    chat_ids: set[int] = set()
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            chat_ids.add(int(item))
        except ValueError as exc:
            raise RuntimeError("TELEGRAM_ALLOWED_CHAT_IDS must contain numeric chat IDs") from exc
    return frozenset(chat_ids)


def chat_is_allowed(chat_id: int | None, allowed_chat_ids: frozenset[int]) -> bool:
    """An empty allowlist keeps backwards-compatible unrestricted behavior."""

    return not allowed_chat_ids or (chat_id is not None and chat_id in allowed_chat_ids)


def _strip_trailing_url_punctuation(value: str) -> str:
    return value.rstrip(".,，。;；:：)>]}")


def parse_check_request(text: str, bot_username: str | None = None) -> CheckRequest:
    """Parse a message containing one HTTPS API URL and one API key."""

    if not text or any(ord(char) < 32 and char not in "\r\n\t" for char in text):
        raise RequestParseError("消息格式无效")
    cleaned = text
    if bot_username:
        cleaned = re.sub(
            rf"@{re.escape(bot_username.lstrip('@'))}\b", " ", cleaned, flags=re.IGNORECASE
        )
    cleaned = re.sub(r"/(?:check|start)(?:@[A-Za-z0-9_]{5,32})?\b", " ", cleaned, flags=re.IGNORECASE)
    match = URL_RE.search(cleaned)
    if not match:
        raise RequestParseError("请发送一个 HTTPS API 地址和一个 API 密钥")
    base_url = _strip_trailing_url_punctuation(match.group(0))
    remaining = f"{cleaned[:match.start()]} {cleaned[match.end():]}"
    remaining = IGNORED_LABEL_RE.sub(" ", remaining)
    tokens = [
        token.strip("\"'`()[]{}<>，。,;；")
        for token in re.split(r"\s+", remaining)
        if token.strip()
    ]
    tokens = [token for token in tokens if token and not BOT_MENTION_RE.fullmatch(token)]
    if len(tokens) != 1:
        raise RequestParseError("格式应为：@机器人 https://你的接口/v1 你的API密钥")
    api_key = tokens[0]
    if len(api_key) > 1000 or any(ord(char) < 32 for char in api_key):
        raise RequestParseError("API 密钥格式无效")
    return CheckRequest(base_url=base_url, api_key=api_key)


def message_targets_bot(text: str, chat_type: str | None, bot_username: str | None) -> bool:
    """Require an explicit mention in groups while allowing private chats."""

    if chat_type == "private":
        return True
    if not bot_username:
        return False
    return bool(
        re.search(rf"@{re.escape(bot_username.lstrip('@'))}\b", text, re.IGNORECASE)
        or re.match(r"\s*/check(?:@[A-Za-z0-9_]{5,32})?\b", text, re.IGNORECASE)
    )


def build_user_mention(user: Any) -> str:
    name = html.escape(str(getattr(user, "full_name", None) or "用户"))
    user_id = getattr(user, "id", None)
    if user_id is None:
        return name
    return f'<a href="tg://user?id={int(user_id)}">{name}</a>'


def format_model_result(model: str, report: dict[str, Any]) -> str:
    combined = report.get("combined_summary") or report
    juice = report.get("juice_summary") or {}
    fingerprint = report.get("fingerprint_summary") or {}
    network = report.get("network_summary") or {}
    title = html.escape(str(combined.get("title_cn") or "检测完成"))
    likely = html.escape(str(
        fingerprint.get("fingerprint_model")
        or juice.get("likely_model_cn")
        or "证据不明确"
    ))
    fingerprint_state = (
        "强指向" if fingerprint.get("fingerprint_status") == "strong_match"
        else html.escape(str(juice.get("confidence") or "参考"))
    )
    network_title = (
        f"{network.get('successful', 0)} 成功 / {network.get('final_errors', 0)} 错误"
        if "successful" in network or "final_errors" in network
        else html.escape(str(network.get("title_cn") or "未知"))
    )
    explanation = html.escape(str(
        combined.get("subtitle_cn")
        or combined.get("explanation_cn")
        or "暂无详细说明"
    ))
    return (
        f"<b>{html.escape(model)}</b>：{title}\n"
        f"指纹：{likely}（{fingerprint_state}）\n"
        f"线路：{network_title}\n{explanation}"
    )


class DetectorClient:
    def __init__(self, config: BotConfig, client: httpx.AsyncClient | None = None) -> None:
        self.config = config
        self.client = client or httpx.AsyncClient(
            base_url=config.detector_api_url,
            headers={"Accept": "application/json", "User-Agent": "gpt56-telegram-bot/1.0"},
            follow_redirects=False,
            timeout=httpx.Timeout(30.0),
        )
        self._owns_client = client is None

    async def close(self) -> None:
        if self._owns_client:
            await self.client.aclose()

    async def _json(self, response: httpx.Response) -> dict[str, Any]:
        if response.status_code >= 400:
            raise DetectorError(f"检测服务请求失败（HTTP {response.status_code}）")
        try:
            payload = response.json()
        except ValueError as exc:
            raise DetectorError("检测服务返回了无效响应") from exc
        if not isinstance(payload, dict):
            raise DetectorError("检测服务返回格式无效")
        return payload

    async def run_model(self, request: CheckRequest, model: str) -> dict[str, Any]:
        try:
            response = await self.client.post(
                "/api/jobs",
                json={
                    "preset": "medium",
                    "candidate": {
                        "base_url": request.base_url,
                        "model": model,
                        "api_key": request.api_key,
                    },
                },
            )
            job = await self._json(response)
            job_id = job.get("id")
            if not isinstance(job_id, str) or not job_id:
                raise DetectorError("检测服务没有返回任务编号")
            deadline = time.monotonic() + self.config.job_timeout_seconds
            while time.monotonic() < deadline:
                status_payload = await self._json(
                    await self.client.get(f"/api/jobs/{job_id}")
                )
                status = status_payload.get("status")
                if status == "completed":
                    report_response = await self.client.get(f"/api/jobs/{job_id}/report.json")
                    return await self._json(report_response)
                if status in {"failed", "stopped", "stopping"}:
                    raise DetectorError("检测任务未完成：" + str(status_payload.get("error") or status))
                await asyncio.sleep(self.config.poll_interval_seconds)
            raise DetectorError("检测任务超时，请稍后重试")
        except httpx.TimeoutException as exc:
            raise DetectorError("检测服务连接超时") from exc
        except httpx.HTTPError as exc:
            raise DetectorError("无法连接检测服务") from exc


async def run_checks(config: BotConfig, check_request: CheckRequest) -> list[tuple[str, dict[str, Any] | None, str | None]]:
    """Run both model checks and retain an error for one model if the other succeeds."""

    client = DetectorClient(config)
    results: list[tuple[str, dict[str, Any] | None, str | None]] = []
    try:
        for model in MODEL_TESTS:
            try:
                results.append((model, await client.run_model(check_request, model), None))
            except DetectorError as exc:
                LOGGER.warning("model check failed: model=%s error=%s", model, exc)
                results.append((model, None, str(exc)))
    finally:
        await client.close()
    return results


def _help_text() -> str:
    return "请在群里 @我 后发送：\nhttps://你的接口/v1 你的API密钥\n\n我会依次检测 GPT-5.6 Sol 和 Terra。"


async def handle_message(update: Any, context: Any) -> None:
    message = getattr(update, "effective_message", None)
    user = getattr(update, "effective_user", None)
    chat = getattr(update, "effective_chat", None)
    text = getattr(message, "text", None) or ""
    bot_username = str(getattr(getattr(context, "bot", None), "username", "") or "")
    chat_type = getattr(chat, "type", None)
    config: BotConfig = context.application.bot_data["config"]
    chat_id = getattr(chat, "id", None)
    if (
        not message
        or not user
        or not chat_is_allowed(chat_id, config.allowed_chat_ids)
        or not message_targets_bot(text, chat_type, bot_username)
    ):
        if message and chat_id is not None and not chat_is_allowed(chat_id, config.allowed_chat_ids):
            LOGGER.info("ignored unauthorized chat_id=%s", chat_id)
        return
    LOGGER.info("check request received: chat_id=%s user_id=%s", chat_id, user.id)
    try:
        check_request = parse_check_request(text, bot_username)
    except RequestParseError as exc:
        await message.reply_text(str(exc) + "\n\n" + _help_text())
        return

    semaphore: asyncio.Semaphore = context.application.bot_data["semaphore"]
    mention = build_user_mention(user)
    await message.reply_text(f"{mention} 已收到，开始检测 Sol 和 Terra。检测可能需要几分钟。", parse_mode="HTML")
    async with semaphore:
        results = await run_checks(config, check_request)
    sections = [f"{mention} 检测完成：", html.escape(check_request.base_url)]
    for model, report, error_message in results:
        sections.append(
            format_model_result(model, report) if report else f"<b>{html.escape(model)}</b>：失败，{html.escape(error_message or '未知错误')}"
        )
    sections.append("\n提示：Juice 指纹是辅助证据，不能单独证明后端身份。")
    await message.reply_text("\n\n".join(sections), parse_mode="HTML", disable_web_page_preview=True)


async def handle_start(update: Any, context: Any) -> None:
    message = getattr(update, "effective_message", None)
    chat = getattr(update, "effective_chat", None)
    config: BotConfig = context.application.bot_data["config"]
    if message and chat_is_allowed(getattr(chat, "id", None), config.allowed_chat_ids):
        await message.reply_text(_help_text())


async def handle_chat_id(update: Any, context: Any) -> None:
    message = getattr(update, "effective_message", None)
    chat = getattr(update, "effective_chat", None)
    config: BotConfig = context.application.bot_data["config"]
    if message and chat_is_allowed(getattr(chat, "id", None), config.allowed_chat_ids):
        await message.reply_text(f"此聊天 ID：{getattr(chat, 'id', 'unknown')}")


def build_application(config: BotConfig) -> Any:
    """Build the python-telegram-bot application lazily for lightweight imports/tests."""

    try:
        from telegram.ext import Application, CommandHandler, MessageHandler, filters
    except ImportError as exc:
        raise RuntimeError("请先安装 requirements-telegram.txt") from exc
    application = (
        Application.builder()
        .token(config.telegram_token)
        .get_updates_connect_timeout(15)
        .get_updates_read_timeout(30)
        .get_updates_write_timeout(15)
        .get_updates_pool_timeout(15)
        .build()
    )
    application.bot_data["config"] = config
    application.bot_data["semaphore"] = asyncio.Semaphore(config.max_concurrent_checks)
    application.add_handler(CommandHandler("start", handle_start))
    application.add_handler(CommandHandler("chatid", handle_chat_id))
    application.add_handler(CommandHandler("check", handle_message))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    return application


def main() -> None:
    logging.basicConfig(
        level=os.getenv("BOT_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # HTTPX logs Telegram Bot API URLs at INFO, which would include the bot token.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    config = BotConfig.from_env()
    application = build_application(config)
    LOGGER.info("Telegram detector bot started; detector=%s", config.detector_api_url)
    application.run_polling(allowed_updates=["message"], drop_pending_updates=True)


if __name__ == "__main__":
    main()
