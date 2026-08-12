from __future__ import annotations

import base64
from dataclasses import dataclass
import fnmatch
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import threading
import time
from typing import Any, Callable, Iterable
import urllib.error
import urllib.parse
import urllib.request

from .utils import normalize_api_base_url, utc_now


ROOT = Path(__file__).resolve().parents[2]
PACKAGED_PROFILE_DIR = Path(__file__).with_name("native")
DEVELOPMENT_PROFILE_DIR = ROOT / "work" / "gpt56_native_profile"
PROFILE_DIR = PACKAGED_PROFILE_DIR if PACKAGED_PROFILE_DIR.is_dir() else DEVELOPMENT_PROFILE_DIR
NODE_TOOL = PROFILE_DIR / "codex-native-transport.mjs"
RAW_PROFILE = PROFILE_DIR / "native-0.147.0.raw"
HISTORY_FIXTURE = PROFILE_DIR / "fixed_32k_history.json"
TERMINAL_EVENTS = {"response.completed", "response.incomplete", "response.failed"}
DEFAULT_SAFE_MESSAGES = {
    "upstream_http_error": "上游返回HTTP错误",
    "truncated_or_invalid_stream": "流式响应不完整或格式错误",
    "timeout": "等待上游响应超时",
    "connection_or_transport_error": "网络连接或传输失败",
    "response_incomplete": "上游返回未完成响应",
    "response_failed": "上游明确返回响应失败",
    "user_cancelled": "用户已停止当前任务，请求已取消",
}


def native_profile_user_agent(path: str | Path = RAW_PROFILE) -> str:
    with Path(path).open("rb") as handle:
        header_block = handle.read(131072).split(b"\r\n\r\n", 1)[0]
    for raw_line in header_block.splitlines():
        name, separator, value = raw_line.partition(b":")
        if separator and name.strip().lower() == b"user-agent":
            user_agent = value.decode("utf-8", errors="strict").strip()
            if user_agent:
                return user_agent
    raise RuntimeError("原生请求模板缺少User-Agent")


DEFAULT_UPSTREAM_USER_AGENT = native_profile_user_agent()


@dataclass(frozen=True)
class ProxyDecision:
    mode: str
    proxy_url: str | None
    source: str


def _environment_value(environment: dict[str, str], name: str) -> str:
    for key in (name, name.casefold()):
        value = str(environment.get(key) or "").strip()
        if value:
            return value
    return ""


def _proxy_host_matches(host: str, port: int | None, raw_rules: str, *, windows: bool = False) -> bool:
    host = host.casefold().strip("[]")
    for raw_rule in re.split(r"[;,]" if windows else r",", raw_rules or ""):
        rule = raw_rule.strip().casefold()
        if not rule:
            continue
        if windows and rule == "<local>" and "." not in host:
            return True
        if rule == "*":
            return True
        if ":" in rule and not rule.startswith("["):
            candidate, separator, candidate_port = rule.rpartition(":")
            if separator and candidate_port.isdigit():
                if port != int(candidate_port):
                    continue
                rule = candidate
        rule = rule.lstrip(".")
        if "*" in rule:
            if fnmatch.fnmatch(host, rule):
                return True
        elif host == rule or host.endswith("." + rule):
            return True
    return False


def _normalize_http_proxy(value: str) -> str:
    raw = value.strip()
    if not raw:
        raise ValueError("代理地址为空")
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme.casefold() != "http":
        raise ValueError("原生Codex仅支持HTTP/mixed代理端口；请改用HTTP代理端口或系统级TUN")
    if not parsed.hostname or parsed.port is None:
        raise ValueError("HTTP代理地址必须包含主机和端口")
    return urllib.parse.urlunsplit(("http", parsed.netloc, "", "", ""))


def _parse_windows_proxy_server(server: str) -> str:
    entries: dict[str, str] = {}
    fallback = ""
    for item in str(server or "").split(";"):
        item = item.strip()
        if not item:
            continue
        if "=" in item:
            protocol, value = item.split("=", 1)
            entries[protocol.strip().casefold()] = value.strip()
        elif not fallback:
            fallback = item
    return entries.get("https") or fallback or entries.get("http") or ""


def read_windows_manual_proxy() -> dict[str, Any]:
    if os.name != "nt":
        return {"enabled": False, "server": "", "bypass": "", "auto_config_url": ""}
    try:
        import winreg

        path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
            def read(name: str, default: Any) -> Any:
                try:
                    return winreg.QueryValueEx(key, name)[0]
                except OSError:
                    return default

            return {
                "enabled": bool(read("ProxyEnable", 0)),
                "server": str(read("ProxyServer", "") or ""),
                "bypass": str(read("ProxyOverride", "") or ""),
                "auto_config_url": str(read("AutoConfigURL", "") or ""),
            }
    except OSError:
        return {"enabled": False, "server": "", "bypass": "", "auto_config_url": ""}


def resolve_native_proxy(
    target_url: str,
    environment: dict[str, str] | None = None,
    windows_proxy_reader: Callable[[], dict[str, Any]] = read_windows_manual_proxy,
) -> ProxyDecision:
    environment = dict(os.environ if environment is None else environment)
    target = urllib.parse.urlsplit(target_url)
    host = target.hostname or ""
    port = target.port or (443 if target.scheme.casefold() == "https" else 80)
    no_proxy = _environment_value(environment, "NO_PROXY")
    if no_proxy and _proxy_host_matches(host, port, no_proxy):
        return ProxyDecision("direct", None, "bypass")
    for name, source in (
        ("HTTPS_PROXY", "environment_https"),
        ("ALL_PROXY", "environment_all"),
        ("HTTP_PROXY", "environment_http"),
    ):
        value = _environment_value(environment, name)
        if value:
            return ProxyDecision("proxy", _normalize_http_proxy(value), source)
    settings = windows_proxy_reader() or {}
    if bool(settings.get("enabled")):
        bypass = str(settings.get("bypass") or "")
        if bypass and _proxy_host_matches(host, port, bypass, windows=True):
            return ProxyDecision("direct", None, "bypass")
        value = _parse_windows_proxy_server(str(settings.get("server") or ""))
        if value:
            return ProxyDecision("proxy", _normalize_http_proxy(value), "windows_manual")
    if str(settings.get("auto_config_url") or "").strip():
        raise ValueError("原生Codex不解析PAC脚本；请改用HTTP/mixed代理端口或系统级TUN")
    return ProxyDecision("direct", None, "none")


def _native_child_environment(target_url: str) -> tuple[dict[str, str], ProxyDecision]:
    decision = resolve_native_proxy(target_url)
    proxy_names = {"https_proxy", "all_proxy", "http_proxy", "no_proxy"}
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.casefold() not in proxy_names
    }
    if decision.mode == "proxy" and decision.proxy_url:
        environment["HTTPS_PROXY"] = decision.proxy_url
    return environment, decision


def _structured_native_error(stderr: str) -> dict[str, Any] | None:
    for line in reversed((stderr or "").splitlines()):
        if not line.strip().startswith("error:"):
            continue
        try:
            value = json.loads(line.split("error:", 1)[1].strip())
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def _native_error_details(stderr: str) -> tuple[str, str, bool]:
    value = _structured_native_error(stderr) or {}
    parts = [str(value.get(key) or "") for key in ("code", "name", "message", "cause")]
    nested = value.get("nested") or []
    parts.extend(str(item) for item in nested if isinstance(item, (str, int)))
    text = " ".join(parts).casefold()
    if "econnrefused" in text:
        return "connection_or_transport_error", "代理端口或目标拒绝连接", True
    if "enotfound" in text or "eai_again" in text:
        return "connection_or_transport_error", "代理或目标DNS解析失败", True
    if "proxy connect timeout" in text:
        return "timeout", "连接HTTP代理隧道超时", True
    if "proxy connect failed" in text:
        return "connection_or_transport_error", "HTTP代理隧道建立失败", True
    if any(token in text for token in ("certificate", "cert_", "tls", "ssl")):
        return "connection_or_transport_error", "代理或目标TLS握手失败", True
    if "native response timeout" in text or "timeout" in text:
        return "timeout", "已建立连接，但等待原生Codex响应超时", True
    return "connection_or_transport_error", "原生Codex网络连接或传输失败", True


class TransportError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        elapsed_ms: int | None = None,
        exchange: dict[str, Any] | None = None,
        stage: str | None = None,
        category: str | None = None,
        retryable: bool | None = None,
        safe_message: str | None = None,
    ):
        super().__init__(message)
        self.status = status
        self.elapsed_ms = elapsed_ms
        self.exchange = exchange or {}
        if category is None:
            if message == "invalid Responses SSE":
                category = "truncated_or_invalid_stream"
            elif status is not None:
                category = "upstream_http_error"
            elif "timeout" in message.casefold():
                category = "timeout"
            else:
                category = "connection_or_transport_error"
        if stage is None:
            stage = "response_stream" if category == "truncated_or_invalid_stream" else ("upstream_http" if status is not None else "transport")
        if retryable is None:
            retryable = status is None or status in {408, 429, 500, 502, 503, 504} or category == "truncated_or_invalid_stream"
        self.stage = stage
        self.category = category
        self.retryable = bool(retryable)
        default_message = DEFAULT_SAFE_MESSAGES.get(category, "上游或本地请求失败")
        self.safe_message = safe_message or (default_message + (f"（HTTP {status}）" if status is not None else ""))

    def error_info(self, attempt: int) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "category": self.category,
            "retryable": self.retryable,
            "http_status": self.status,
            "attempt": int(attempt),
            "safe_message": self.safe_message,
        }


class TransportCancelled(TransportError):
    def __init__(self, *, exchange: dict[str, Any] | None = None):
        super().__init__(
            "request cancelled",
            exchange=exchange,
            stage="transport",
            category="user_cancelled",
            retryable=False,
            safe_message="用户已停止当前任务，请求已取消",
        )


class ResponseTerminalError(ValueError):
    def __init__(self, terminal_type: str, response: dict[str, Any]):
        super().__init__(f"Responses stream ended with {terminal_type}")
        self.terminal_type = terminal_type
        self.response = response


class RequestCancellationController:
    """Tracks the concrete resource that can abort each in-flight request."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._callbacks: dict[str, Callable[[], None]] = {}
        self._cancelled = threading.Event()

    def register(self, job_id: str, callback: Callable[[], None]) -> None:
        with self._lock:
            if self._cancelled.is_set():
                callback()
                raise TransportCancelled()
            self._callbacks[job_id] = callback

    def unregister(self, job_id: str) -> None:
        with self._lock:
            self._callbacks.pop(job_id, None)

    def cancel_all(self) -> int:
        self._cancelled.set()
        with self._lock:
            callbacks = list(self._callbacks.values())
        for callback in callbacks:
            try:
                callback()
            except Exception:
                pass
        return len(callbacks)

    def is_cancelled(self) -> bool:
        return self._cancelled.is_set()

    def active_count(self) -> int:
        with self._lock:
            return len(self._callbacks)


@dataclass
class TransportResult:
    response: dict[str, Any]
    answer: str
    meta: dict[str, Any]
    exchange: dict[str, Any]


def output_text(response: dict[str, Any]) -> str:
    direct = response.get("output_text")
    if isinstance(direct, str):
        return direct.strip()
    chunks = []
    for item in response.get("output", []):
        if not isinstance(item, dict) or item.get("type") != "message":
            continue
        for part in item.get("content", []):
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                chunks.append(part["text"])
    return "".join(chunks).strip()


class _SSECollector:
    def __init__(self) -> None:
        self.data_lines: list[str] = []
        self.terminal: dict[str, Any] | None = None
        self.terminal_type: str | None = None
        self.output_text_deltas: list[str] = []
        self.events = 0

    def _consume(self) -> None:
        if not self.data_lines:
            return
        payload = "\n".join(self.data_lines)
        self.data_lines.clear()
        if payload == "[DONE]":
            return
        event = json.loads(payload)
        if not isinstance(event, dict):
            raise ValueError("SSE event is not an object")
        self.events += 1
        event_type = event.get("type")
        if event_type == "response.output_text.delta" and isinstance(event.get("delta"), str):
            self.output_text_deltas.append(event["delta"])
        if event_type in TERMINAL_EVENTS and isinstance(event.get("response"), dict):
            self.terminal = event["response"]
            self.terminal_type = event_type

    def feed(self, raw_line: bytes) -> bool:
        line = raw_line.decode("utf-8").rstrip("\r\n")
        if not line:
            self._consume()
        elif line.startswith("data:"):
            self.data_lines.append(line[5:].lstrip(" "))
        return self.terminal is not None

    def finish(self) -> tuple[dict[str, Any], int]:
        self._consume()
        if self.terminal is None:
            raise ValueError("SSE ended without a terminal response")
        terminal = self.terminal
        if self.terminal_type != "response.completed":
            raise ResponseTerminalError(str(self.terminal_type), terminal)
        terminal_text = output_text(terminal)
        streamed_text = "".join(self.output_text_deltas).strip()
        if terminal_text and streamed_text and terminal_text != streamed_text:
            raise ValueError("SSE terminal output conflicts with streamed text")
        if not terminal_text and streamed_text:
            terminal = dict(terminal)
            terminal["output_text"] = streamed_text
        return terminal, self.events


def parse_sse(raw: bytes) -> tuple[dict[str, Any], int]:
    collector = _SSECollector()

    for raw_line in raw.splitlines(keepends=True):
        collector.feed(raw_line)
    return collector.finish()


def load_history() -> list[dict[str, str]]:
    value = json.loads(HISTORY_FIXTURE.read_text(encoding="utf-8"))
    return [{"role": item["role"], "content": item["text"]} for item in value]


def build_payload(model: str, messages: list[dict[str, str]], effort: str, context_mode: str, cache_key: str) -> dict[str, Any]:
    if not messages or messages[-1].get("role") != "user":
        raise ValueError("the final probe message must use user role")
    input_items = list(messages[:-1])
    if context_mode == "fixed_32k_history":
        input_items.extend(load_history())
    input_items.append(messages[-1])
    return {
        "model": model,
        "input": input_items,
        "reasoning": {"effort": effort},
        "include": ["reasoning.encrypted_content"],
        "store": False,
        "stream": True,
        "prompt_cache_key": cache_key,
    }


class StreamingTransport:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float = 180.0,
        capture_exchange: bool = False,
        cancellation: RequestCancellationController | None = None,
    ):
        self.base_url = normalize_api_base_url(base_url)
        self.api_key = api_key
        self.timeout = timeout
        self.capture_exchange = capture_exchange
        self.cancellation = cancellation or RequestCancellationController()

    def cancel_all(self) -> int:
        return self.cancellation.cancel_all()

    @staticmethod
    def _close_response(response: Any) -> None:
        socket_closed = False
        try:
            stack = [response]
            visited: set[int] = set()
            sock = None
            while stack and sock is None:
                current = stack.pop()
                if current is None or id(current) in visited:
                    continue
                visited.add(id(current))
                if isinstance(current, socket.socket):
                    sock = current
                    break
                candidate = getattr(current, "_sock", None)
                if isinstance(candidate, socket.socket):
                    sock = candidate
                    break
                if len(visited) < 12:
                    stack.extend(getattr(current, name, None) for name in ("fp", "raw", "_fp"))
            if sock is not None:
                sock.shutdown(socket.SHUT_RDWR)
                real_close = getattr(sock, "_real_close", None)
                if callable(real_close):
                    # socket.makefile() defers close while buffered readers hold
                    # references. Closing the OS handle is what wakes a blocked
                    # readline on Windows after the user presses Stop.
                    real_close()
                else:
                    sock.close()
                socket_closed = True
        except Exception:
            pass
        if not socket_closed:
            def close_without_blocking_stop() -> None:
                try:
                    response.close()
                except Exception:
                    pass

            closer = threading.Thread(target=close_without_blocking_stop, daemon=True, name="gpt56-response-close")
            closer.start()

    @staticmethod
    def _terminate_process(process: subprocess.Popen[str]) -> None:
        if process.poll() is not None:
            return
        try:
            process.terminate()
        except Exception:
            return

        def force_kill() -> None:
            if process.poll() is None:
                try:
                    process.kill()
                except Exception:
                    pass

        timer = threading.Timer(1.0, force_kill)
        timer.daemon = True
        timer.start()

    def post(
        self,
        *,
        model: str,
        messages: list[dict[str, str]],
        effort: str,
        request_format: str,
        context_mode: str,
        cache_key: str,
        job_id: str,
        session_id: str,
    ) -> TransportResult:
        if request_format == "normal":
            return self._post_normal(model, messages, effort, context_mode, cache_key, job_id, session_id)
        if request_format == "native_codex":
            return self._post_native(model, messages, effort, context_mode, job_id, session_id)
        raise ValueError(f"unsupported request format: {request_format}")

    def _post_normal(self, model: str, messages: list[dict[str, str]], effort: str, context_mode: str, cache_key: str, job_id: str, session_id: str) -> TransportResult:
        payload = build_payload(model, messages, effort, context_mode, cache_key)
        body_text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        body = body_text.encode("utf-8")
        url = self.base_url + "/responses"
        request = urllib.request.Request(url, data=body, method="POST", headers={
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
            "User-Agent": str(os.environ.get("GPT56_USER_AGENT") or "").strip() or DEFAULT_UPSTREAM_USER_AGENT,
        })
        started_wall = utc_now()
        started = time.perf_counter()
        first_event_at = None
        first_ms = None
        raw = bytearray()
        collector = _SSECollector()
        stream_parse_error: Exception | None = None
        status = None
        headers: dict[str, str] = {}
        active: dict[str, Any] = {"response": None}

        def open_response_cancelably() -> Any:
            opened = threading.Event()
            outcome: dict[str, Any] = {}

            def open_response() -> None:
                try:
                    response = urllib.request.urlopen(request, timeout=self.timeout)
                    active["response"] = response
                    if self.cancellation.is_cancelled():
                        self._close_response(response)
                    else:
                        outcome["response"] = response
                except BaseException as exc:
                    outcome["error"] = exc
                finally:
                    opened.set()

            opener = threading.Thread(target=open_response, daemon=True, name=f"gpt56-open-{job_id[:12]}")
            opener.start()
            while not opened.wait(0.05):
                if self.cancellation.is_cancelled():
                    raise TransportCancelled()
            if self.cancellation.is_cancelled():
                response = outcome.get("response")
                if response is not None:
                    self._close_response(response)
                raise TransportCancelled()
            if "error" in outcome:
                raise outcome["error"]
            return outcome["response"]

        def cancel_request() -> None:
            response = active.get("response")
            if response is not None:
                self._close_response(response)

        self.cancellation.register(job_id, cancel_request)
        try:
            with open_response_cancelably() as response:
                active["response"] = response
                if self.cancellation.is_cancelled():
                    raise TransportCancelled()
                status = int(response.status)
                headers = {str(key): str(value) for key, value in response.headers.items() if str(key).casefold() not in {"authorization", "set-cookie"}}
                while True:
                    line = response.readline()
                    if not line:
                        break
                    raw.extend(line)
                    if first_ms is None and line.strip():
                        first_ms = round((time.perf_counter() - started) * 1000)
                        first_event_at = utc_now()
                    try:
                        terminal_seen = collector.feed(line)
                    except Exception as exc:
                        stream_parse_error = exc
                        break
                    if terminal_seen:
                        break
                    if time.perf_counter() - started > self.timeout:
                        raise TimeoutError("stream exceeded hard deadline")
        except urllib.error.HTTPError as exc:
            if self.cancellation.is_cancelled():
                raise TransportCancelled() from exc
            active["response"] = exc
            status = int(exc.code)
            headers = {str(key): str(value) for key, value in exc.headers.items() if str(key).casefold() not in {"authorization", "set-cookie"}}
            try:
                while True:
                    if self.cancellation.is_cancelled():
                        raise TransportCancelled() from exc
                    chunk = exc.read(65536)
                    if not chunk:
                        break
                    raw.extend(chunk)
            except Exception as read_exc:
                if isinstance(read_exc, TransportCancelled) or self.cancellation.is_cancelled():
                    raise TransportCancelled() from read_exc
                raise
            finally:
                try:
                    exc.close()
                except Exception:
                    pass
            raise TransportError("upstream HTTP error", status=status, elapsed_ms=round((time.perf_counter() - started) * 1000), exchange=self._exchange(session_id, job_id, started_wall, first_event_at, url, "normal", context_mode, model, effort, status, headers, body_text, raw.decode("utf-8", errors="replace"), None, first_ms, 0, "upstream HTTP error")) from exc
        except Exception as exc:
            if isinstance(exc, TransportCancelled) or self.cancellation.is_cancelled():
                raise TransportCancelled() from exc
            raise TransportError(type(exc).__name__, status=status, elapsed_ms=round((time.perf_counter() - started) * 1000), exchange=self._exchange(session_id, job_id, started_wall, first_event_at, url, "normal", context_mode, model, effort, status, headers, body_text, raw.decode("utf-8", errors="replace"), None, first_ms, 0, type(exc).__name__)) from exc
        finally:
            active["response"] = None
            self.cancellation.unregister(job_id)
        elapsed = round((time.perf_counter() - started) * 1000)
        try:
            if stream_parse_error is not None:
                raise stream_parse_error
            parsed, events = collector.finish()
        except ResponseTerminalError as exc:
            category = "response_incomplete" if exc.terminal_type == "response.incomplete" else "response_failed"
            raise TransportError(
                exc.terminal_type,
                status=status,
                elapsed_ms=elapsed,
                exchange=self._exchange(session_id, job_id, started_wall, first_event_at, url, "normal", context_mode, model, effort, status, headers, body_text, raw.decode("utf-8", errors="replace"), exc.response, first_ms, collector.events, exc.terminal_type),
                stage="response_stream",
                category=category,
                retryable=True,
                safe_message="上游返回未完成响应" if category == "response_incomplete" else "上游明确返回响应失败",
            ) from exc
        except Exception as exc:
            raise TransportError("invalid Responses SSE", status=status, elapsed_ms=elapsed, exchange=self._exchange(session_id, job_id, started_wall, first_event_at, url, "normal", context_mode, model, effort, status, headers, body_text, raw.decode("utf-8", errors="replace"), None, first_ms, 0, "invalid Responses SSE")) from exc
        exchange = self._exchange(session_id, job_id, started_wall, first_event_at, url, "normal", context_mode, model, effort, status, headers, body_text, raw.decode("utf-8"), parsed, first_ms, events, None)
        exchange["elapsed_ms"] = elapsed
        return TransportResult(parsed, output_text(parsed), {"http_status": status, "elapsed_ms": elapsed, "response_headers": headers, "streaming": True, "stream_event_count": events, "time_to_first_event_ms": first_ms}, exchange)

    def _post_native(self, model: str, messages: list[dict[str, str]], effort: str, context_mode: str, job_id: str, session_id: str) -> TransportResult:
        node = os.environ.get("GPT56_NODE") or shutil.which("node")
        if not node:
            raise TransportError("Node.js is required for native Codex requests")
        url = self.base_url + "/responses"
        command = [
            node, str(NODE_TOOL), "send-native", "--profile", str(RAW_PROFILE), "--url", url,
            "--model", model, "--timeout", str(round(self.timeout * 1000)), "--input-json", "true",
            "--effort", effort, "--capture-sanitized-request", "true" if self.capture_exchange else "false",
        ]
        if context_mode == "fixed_32k_history":
            command.extend(["--history-file", str(HISTORY_FIXTURE)])
        try:
            environment, proxy_decision = _native_child_environment(url)
        except ValueError as exc:
            raise TransportError(
                "unsupported native proxy configuration",
                category="connection_or_transport_error",
                retryable=False,
                safe_message=str(exc),
            ) from exc
        environment["GPT56_NATIVE_AUTHORIZATION"] = self.api_key
        started_wall = utc_now()
        started = time.perf_counter()
        process: subprocess.Popen[str] | None = None

        def cancel_request() -> None:
            if process is not None:
                self._terminate_process(process)

        self.cancellation.register(job_id, cancel_request)
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                env=environment,
            )
            if self.cancellation.is_cancelled():
                self._terminate_process(process)
                raise TransportCancelled()
            try:
                stdout, stderr = process.communicate(
                    input=json.dumps(messages, ensure_ascii=False, separators=(",", ":")),
                    timeout=self.timeout + 10,
                )
            except subprocess.TimeoutExpired as exc:
                self._terminate_process(process)
                process.wait(timeout=2)
                raise TransportError(
                    "native transport timeout",
                    elapsed_ms=round((time.perf_counter() - started) * 1000),
                    category="timeout",
                    safe_message="原生 Codex 请求等待上游响应超时",
                ) from exc
        finally:
            environment.pop("GPT56_NATIVE_AUTHORIZATION", None)
            self.cancellation.unregister(job_id)
        elapsed = round((time.perf_counter() - started) * 1000)
        if self.cancellation.is_cancelled():
            raise TransportCancelled()
        if process is None or process.returncode != 0:
            category, safe_message, retryable = _native_error_details(stderr if process is not None else "")
            raise TransportError(
                "native transport failed",
                elapsed_ms=elapsed,
                category=category,
                retryable=retryable,
                safe_message=safe_message,
            )
        report = json.loads(stdout)
        status = int(report["status"])
        stream_text = str(report.get("body", ""))
        request_text = ""
        if self.capture_exchange:
            encoded = report.get("request", {}).get("raw_without_auth_base64")
            if not isinstance(encoded, str):
                raise TransportError("native transport omitted sanitized request", status=status, elapsed_ms=elapsed)
            request_text = base64.b64decode(encoded).decode("utf-8")
        if not 200 <= status < 300:
            exchange = self._exchange(session_id, job_id, started_wall, None, url, "native_codex", context_mode, model, effort, status, report.get("headers", {}), request_text, stream_text, None, None, 0, "native upstream HTTP error")
            safe_message = (
                "已到达中转，但认证或客户端权限被拒绝；请检查API key、权限、User-Agent或客户端白名单"
                if status in {401, 403}
                else f"上游返回HTTP错误（HTTP {status}）"
            )
            raise TransportError("native upstream HTTP error", status=status, elapsed_ms=elapsed, exchange=exchange, safe_message=safe_message)
        try:
            parsed, events = parse_sse(stream_text.encode("utf-8"))
        except ResponseTerminalError as exc:
            category = "response_incomplete" if exc.terminal_type == "response.incomplete" else "response_failed"
            exchange = self._exchange(session_id, job_id, started_wall, None, url, "native_codex", context_mode, model, effort, status, report.get("headers", {}), request_text, stream_text, exc.response, None, 0, exc.terminal_type)
            raise TransportError(
                exc.terminal_type,
                status=status,
                elapsed_ms=elapsed,
                exchange=exchange,
                stage="response_stream",
                category=category,
                retryable=True,
                safe_message="上游返回未完成响应" if category == "response_incomplete" else "上游明确返回响应失败",
            ) from exc
        except Exception as exc:
            exchange = self._exchange(session_id, job_id, started_wall, None, url, "native_codex", context_mode, model, effort, status, report.get("headers", {}), request_text, stream_text, None, None, 0, "invalid Responses SSE")
            raise TransportError("invalid Responses SSE", status=status, elapsed_ms=elapsed, exchange=exchange) from exc
        exchange = self._exchange(session_id, job_id, started_wall, None, url, "native_codex", context_mode, model, effort, status, report.get("headers", {}), request_text, stream_text, parsed, None, events, None)
        exchange["elapsed_ms"] = elapsed
        return TransportResult(parsed, output_text(parsed), {"http_status": status, "elapsed_ms": elapsed, "response_headers": report.get("headers", {}), "streaming": True, "stream_event_count": events, "time_to_first_event_ms": None, "request_profile": report.get("request", {})}, exchange)

    @staticmethod
    def _exchange(session_id: str, job_id: str, started_at: str, first_event_at: str | None, url: str, request_format: str, context_mode: str, model: str, effort: str, status: int | None, headers: dict[str, Any], request_text: str, response_text: str, parsed: dict[str, Any] | None, first_ms: int | None, events: int, error: str | None) -> dict[str, Any]:
        return {
            "session_id": session_id, "job_id": job_id, "started_at": started_at,
            "first_event_at": first_event_at, "completed_at": utc_now(), "request_id": headers.get("x-request-id") or headers.get("X-Request-Id"),
            "sanitized_url": url, "request_format": request_format, "context_mode": context_mode,
            "model": model, "effort": effort, "http_status": status,
            "response_headers_without_auth": headers, "elapsed_ms": None, "time_to_first_event_ms": first_ms,
            "stream_event_count": events, "request_body_utf8_exact": request_text,
            "response_stream_utf8_exact": response_text, "parsed_response_json_if_available": parsed,
            "transport_error_if_any": error, "auth_header_omitted": True,
        }


__all__ = [
    "DEFAULT_UPSTREAM_USER_AGENT",
    "ProxyDecision",
    "RAW_PROFILE",
    "RequestCancellationController",
    "ResponseTerminalError",
    "StreamingTransport",
    "TransportCancelled",
    "TransportError",
    "TransportResult",
    "build_payload",
    "native_profile_user_agent",
    "output_text",
    "parse_sse",
    "read_windows_manual_proxy",
    "resolve_native_proxy",
]
