#!/usr/bin/env python3
"""Probe GPT-5.6 encrypted-reasoning compatibility across two Responses APIs.

This is a capability test, not cryptographic proof of model identity. A passing
candidate can decrypt/replay state emitted by the trusted GPT-5.6 endpoint, or
can proxy the request to a backend that can. It cannot distinguish Sol, Terra,
and Luna.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.request
from gpt56_juice_probe import (
    EFFORTS,
    EFFORT_LABELS_CN,
    MODEL_LABELS_CN,
    classify_visible_answer,
    combined_summary,
    matching_models,
    run_juice_request,
    summarize_juice,
)
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


TASKS = (
    (
        "reverse",
        "In hidden reasoning, take the ten-digit input {value} and compute B by reversing all ten digits. "
        "Retain the exact ten-digit B for the next turn. Do not expose the input, B, intermediate work, "
        "or any hint in visible output. Your entire visible response must be exactly READY",
    ),
    (
        "rotate_left_3",
        "In hidden reasoning, take the ten-digit input {value} and compute B by moving its first three "
        "digits to the end without changing any other order. Retain the exact ten-digit B for the next "
        "turn. Reveal no digits or work. Your complete visible response must be exactly READY",
    ),
    (
        "complement_9",
        "In hidden reasoning, transform the ten-digit input {value} digit by digit using d -> 9-d and "
        "call the resulting ten-character digit string B. Retain B for the next turn. Do not reveal any "
        "input, result, or work. Your entire visible response must be exactly READY",
    ),
)

RECALL_PROMPT = (
    "Return the exact ten-digit value B computed and retained in the preceding hidden reasoning state. "
    "Output only B. If that state is absent or unreadable, output exactly UNKNOWN. Do not recompute, "
    "guess, or create a replacement value."
)

KEY_PATTERN = re.compile(r"sk-[A-Za-z0-9_-]{12,}")
TRANSIENT_HTTP_STATUSES = {429, 500, 502, 503, 504}


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def redact(value: Any, key: str | None = None) -> Any:
    if key == "encrypted_content" and isinstance(value, str):
        return {"redacted": True, "length": len(value), "sha256": sha256(value)}
    if isinstance(value, dict):
        return {
            child_key: (
                "[REDACTED]"
                if child_key.lower() in {"authorization", "api_key", "apikey"}
                else redact(child_value, child_key)
            )
            for child_key, child_value in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return KEY_PATTERN.sub("sk-[REDACTED]", value)
    return value


def output_text(response: dict[str, Any]) -> str:
    direct = response.get("output_text")
    if isinstance(direct, str):
        return direct.strip()
    chunks: list[str] = []
    for item in response.get("output", []):
        if not isinstance(item, dict) or item.get("type") != "message":
            continue
        for part in item.get("content", []):
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                chunks.append(part["text"])
    return "".join(chunks).strip()


def random_ten_digits() -> str:
    first = str(secrets.randbelow(9) + 1)
    middle = "".join(str(secrets.randbelow(10)) for _ in range(8))
    last = str(secrets.randbelow(9) + 1)
    return first + middle + last


def random_float(minimum: float, maximum: float) -> float:
    if maximum <= minimum:
        return minimum
    return minimum + (maximum - minimum) * (secrets.randbelow(1_000_001) / 1_000_000)


def transform(task: str, value: str) -> str:
    if task == "reverse":
        return value[::-1]
    if task == "rotate_left_3":
        return value[3:] + value[:3]
    if task == "complement_9":
        return "".join(str(9 - int(char)) for char in value)
    raise ValueError(f"unknown task: {task}")


class ProbeError(RuntimeError):
    def __init__(self, message: str, status: int | None = None, elapsed_ms: int | None = None):
        super().__init__(message)
        self.status = status
        self.elapsed_ms = elapsed_ms


@dataclass
class ResponsesClient:
    base_url: str
    api_key: str
    timeout: float

    @property
    def url(self) -> str:
        return self.base_url.rstrip("/") + "/responses"

    def post(self, payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            self.url,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "gpt56-api-detector/1.1",
            },
        )
        started = time.perf_counter()
        status: int | None = None
        raw = b""
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                status = response.status
                raw = response.read()
        except urllib.error.HTTPError as exc:
            status = exc.code
            raw = exc.read()
        except Exception as exc:
            elapsed = round((time.perf_counter() - started) * 1000)
            raise ProbeError(redact(str(exc)), status=None, elapsed_ms=elapsed) from exc
        elapsed = round((time.perf_counter() - started) * 1000)
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProbeError("non-JSON response", status=status, elapsed_ms=elapsed) from exc
        if status is None or not 200 <= status < 300:
            error = decoded.get("error", decoded) if isinstance(decoded, dict) else decoded
            raise ProbeError(str(redact(error)), status=status, elapsed_ms=elapsed)
        if not isinstance(decoded, dict):
            raise ProbeError("response JSON is not an object", status=status, elapsed_ms=elapsed)
        return decoded, {"http_status": status, "elapsed_ms": elapsed}


def seed_payload(model: str, prompt: str) -> dict[str, Any]:
    return {
        "model": model,
        "input": [{"role": "user", "content": prompt}],
        "reasoning": {"effort": "high"},
        "include": ["reasoning.encrypted_content"],
        "store": False,
    }


def recall_payload(model: str, context: list[Any]) -> dict[str, Any]:
    return {
        "model": model,
        "input": copy.deepcopy(context) + [{"role": "user", "content": RECALL_PROMPT}],
        "reasoning": {"effort": "high"},
        "include": ["reasoning.encrypted_content"],
        "store": False,
    }


def select_items(output: list[Any], item_type: str) -> list[dict[str, Any]]:
    return [
        copy.deepcopy(item)
        for item in output
        if isinstance(item, dict) and item.get("type") == item_type
    ]


def context_variant(output: list[Any], variant: str) -> list[Any]:
    if variant == "full":
        return copy.deepcopy(output)
    if variant == "message_only":
        return select_items(output, "message")
    context = copy.deepcopy(output)
    if variant == "without_ids":
        for item in context:
            if isinstance(item, dict):
                item.pop("id", None)
        return context
    if variant == "corrupted_ciphertext":
        changed = False
        for item in context:
            if not isinstance(item, dict) or item.get("type") != "reasoning":
                continue
            encrypted = item.get("encrypted_content")
            if isinstance(encrypted, str) and encrypted:
                index = len(encrypted) // 2
                replacement = "A" if encrypted[index] != "A" else "B"
                item["encrypted_content"] = encrypted[:index] + replacement + encrypted[index + 1 :]
                changed = True
        if not changed:
            raise ValueError("no encrypted reasoning item to corrupt")
        return context
    raise ValueError(f"unknown context variant: {variant}")


def encrypted_fingerprints(output: list[Any]) -> list[dict[str, Any]]:
    fingerprints = []
    for item in output:
        if not isinstance(item, dict) or item.get("type") != "reasoning":
            continue
        encrypted = item.get("encrypted_content")
        if isinstance(encrypted, str) and encrypted:
            fingerprints.append({"length": len(encrypted), "sha256": sha256(encrypted)})
    return fingerprints


def call_and_score(
    client: ResponsesClient,
    model: str,
    context: list[Any],
    expected: str,
    *,
    max_transport_attempts: int = 1,
    retry_base_seconds: float = 2.0,
) -> dict[str, Any]:
    payload = recall_payload(model, context)
    serialized = json.dumps(redact(payload), ensure_ascii=False)
    plaintext_leak = expected in serialized
    if plaintext_leak:
        return {
            "status": "invalid_probe",
            "exact": False,
            "plaintext_leak": True,
            "error": "expected value appeared in candidate request plaintext",
        }

    last_error: ProbeError | None = None
    transport_errors: list[dict[str, Any]] = []
    for transport_attempt in range(1, max_transport_attempts + 1):
        try:
            response, meta = client.post(payload)
            answer = output_text(response)
            return {
                "status": "ok",
                "exact": answer == expected,
                "unknown": answer == "UNKNOWN",
                "answer_sha256": sha256(answer),
                "answer_length": len(answer),
                "plaintext_leak": False,
                "transport_attempts": transport_attempt,
                "transport_errors": transport_errors,
                **meta,
            }
        except ProbeError as exc:
            last_error = exc
            transport_errors.append({
                "http_status": exc.status,
                "elapsed_ms": exc.elapsed_ms,
                "error": redact(str(exc)),
            })
            transient = exc.status is None or exc.status in TRANSIENT_HTTP_STATUSES
            if transport_attempt >= max_transport_attempts or not transient:
                break
            backoff = retry_base_seconds * (2 ** (transport_attempt - 1))
            time.sleep(backoff + secrets.randbelow(1001) / 1000)

    assert last_error is not None
    return {
        "status": "error",
        "exact": False,
        "plaintext_leak": False,
        "http_status": last_error.status,
        "elapsed_ms": last_error.elapsed_ms,
        "transport_attempts": transport_attempt,
        "transport_errors": transport_errors,
        "error": redact(str(last_error)),
    }

def blind_guess_tail_probability(successes: int, trials: int) -> float:
    if successes <= 0:
        return 1.0
    p = 1e-10
    return sum(
        math.comb(trials, count) * (p**count) * ((1 - p) ** (trials - count))
        for count in range(successes, trials + 1)
    )

def encrypted_state_verdict(
    *,
    attempts: int,
    required_attempts: int,
    full_exact: int,
    without_ids_exact: int,
    required_matches: int,
    message_only_exact: int,
    corrupted_ciphertext_exact: int,
    plaintext_leaks: int,
    warming_verdict: str = "inconclusive",
    incompatible_verdict: str = "not_compatible_in_this_probe",
) -> tuple[str, str]:
    """Judge model capability independently from transport quality."""
    if attempts < required_attempts:
        return warming_verdict, "not enough candidate attempts"
    if plaintext_leaks:
        return "invalid", "one or more candidate requests contained challenge plaintext"
    if message_only_exact or corrupted_ciphertext_exact:
        return "suspicious", "a negative control unexpectedly matched the hidden challenge"
    if full_exact >= required_matches and without_ids_exact >= required_matches:
        return (
            "gpt_5_6_encrypted_state_compatible",
            "candidate repeatedly recovered trusted GPT-5.6 hidden values from encrypted state",
        )
    if full_exact == 0 and without_ids_exact == 0:
        return incompatible_verdict, "candidate recovered none of the trusted encrypted challenge states"
    return "inconclusive", "partial replay evidence did not reach the configured threshold"


def connection_quality(error_rounds: int, retry_rounds: int) -> dict[str, Any]:
    if error_rounds:
        return {
            "status": "unstable",
            "title_cn": "不稳定",
            "detail_cn": f"{error_rounds} 轮最终失败，{retry_rounds} 轮发生过重试",
        }
    if retry_rounds:
        return {
            "status": "intermittent",
            "title_cn": "偶有波动",
            "detail_cn": f"没有最终失败，{retry_rounds} 轮重试后恢复",
        }
    return {
        "status": "smooth",
        "title_cn": "流畅",
        "detail_cn": "没有最终失败，也没有发生重试",
    }

TASK_LABELS_CN = {
    "reverse": "十位数字倒序",
    "rotate_left_3": "前三位移到末尾",
    "complement_9": "逐位计算九补数",
}

VERDICT_LABELS_CN = {
    "gpt_5_6_encrypted_state_compatible": ("检测通过", "是"),
    "not_compatible_in_this_probe": ("当前检测未观察到兼容能力", "否"),
    "inconclusive": ("证据不足或网络不稳定", "尚不能确认"),
    "suspicious": ("阴性对照异常，结果不可信", "否"),
    "invalid": ("检测发生明文泄漏，结果无效", "否"),
}


def print_candidate_attempt_result(trial: dict[str, Any]) -> None:
    candidate = trial["candidate"]
    retries = sum(
        len(result.get("transport_errors", [])) for result in candidate.values()
    )
    errors = sum(result.get("status") == "error" for result in candidate.values())
    negative = int(bool(candidate["message_only"].get("exact"))) + int(
        bool(candidate["corrupted_ciphertext"].get("exact"))
    )
    network = "正常" if not errors and not retries else f"失败 {errors} 个，重试 {retries} 次"
    print(
        "本轮结果："
        f"完整状态{'答对' if candidate['full'].get('exact') else '未答对'}，"
        f"去掉编号后{'答对' if candidate['without_ids'].get('exact') else '未答对'}，"
        f"异常测试{'正常' if negative == 0 else '命中'}，线路{network}"
    )


def print_probe_summary(report: dict[str, Any], report_path: Path) -> None:
    summary = report["summary"]
    verdict = report["verdict"]
    combined = report["combined_summary"]
    juice = report.get("juice_summary")
    requested = report["configuration"]["requested_candidate_attempts"]
    attempts = summary["candidate_attempts"]
    required = report["configuration"]["required_matches_per_positive_condition"]
    negative = (
        summary["candidate_message_only_exact"]
        + summary["candidate_corrupted_ciphertext_exact"]
    )
    network = report["network_summary"]
    confidence_cn = {
        "high": "高", "medium": "中", "preliminary": "初步", "insufficient": "不足"
    }

    print("\n" + "=" * 62)
    print(f"检测完成：{combined['title_cn']}（是否通过：{combined['passed_cn']}）")
    print(f"综合结论：{combined['explanation_cn']}")
    if verdict == "gpt_5_6_encrypted_state_compatible":
        strong_text = "通过，极高置信度具备 GPT-5.6 加密状态处理能力"
    else:
        strong_text = VERDICT_LABELS_CN.get(verdict, (verdict, ""))[0]
    print(
        f"模型能力：{strong_text}；"
        f"两种有效测试 {summary['candidate_full_exact']}/{required}、"
        f"{summary['candidate_without_ids_exact']}/{required}"
    )
    print(
        f"防误判检查：异常命中 {negative}，答案泄漏 "
        f"{summary['candidate_request_plaintext_leaks']}（都必须为 0）"
    )
    if juice is not None:
        mixed_cn = "已发现" if juice["status"] == "mixed_or_inconsistent" else "未发现"
        print(
            f"具体型号：{juice['likely_model_cn']}（置信度"
            f"{confidence_cn.get(juice['confidence'], juice['confidence'])}，"
            f"高档样本 {juice['high_numeric_samples']}/{juice['required_high_samples']}，"
            f"混用{mixed_cn}）"
        )
        if juice["status"] == "mixed_or_inconsistent":
            labels = [
                MODEL_LABELS_CN.get(item, item)
                for item in juice["session_distinct_high_groups"]
            ]
            conflicts = juice.get("session_conflicting_observations", [])
            if len(labels) >= 2:
                detail = f"高档同时出现：{'、'.join(labels)}"
            elif conflicts:
                detail = "与主要型号冲突：" + "、".join(
                    f"{EFFORT_LABELS_CN.get(item['effort'], item['effort'])}档={item['normalized_value']}"
                    for item in conflicts
                )
            else:
                detail = "型号结果互相冲突"
            print(f"严重警报：{detail}。已直接标记混用。")
    print(f"线路情况：{network['title_cn']}（{network['detail_cn']}）")
    print(
        f"样本：{attempts}/{requested} 轮；"
        f"可信端自行验证失败 {summary['rejected_trusted_attempts']} 次"
    )
    print(f"详细脱敏报告：{report_path.resolve()}")
    print("=" * 62)
def run_probe(args: argparse.Namespace) -> dict[str, Any]:
    trusted_key = os.getenv(args.trusted_key_env)
    candidate_key = os.getenv(args.candidate_key_env)
    if not trusted_key:
        raise SystemExit(f"缺少可信 API 临时密钥环境变量：{args.trusted_key_env}")
    if not candidate_key:
        raise SystemExit(f"缺少待测 API 临时密钥环境变量：{args.candidate_key_env}")

    trusted = ResponsesClient(args.trusted_base_url, trusted_key, args.timeout)
    candidate = ResponsesClient(args.candidate_base_url, candidate_key, args.timeout)
    valid_trials: list[dict[str, Any]] = []
    rejected_attempts: list[dict[str, Any]] = []
    max_attempts = args.max_attempts or args.trials * 3

    for attempt in range(1, max_attempts + 1):
        if len(valid_trials) >= args.trials:
            break
        task, template = TASKS[(attempt - 1) % len(TASKS)]
        input_value = random_ten_digits()
        expected = transform(task, input_value)
        print(
            f"\n正在检测第 {len(valid_trials) + 1}/{args.trials} 轮："
            f"{TASK_LABELS_CN.get(task, task)}",
            flush=True,
        )
        try:
            seed, seed_meta = trusted.post(
                seed_payload(args.trusted_model, template.format(value=input_value))
            )
        except ProbeError as exc:
            rejected_attempts.append(
                {
                    "attempt": attempt,
                    "reason": "trusted_seed_error",
                    "http_status": exc.status,
                    "error": redact(str(exc)),
                }
            )
            print("本轮舍弃：可信 API 生成状态失败。", flush=True)
            continue

        output = seed.get("output")
        visible = output_text(seed)
        if not isinstance(output, list):
            rejected_attempts.append({"attempt": attempt, "reason": "missing_output_array"})
            print("本轮舍弃：可信 API 返回格式不完整。", flush=True)
            continue
        fingerprints = encrypted_fingerprints(output)
        sanitized_output = json.dumps(redact(output), ensure_ascii=False)
        visible_leak = input_value in sanitized_output or expected in sanitized_output
        if visible != "READY" or not fingerprints or visible_leak:
            rejected_attempts.append(
                {
                    "attempt": attempt,
                    "reason": "invalid_trusted_seed",
                    "visible_contract_ok": visible == "READY",
                    "encrypted_reasoning_items": len(fingerprints),
                    "visible_plaintext_leak": visible_leak,
                }
            )
            print("本轮舍弃：可信状态不符合 READY、密文或无泄漏要求。", flush=True)
            continue

        trusted_self = call_and_score(
            trusted,
            args.trusted_model,
            context_variant(output, "full"),
            expected,
        )
        if not trusted_self["exact"]:
            rejected_attempts.append(
                {
                    "attempt": attempt,
                    "reason": "trusted_state_not_self_verifiable",
                    "trusted_self": trusted_self,
                }
            )
            print("本轮舍弃：可信 API 无法自证刚生成的状态。", flush=True)
            continue

        conditions = {}
        variants = ("full", "without_ids", "message_only", "corrupted_ciphertext")
        for index, variant in enumerate(variants):
            conditions[variant] = call_and_score(
                candidate,
                args.candidate_model,
                context_variant(output, variant),
                expected,
                max_transport_attempts=args.candidate_retries + 1,
            )
            if index + 1 < len(variants):
                time.sleep(random_float(args.candidate_min_gap, args.candidate_max_gap))
        valid_trials.append(
            {
                "trial": len(valid_trials) + 1,
                "attempt": attempt,
                "task": task,
                "expected_sha256": sha256(expected),
                "trusted_seed": {
                    "http_status": seed_meta["http_status"],
                    "elapsed_ms": seed_meta["elapsed_ms"],
                    "output_item_types": [
                        item.get("type") for item in output if isinstance(item, dict)
                    ],
                    "encrypted_items": fingerprints,
                    "visible_contract_ok": True,
                    "plaintext_leak": False,
                },
                "trusted_self": trusted_self,
                "candidate": conditions,
            }
        )
        print_candidate_attempt_result(valid_trials[-1])

    def count_exact(condition: str) -> int:
        return sum(bool(trial["candidate"][condition]["exact"]) for trial in valid_trials)

    candidate_attempt_count = len(valid_trials)
    complete_trial_count = sum(
        all(result.get("status") != "error" for result in trial["candidate"].values())
        for trial in valid_trials
    )
    valid_count = candidate_attempt_count
    full_exact = count_exact("full")
    no_id_exact = count_exact("without_ids")
    message_exact = count_exact("message_only")
    corrupt_exact = count_exact("corrupted_ciphertext")
    plaintext_leaks = sum(
        bool(result.get("plaintext_leak"))
        for trial in valid_trials
        for result in trial["candidate"].values()
    )
    candidate_request_errors = sum(
        result.get("status") == "error"
        for trial in valid_trials
        for result in trial["candidate"].values()
    )
    candidate_error_rounds = sum(
        any(result.get("status") == "error" for result in trial["candidate"].values())
        for trial in valid_trials
    )
    candidate_retry_rounds = sum(
        any(result.get("transport_attempts", 1) > 1 for result in trial["candidate"].values())
        for trial in valid_trials
    )
    juice_repeats = getattr(args, "juice_repeats", 3)
    no_juice = getattr(args, "no_juice", False)
    juice_observations: list[dict[str, Any]] = []
    if not no_juice:
        jobs = [effort for effort in EFFORTS for _ in range(juice_repeats)]
        for index in range(len(jobs) - 1, 0, -1):
            other = secrets.randbelow(index + 1)
            jobs[index], jobs[other] = jobs[other], jobs[index]
        print("\n" + "=" * 66)
        print("开始第二层：juice 浅层型号指纹")
        print("五个推理档位会各测多次；高档互斥结果实行混用零容忍。")
        print("=" * 66, flush=True)
        for index, effort in enumerate(jobs, start=1):
            print(
                f"浅层指纹 {index}/{len(jobs)}：{EFFORT_LABELS_CN[effort]}档……",
                flush=True,
            )
            observation = run_juice_request(
                candidate,
                args.candidate_model,
                effort,
                max_transport_attempts=args.candidate_retries + 1,
            )
            juice_observations.append(observation)
            if observation["answer_kind"] == "number":
                detail = f"数字 {observation['normalized_value']}"
            elif observation["answer_kind"] == "refusal":
                detail = "模型拒绝提供（记为无证据）"
            elif observation["answer_kind"] == "error":
                detail = "接口错误（记为无证据）"
            else:
                detail = "其他非数字回复（记为无证据）"
            print(f"  结果：{detail}", flush=True)
            if index < len(jobs):
                time.sleep(random_float(args.candidate_min_gap, args.candidate_max_gap))
    juice_summary = summarize_juice(juice_observations, per_effort=juice_repeats)
    required_matches = max(args.min_matches, math.ceil(args.min_match_rate * args.trials))

    verdict, reason = encrypted_state_verdict(
        attempts=valid_count,
        required_attempts=args.trials,
        full_exact=full_exact,
        without_ids_exact=no_id_exact,
        required_matches=required_matches,
        message_only_exact=message_exact,
        corrupted_ciphertext_exact=corrupt_exact,
        plaintext_leaks=plaintext_leaks,
    )
    network_summary = connection_quality(candidate_error_rounds, candidate_retry_rounds)
    combined = combined_summary(
        verdict, juice_summary, args.candidate_model, network_summary
    )

    return {
        "schema_version": 3,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
        "encrypted_state_verdict": verdict,
        "combined_verdict": combined["status"],
        "reason": reason,
        "scope": (
            "Encrypted reasoning-state compatibility with the trusted GPT-5.6 source. "
            "This is not proof of physical backend identity and cannot distinguish Sol, Terra, or Luna."
        ),
        "configuration": {
            "trusted_base_url": args.trusted_base_url,
            "trusted_model": args.trusted_model,
            "candidate_base_url": args.candidate_base_url,
            "candidate_model": args.candidate_model,
            "requested_candidate_attempts": args.trials,
            "requested_valid_trials": args.trials,
            "max_attempts": max_attempts,
            "required_matches_per_positive_condition": required_matches,
            "min_match_rate": args.min_match_rate,
            "min_matches": args.min_matches,
            "candidate_transient_retries": args.candidate_retries,
            "candidate_request_gap_seconds": [args.candidate_min_gap, args.candidate_max_gap],
            "candidate_errors_remain_in_verdict_denominator": True,
            "candidate_error_round_blocks_passing": False,
            "candidate_retry_round_blocks_passing": False,
            "network_quality_reported_separately": True,
            "juice_probe_enabled": not no_juice,
            "juice_repeats_per_effort": juice_repeats,
            "juice_high_mixing_zero_tolerance": True,
            "juice_known_cross_effort_conflict_zero_tolerance": True,
            "juice_mixing_flag_scope": "entire_run",
            "keys_persisted": False,
            "raw_ciphertext_persisted": False,
        },
        "summary": {
            "candidate_attempts": candidate_attempt_count,
            "complete_trials": complete_trial_count,
            "valid_trials": valid_count,
            "rejected_trusted_attempts": len(rejected_attempts),
            "candidate_full_exact": full_exact,
            "candidate_without_ids_exact": no_id_exact,
            "candidate_message_only_exact": message_exact,
            "candidate_corrupted_ciphertext_exact": corrupt_exact,
            "candidate_request_plaintext_leaks": plaintext_leaks,
            "candidate_request_errors": candidate_request_errors,
            "candidate_error_rounds": candidate_error_rounds,
            "candidate_retry_rounds": candidate_retry_rounds,
            "blind_guess_upper_tail_full": f"{blind_guess_tail_probability(full_exact, valid_count):.3e}",
            "blind_guess_upper_tail_without_ids": f"{blind_guess_tail_probability(no_id_exact, valid_count):.3e}",
        },
        "network_summary": network_summary,
        "juice_summary": juice_summary,
        "combined_summary": combined,
        "juice_observations": juice_observations,
        "candidate_attempts": valid_trials,
        "valid_trials": valid_trials,
        "rejected_attempts": rejected_attempts,
        "limitations": [
            "A candidate can pass by proxying to a compatible GPT-5.6 backend.",
            "A future or different model with backward-compatible reasoning decryption can pass.",
            "The probe establishes capability compatibility, not model weights, ownership, or hosting identity.",
            "Sol, Terra, and Luna share this observable compatibility and cannot be reliably distinguished here.",
            "Juice is an auxiliary visible-output fingerprint and can be spoofed by a relay.",
        ],
    }


def self_test() -> None:
    values = {
        "reverse": ("1234567891", "1987654321"),
        "rotate_left_3": ("1234567891", "4567891123"),
        "complement_9": ("1234567891", "8765432108"),
    }
    for task, (value, expected) in values.items():
        assert transform(task, value) == expected
    sample = [
        {"type": "reasoning", "id": "rs_1", "summary": [], "encrypted_content": "abcdef"},
        {"type": "message", "id": "msg_1", "content": [{"type": "output_text", "text": "READY"}]},
    ]
    assert len(context_variant(sample, "message_only")) == 1
    no_ids = context_variant(sample, "without_ids")
    assert all("id" not in item for item in no_ids)
    corrupted = context_variant(sample, "corrupted_ciphertext")
    assert corrupted[0]["encrypted_content"] != sample[0]["encrypted_content"]
    assert encrypted_fingerprints(sample)[0]["sha256"] == sha256("abcdef")
    assert classify_visible_answer("8.855")["normalized_value"] == "8.855"
    assert classify_visible_answer("I can't provide that.")["kind"] == "refusal"
    assert matching_models("high", "40855") == ["gpt_5_6_sol"]
    assert matching_models("high", "32") == ["gpt_5_6_terra"]
    assert matching_models("high", "48") == ["gpt_5_6_luna"]
    assert set(matching_models("low", "8")) == {
        "gpt_5_6_sol", "gpt_5_6_luna", "gpt_5_4_mini"
    }
    noisy_verdict, _ = encrypted_state_verdict(
        attempts=20,
        required_attempts=20,
        full_exact=16,
        without_ids_exact=15,
        required_matches=15,
        message_only_exact=0,
        corrupted_ciphertext_exact=0,
        plaintext_leaks=0,
    )
    assert noisy_verdict == "gpt_5_6_encrypted_state_compatible"
    assert connection_quality(1, 2)["status"] == "unstable"
    assert connection_quality(0, 2)["status"] == "intermittent"
    assert connection_quality(0, 0)["status"] == "smooth"

    def juice_observation(effort: str, value: str) -> dict[str, Any]:
        return {
            "effort": effort,
            "status": "ok",
            "answer_kind": "number",
            "normalized_value": value,
            "matched_models": matching_models(effort, value),
        }

    sol = [
        juice_observation("high", "40855"),
        juice_observation("low", "8"),
        juice_observation("high", "40850"),
        juice_observation("medium", "16"),
        juice_observation("high", "40855"),
    ]
    sol_summary = summarize_juice(sol)
    assert sol_summary["status"] == "classified"
    assert sol_summary["likely_model"] == "gpt_5_6_sol"
    assert sol_summary["confidence"] == "high"
    mixed = sol + [juice_observation("high", "48")] + [
        juice_observation("high", "40855") for _ in range(5)
    ]
    mixed_summary = summarize_juice(mixed)
    assert mixed_summary["status"] == "mixed_or_inconsistent"
    assert set(mixed_summary["session_distinct_high_groups"]) == {
        "gpt_5_6_sol", "gpt_5_6_luna"
    }
    print("自检：通过（模型判定与线路分离、juice 指纹、混用零容忍）")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trusted-base-url")
    parser.add_argument("--trusted-model", default="gpt-5.6-sol")
    parser.add_argument("--trusted-key-env", default="TRUSTED_API_KEY")
    parser.add_argument("--candidate-base-url")
    parser.add_argument("--candidate-model", default="gpt-5.6-sol")
    parser.add_argument("--candidate-key-env", default="CANDIDATE_API_KEY")
    parser.add_argument("--trials", type=int, default=12)
    parser.add_argument("--max-attempts", type=int)
    parser.add_argument("--min-match-rate", type=float, default=0.5)
    parser.add_argument("--min-matches", type=int, default=4)
    parser.add_argument("--candidate-retries", type=int, default=2)
    parser.add_argument("--candidate-min-gap", type=float, default=2.0)
    parser.add_argument("--candidate-max-gap", type=float, default=5.0)
    parser.add_argument("--juice-repeats", type=int, default=3)
    parser.add_argument("--no-juice", action="store_true")
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--output", type=Path, default=Path("gpt56_probe_report.json"))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return args
    if not args.trusted_base_url or not args.candidate_base_url:
        parser.error("--trusted-base-url and --candidate-base-url are required")
    if args.trials < 4:
        parser.error("--trials must be at least 4")
    if args.min_matches < 3:
        parser.error("--min-matches must be at least 3")
    if not 0 < args.min_match_rate <= 1:
        parser.error("--min-match-rate must be in (0, 1]")
    if not 0 <= args.candidate_retries <= 5:
        parser.error("--candidate-retries must be between 0 and 5")
    if args.candidate_min_gap < 0 or args.candidate_max_gap < args.candidate_min_gap:
        parser.error("candidate gaps must satisfy 0 <= min <= max")
    if not 1 <= args.juice_repeats <= 5:
        parser.error("juice-repeats must be between 1 and 5")
    return args


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        return 0
    report = run_probe(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print_probe_summary(report, args.output)
    if args.no_juice:
        return 0 if report["verdict"] == "gpt_5_6_encrypted_state_compatible" else 1
    return 0 if report["combined_verdict"] == "compatible_and_variant_consistent" else 1


if __name__ == "__main__":
    raise SystemExit(main())
