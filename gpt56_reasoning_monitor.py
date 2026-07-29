#!/usr/bin/env python3
"""Continuously monitor GPT-5.6 encrypted-state compatibility."""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import secrets
import time
from typing import Any

from gpt56_reasoning_probe import (
    ProbeError,
    ResponsesClient,
    context_variant,
    encrypted_fingerprints,
    output_text,
    random_ten_digits,
    redact,
    sha256,
    transform,
)


TASK_PROMPTS = {
    "reverse": (
        "In hidden reasoning, take the ten-digit input {value} and compute B by reversing all ten digits. Retain the exact ten-digit B for the next turn. Do not expose the input, B, intermediate work, or any hint in visible output. Your entire visible response must be exactly READY",
    ),
    "rotate_left_3": (
        "In hidden reasoning, take the ten-digit input {value} and compute B by moving its first three digits to the end without changing any other order. Retain the exact ten-digit B for the next turn. Reveal no digits or work. Your complete visible response must be exactly READY",
    ),
    "complement_9": (
        "In hidden reasoning, transform the ten-digit input {value} digit by digit using d -> 9-d and call the resulting ten-character digit string B. Retain B for the next turn. Do not reveal any input, result, or work. Your entire visible response must be exactly READY",
    ),
}
RECALL_PROMPT = (
    "Return only the exact ten-digit B retained in the preceding hidden state. "
    "If that state is unavailable, return exactly UNKNOWN. Do not guess or recompute."
)

CONDITIONS = ("full", "without_ids", "message_only", "corrupted_ciphertext")
TRANSIENT_HTTP_STATUSES = {429, 500, 502, 503, 504}


def choice(values: tuple[Any, ...] | list[Any]) -> Any:
    return values[secrets.randbelow(len(values))]


def shuffled(values: tuple[str, ...]) -> list[str]:
    remaining = list(values)
    result: list[str] = []
    while remaining:
        result.append(remaining.pop(secrets.randbelow(len(remaining))))
    return result


def recall_payload(model: str, context: list[Any], prompt: str) -> dict[str, Any]:
    return {
        "model": model,
        "input": copy.deepcopy(context) + [{"role": "user", "content": prompt}],
        "reasoning": {"effort": "high"},
        "include": ["reasoning.encrypted_content"],
        "store": False,
    }


def call_and_score(
    client: ResponsesClient,
    model: str,
    context: list[Any],
    expected: str,
    *,
    max_transport_attempts: int = 1,
    retry_base_seconds: float = 2.0,
) -> dict[str, Any]:
    payload = recall_payload(model, context, RECALL_PROMPT)
    serialized = json.dumps(redact(payload), ensure_ascii=False)
    if expected in serialized:
        return {
            "status": "invalid_probe",
            "exact": False,
            "plaintext_leak": True,
            "error": "expected value appeared in request plaintext",
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
                "prompt_variant_sha256": sha256(RECALL_PROMPT),
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

def seed_payload(model: str, prompt: str) -> dict[str, Any]:
    return {
        "model": model,
        "input": [{"role": "user", "content": prompt}],
        "reasoning": {"effort": "high"},
        "include": ["reasoning.encrypted_content"],
        "store": False,
    }


def run_one_challenge(
    trusted: ResponsesClient,
    candidate: ResponsesClient,
    trusted_model: str,
    candidate_model: str,
    task: str,
    candidate_retries: int,
    candidate_min_gap: float,
    candidate_max_gap: float,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    input_value = random_ten_digits()
    expected = transform(task, input_value)
    seed_prompt = choice(TASK_PROMPTS[task]).format(value=input_value)
    try:
        seed, seed_meta = trusted.post(seed_payload(trusted_model, seed_prompt))
    except ProbeError as exc:
        return None, {
            "time": datetime.now(timezone.utc).isoformat(),
            "reason": "trusted_seed_error",
            "task": task,
            "http_status": exc.status,
            "error": redact(str(exc)),
        }

    output = seed.get("output")
    visible = output_text(seed)
    if not isinstance(output, list):
        return None, {
            "time": datetime.now(timezone.utc).isoformat(),
            "reason": "missing_output_array",
            "task": task,
        }
    fingerprints = encrypted_fingerprints(output)
    sanitized_output = json.dumps(redact(output), ensure_ascii=False)
    visible_leak = input_value in sanitized_output or expected in sanitized_output
    if visible != "READY" or not fingerprints or visible_leak:
        return None, {
            "time": datetime.now(timezone.utc).isoformat(),
            "reason": "invalid_trusted_seed",
            "task": task,
            "visible_contract_ok": visible == "READY",
            "encrypted_reasoning_items": len(fingerprints),
            "visible_plaintext_leak": visible_leak,
        }

    trusted_self = call_and_score(
        trusted, trusted_model, context_variant(output, "full"), expected
    )
    if not trusted_self["exact"]:
        return None, {
            "time": datetime.now(timezone.utc).isoformat(),
            "reason": "trusted_state_not_self_verifiable",
            "task": task,
            "seed_prompt_variant_sha256": sha256(
                seed_prompt.replace(input_value, "{challenge}")
            ),
            "trusted_self": trusted_self,
        }

    condition_order = shuffled(CONDITIONS)
    conditions: dict[str, Any] = {}
    for index, variant in enumerate(condition_order):
        conditions[variant] = call_and_score(
            candidate,
            candidate_model,
            context_variant(output, variant),
            expected,
            max_transport_attempts=candidate_retries + 1,
        )
        if index + 1 < len(condition_order):
            time.sleep(random_float(candidate_min_gap, candidate_max_gap))

    record = {
        "time": datetime.now(timezone.utc).isoformat(),
        "task": task,
        "seed_prompt_variant_sha256": sha256(seed_prompt.replace(input_value, "{challenge}")),
        "condition_order": condition_order,
        "expected_sha256": sha256(expected),
        "trusted_seed": {
            **seed_meta,
            "encrypted_items": fingerprints,
            "plaintext_leak": False,
        },
        "trusted_self": trusted_self,
        "candidate": conditions,
    }
    errors = {
        variant: result
        for variant, result in conditions.items()
        if result.get("status") == "error"
    }
    if errors:
        return None, {
            "time": record["time"],
            "reason": "candidate_request_error",
            "task": task,
            "conditions": errors,
            "candidate_attempt": record,
        }
    return record, None

def window_summary(
    attempts: list[dict[str, Any]], window_size: int, required: int
) -> dict[str, Any]:
    window = attempts[-window_size:]
    attempt_count = len(window)
    error_rounds = sum(
        any(result.get("status") == "error" for result in item["candidate"].values())
        for item in window
    )
    retry_rounds = sum(
        any(result.get("transport_attempts", 1) > 1 for result in item["candidate"].values())
        for item in window
    )
    complete_count = attempt_count - error_rounds
    exact = {
        name: sum(bool(item["candidate"][name].get("exact")) for item in window)
        for name in CONDITIONS
    }
    leaks = sum(
        bool(result.get("plaintext_leak"))
        for item in window
        for result in item["candidate"].values()
    )
    task_counts = {
        task: sum(item.get("task") == task for item in window) for task in TASK_PROMPTS
    }
    if attempt_count < window_size:
        verdict = "warming_up"
    elif leaks:
        verdict = "invalid"
    elif exact["message_only"] or exact["corrupted_ciphertext"]:
        verdict = "suspicious"
    elif error_rounds or retry_rounds:
        verdict = "inconclusive_candidate_unstable"
    elif exact["full"] >= required and exact["without_ids"] >= required:
        verdict = "gpt_5_6_encrypted_state_compatible"
    elif exact["full"] == 0 and exact["without_ids"] == 0:
        verdict = "not_compatible_in_this_window"
    else:
        verdict = "inconclusive"
    return {
        "verdict": verdict,
        "candidate_attempts_in_window": attempt_count,
        "complete_trials_in_window": complete_count,
        "valid_trials_in_window": complete_count,
        "candidate_error_rounds": error_rounds,
        "candidate_retry_rounds": retry_rounds,
        "window_size": window_size,
        "required_positive_matches": required,
        "full_exact": exact["full"],
        "without_ids_exact": exact["without_ids"],
        "message_only_exact": exact["message_only"],
        "corrupted_ciphertext_exact": exact["corrupted_ciphertext"],
        "plaintext_leaks": leaks,
        "task_counts": task_counts,
    }

def atomic_write(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def random_interval(minimum: int, maximum: int) -> int:
    return minimum + secrets.randbelow(maximum - minimum + 1)

def random_float(minimum: float, maximum: float) -> float:
    if maximum <= minimum:
        return minimum
    return minimum + (maximum - minimum) * (secrets.randbelow(1_000_001) / 1_000_000)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trusted-base-url", required=True)
    parser.add_argument("--trusted-model", default="gpt-5.6-sol")
    parser.add_argument("--candidate-base-url", required=True)
    parser.add_argument("--candidate-model", default="gpt-5.6-sol")
    parser.add_argument("--trusted-key-env", default="TRUSTED_API_KEY")
    parser.add_argument("--candidate-key-env", default="CANDIDATE_API_KEY")
    parser.add_argument("--min-interval", type=int, default=20)
    parser.add_argument("--max-interval", type=int, default=40)
    parser.add_argument("--window", type=int, default=20)
    parser.add_argument("--required-matches", type=int, default=15)
    parser.add_argument("--candidate-retries", type=int, default=2)
    parser.add_argument("--candidate-min-gap", type=float, default=2.0)
    parser.add_argument("--candidate-max-gap", type=float, default=5.0)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--max-valid-trials", type=int, default=0)
    parser.add_argument("--output", type=Path, default=Path("gpt56-monitor-report.json"))
    args = parser.parse_args()
    if args.min_interval < 1 or args.max_interval < args.min_interval:
        parser.error("intervals must satisfy 1 <= min <= max")
    if args.window < 4 or not 1 <= args.required_matches <= args.window:
        parser.error("window and required-matches are invalid")
    if not 0 <= args.candidate_retries <= 5:
        parser.error("candidate-retries must be between 0 and 5")
    if args.candidate_min_gap < 0 or args.candidate_max_gap < args.candidate_min_gap:
        parser.error("candidate gaps must satisfy 0 <= min <= max")
    return args


def main() -> int:
    args = parse_args()
    trusted_key = os.getenv(args.trusted_key_env)
    candidate_key = os.getenv(args.candidate_key_env)
    if not trusted_key or not candidate_key:
        raise SystemExit("trusted and candidate key environment variables are required")
    trusted = ResponsesClient(args.trusted_base_url, trusted_key, args.timeout)
    candidate = ResponsesClient(args.candidate_base_url, candidate_key, args.timeout)
    trials: list[dict[str, Any]] = []
    candidate_attempts: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    started = datetime.now(timezone.utc).isoformat()
    cycle = 0
    tasks = tuple(TASK_PROMPTS)
    print("Continuous monitor v2 started. Press Ctrl+C to stop.", flush=True)
    try:
        while not args.max_valid_trials or len(trials) < args.max_valid_trials:
            cycle += 1
            task = tasks[len(candidate_attempts) % len(tasks)]
            trial, failure = run_one_challenge(
                trusted,
                candidate,
                args.trusted_model,
                args.candidate_model,
                task,
                args.candidate_retries,
                args.candidate_min_gap,
                args.candidate_max_gap,
            )
            if trial is not None:
                trials.append(trial)
                candidate_attempts.append(trial)
            elif failure is not None:
                candidate_attempt = failure.pop("candidate_attempt", None)
                if candidate_attempt is not None:
                    candidate_attempts.append(candidate_attempt)
                rejected.append(failure)
            summary = window_summary(
                candidate_attempts, args.window, args.required_matches
            )
            report = {
                "schema_version": 2,
                "mode": "continuous_balanced_monitor",
                "started_at": started,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "configuration": {
                    "trusted_base_url": args.trusted_base_url,
                    "trusted_model": args.trusted_model,
                    "candidate_base_url": args.candidate_base_url,
                    "candidate_model": args.candidate_model,
                    "random_interval_seconds": [args.min_interval, args.max_interval],
                    "candidate_request_gap_seconds": [
                        args.candidate_min_gap,
                        args.candidate_max_gap,
                    ],
                    "candidate_transient_retries": args.candidate_retries,
                    "rolling_window": args.window,
                    "required_positive_matches": args.required_matches,
                    "candidate_errors_remain_in_window_denominator": True,
                    "candidate_retry_round_blocks_passing": True,
                    "keys_persisted": False,
                    "raw_ciphertext_persisted": False,
                },
                "experiment_controls": [
                    "canonical recall prompt selected from empirical trusted-endpoint stability data",
                    "same canonical recall prompt for every condition",
                    "balanced task rotation across candidate attempts",
                    "fresh random challenge on every cycle",
                    "canonical seed and recall prompts selected for trusted-state stability",
                    "randomized candidate condition order",
                    "random gap between candidate condition requests",
                    "bounded randomized backoff for transient candidate transport errors",
                    "candidate error and retry rounds remain in the verdict window",
                ],
                "warning": (
                    "Randomization reduces simple fixed-pattern detection only. A relay can still recognize "
                    "Responses reasoning replay or proxy all probe-like traffic to GPT-5.6."
                ),
                "cycles": cycle,
                "total_candidate_attempts": len(candidate_attempts),
                "total_valid_trials": len(trials),
                "total_rejected_attempts": len(rejected),
                "rolling_summary": summary,
                "candidate_attempts": candidate_attempts,
                "valid_trials": trials,
                "rejected_attempts": rejected,
            }
            atomic_write(args.output, report)
            print(
                f"[{report['updated_at']}] attempts={len(candidate_attempts)} "
                f"complete={len(trials)} rejected={len(rejected)} "
                f"window={summary['candidate_attempts_in_window']}/{args.window} "
                f"full={summary['full_exact']} no-id={summary['without_ids_exact']} "
                f"errors={summary['candidate_error_rounds']} "
                f"retries={summary['candidate_retry_rounds']} "
                f"negative={summary['message_only_exact'] + summary['corrupted_ciphertext_exact']} "
                f"verdict={summary['verdict']}",
                flush=True,
            )
            if failure is not None:
                statuses = sorted(
                    {
                        result.get("http_status")
                        for result in failure.get("conditions", {}).values()
                        if result.get("http_status") is not None
                    }
                )
                detail = f" HTTP={statuses}" if statuses else ""
                print(f"Last attempt rejected: {failure['reason']}.{detail}", flush=True)
            if args.max_valid_trials and len(trials) >= args.max_valid_trials:
                break
            delay = random_interval(args.min_interval, args.max_interval)
            print(f"Next challenge in {delay} seconds.", flush=True)
            time.sleep(delay)
    except KeyboardInterrupt:
        print("\nMonitor stopped by user. The latest report has been saved.", flush=True)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())


