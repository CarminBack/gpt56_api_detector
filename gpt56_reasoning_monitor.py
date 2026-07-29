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
        "Privately reverse every digit of the ten-digit string {value}. Keep the exact result as B for a later turn. Show no digits or calculation; the visible reply must be exactly READY.",
        "In hidden reasoning, read {value} as a fixed-width ten-digit string, reverse its order, and retain that result under the name B. Reveal nothing except the single word READY.",
        "Compute B internally by writing the ten characters of {value} in reverse order. Preserve B for the next request. Do not expose any number or working. Respond only READY.",
    ),
    "rotate_left_3": (
        "Privately transform {value} by moving its first three digits to the end, preserving all other order. Retain the ten-digit result as B. The entire visible response must be READY.",
        "In hidden reasoning, rotate the fixed-width string {value} left by three positions and remember the result as B. Do not reveal digits or work; output only READY.",
        "Take {value} internally, append its first three characters after its last seven, and keep the exact result B for later recall. Show only READY.",
    ),
    "complement_9": (
        "For each digit d in {value}, privately replace it with 9-d. Retain the resulting ten-character string as B. Reveal no input, result, or work; answer only READY.",
        "In hidden reasoning, compute the digitwise nine-complement of {value} and preserve it as B for the next turn. The complete visible output must be READY.",
        "Privately map every character d of {value} to 9 minus d, keeping all positions. Store the exact ten-digit B. Do not print any number; print READY only.",
    ),
}

RECALL_PROMPTS = (
    "Return only the exact ten-digit B retained in the preceding hidden state. If that state is unavailable, return exactly UNKNOWN. Do not guess or recompute.",
    "Read the preceding hidden reasoning state and output its stored ten-digit value B, with no other text. If it cannot be read, output UNKNOWN exactly.",
    "Recover B solely from the immediately preceding hidden state. Reply with those ten digits only; when no readable B exists, reply UNKNOWN. Never invent a value.",
    "Output the exact fixed-width value named B from the prior hidden state. Use only that state, not inference. If absent or invalid, output exactly UNKNOWN.",
)

CONDITIONS = ("full", "without_ids", "message_only", "corrupted_ciphertext")


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
    client: ResponsesClient, model: str, context: list[Any], expected: str
) -> dict[str, Any]:
    prompt = choice(RECALL_PROMPTS)
    payload = recall_payload(model, context, prompt)
    serialized = json.dumps(redact(payload), ensure_ascii=False)
    if expected in serialized:
        return {
            "status": "invalid_probe",
            "exact": False,
            "plaintext_leak": True,
            "error": "expected value appeared in request plaintext",
        }
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
            "prompt_variant_sha256": sha256(prompt),
            **meta,
        }
    except ProbeError as exc:
        return {
            "status": "error",
            "exact": False,
            "plaintext_leak": False,
            "http_status": exc.status,
            "elapsed_ms": exc.elapsed_ms,
            "error": redact(str(exc)),
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
    trusted: ResponsesClient, candidate: ResponsesClient, trusted_model: str, candidate_model: str
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    task = choice(tuple(TASK_PROMPTS))
    input_value = random_ten_digits()
    expected = transform(task, input_value)
    seed_prompt = choice(TASK_PROMPTS[task]).format(value=input_value)
    try:
        seed, seed_meta = trusted.post(seed_payload(trusted_model, seed_prompt))
    except ProbeError as exc:
        return None, {
            "time": datetime.now(timezone.utc).isoformat(),
            "reason": "trusted_seed_error",
            "http_status": exc.status,
            "error": redact(str(exc)),
        }

    output = seed.get("output")
    visible = output_text(seed)
    if not isinstance(output, list):
        return None, {"time": datetime.now(timezone.utc).isoformat(), "reason": "missing_output_array"}
    fingerprints = encrypted_fingerprints(output)
    sanitized_output = json.dumps(redact(output), ensure_ascii=False)
    visible_leak = input_value in sanitized_output or expected in sanitized_output
    if visible != "READY" or not fingerprints or visible_leak:
        return None, {
            "time": datetime.now(timezone.utc).isoformat(),
            "reason": "invalid_trusted_seed",
            "visible_contract_ok": visible == "READY",
            "encrypted_reasoning_items": len(fingerprints),
            "visible_plaintext_leak": visible_leak,
        }

    trusted_self = call_and_score(trusted, trusted_model, context_variant(output, "full"), expected)
    if not trusted_self["exact"]:
        return None, {
            "time": datetime.now(timezone.utc).isoformat(),
            "reason": "trusted_state_not_self_verifiable",
            "trusted_self": trusted_self,
        }

    condition_order = shuffled(CONDITIONS)
    conditions: dict[str, Any] = {}
    for variant in condition_order:
        conditions[variant] = call_and_score(
            candidate, candidate_model, context_variant(output, variant), expected
        )

    return {
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
    }, None


def window_summary(trials: list[dict[str, Any]], window_size: int, required: int) -> dict[str, Any]:
    window = trials[-window_size:]
    count = len(window)
    exact = {
        name: sum(bool(item["candidate"][name]["exact"]) for item in window)
        for name in CONDITIONS
    }
    leaks = sum(
        bool(result.get("plaintext_leak"))
        for item in window
        for result in item["candidate"].values()
    )
    if count < window_size:
        verdict = "warming_up"
    elif leaks:
        verdict = "invalid"
    elif exact["message_only"] or exact["corrupted_ciphertext"]:
        verdict = "suspicious"
    elif exact["full"] >= required and exact["without_ids"] >= required:
        verdict = "gpt_5_6_encrypted_state_compatible"
    elif exact["full"] == 0 and exact["without_ids"] == 0:
        verdict = "not_compatible_in_this_window"
    else:
        verdict = "inconclusive"
    return {
        "verdict": verdict,
        "valid_trials_in_window": count,
        "window_size": window_size,
        "required_positive_matches": required,
        "full_exact": exact["full"],
        "without_ids_exact": exact["without_ids"],
        "message_only_exact": exact["message_only"],
        "corrupted_ciphertext_exact": exact["corrupted_ciphertext"],
        "plaintext_leaks": leaks,
    }


def atomic_write(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def random_interval(minimum: int, maximum: int) -> int:
    return minimum + secrets.randbelow(maximum - minimum + 1)


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
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--max-valid-trials", type=int, default=0)
    parser.add_argument("--output", type=Path, default=Path("gpt56-monitor-report.json"))
    args = parser.parse_args()
    if args.min_interval < 1 or args.max_interval < args.min_interval:
        parser.error("intervals must satisfy 1 <= min <= max")
    if args.window < 4 or not 1 <= args.required_matches <= args.window:
        parser.error("window and required-matches are invalid")
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
    rejected: list[dict[str, Any]] = []
    started = datetime.now(timezone.utc).isoformat()
    cycle = 0
    print("Continuous monitor started. Press Ctrl+C to stop.", flush=True)
    try:
        while not args.max_valid_trials or len(trials) < args.max_valid_trials:
            cycle += 1
            trial, failure = run_one_challenge(
                trusted, candidate, args.trusted_model, args.candidate_model
            )
            if trial is not None:
                trials.append(trial)
            elif failure is not None:
                rejected.append(failure)
            summary = window_summary(trials, args.window, args.required_matches)
            report = {
                "schema_version": 1,
                "mode": "continuous_randomized_monitor",
                "started_at": started,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "configuration": {
                    "trusted_base_url": args.trusted_base_url,
                    "trusted_model": args.trusted_model,
                    "candidate_base_url": args.candidate_base_url,
                    "candidate_model": args.candidate_model,
                    "random_interval_seconds": [args.min_interval, args.max_interval],
                    "rolling_window": args.window,
                    "required_positive_matches": args.required_matches,
                    "keys_persisted": False,
                    "raw_ciphertext_persisted": False,
                },
                "anti_classification_measures": [
                    "cryptographically random interval within configured range",
                    "fresh random challenge on every cycle",
                    "random task and seed-prompt wording",
                    "random recall wording for every request",
                    "randomized candidate condition order",
                ],
                "warning": (
                    "These measures reduce simple fixed-pattern detection only. A relay can still recognize "
                    "Responses reasoning replay or proxy all probe-like traffic to GPT-5.6."
                ),
                "cycles": cycle,
                "total_valid_trials": len(trials),
                "total_rejected_attempts": len(rejected),
                "rolling_summary": summary,
                "valid_trials": trials,
                "rejected_attempts": rejected,
            }
            atomic_write(args.output, report)
            print(
                f"[{report['updated_at']}] valid={len(trials)} rejected={len(rejected)} "
                f"window={summary['valid_trials_in_window']}/{args.window} "
                f"full={summary['full_exact']} no-id={summary['without_ids_exact']} "
                f"negative={summary['message_only_exact'] + summary['corrupted_ciphertext_exact']} "
                f"verdict={summary['verdict']}",
                flush=True,
            )
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


