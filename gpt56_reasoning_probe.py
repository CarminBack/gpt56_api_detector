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


def blind_guess_tail_probability(successes: int, trials: int) -> float:
    if successes <= 0:
        return 1.0
    p = 1e-10
    return sum(
        math.comb(trials, count) * (p**count) * ((1 - p) ** (trials - count))
        for count in range(successes, trials + 1)
    )


def run_probe(args: argparse.Namespace) -> dict[str, Any]:
    trusted_key = os.getenv(args.trusted_key_env)
    candidate_key = os.getenv(args.candidate_key_env)
    if not trusted_key:
        raise SystemExit(f"environment variable {args.trusted_key_env} is required")
    if not candidate_key:
        raise SystemExit(f"environment variable {args.candidate_key_env} is required")

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
            f"Attempt {attempt}/{max_attempts}: {task}, "
            f"valid {len(valid_trials)}/{args.trials}",
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
            continue

        output = seed.get("output")
        visible = output_text(seed)
        if not isinstance(output, list):
            rejected_attempts.append({"attempt": attempt, "reason": "missing_output_array"})
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
            continue

        conditions = {}
        for variant in ("full", "without_ids", "message_only", "corrupted_ciphertext"):
            conditions[variant] = call_and_score(
                candidate,
                args.candidate_model,
                context_variant(output, variant),
                expected,
            )
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

    def count_exact(condition: str) -> int:
        return sum(bool(trial["candidate"][condition]["exact"]) for trial in valid_trials)

    valid_count = len(valid_trials)
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
    required_matches = max(args.min_matches, math.ceil(args.min_match_rate * args.trials))

    if valid_count < args.trials:
        verdict = "inconclusive"
        reason = "trusted endpoint did not produce enough self-verifiable challenge states"
    elif candidate_request_errors:
        verdict = "inconclusive"
        reason = "one or more candidate requests failed before a usable model response was received"
    elif plaintext_leaks:
        verdict = "invalid"
        reason = "one or more candidate requests contained challenge plaintext"
    elif message_exact or corrupt_exact:
        verdict = "suspicious"
        reason = "a negative control unexpectedly matched the hidden challenge"
    elif full_exact >= required_matches and no_id_exact >= required_matches:
        verdict = "gpt_5_6_encrypted_state_compatible"
        reason = (
            "candidate repeatedly recovered trusted GPT-5.6 hidden values from encrypted state, "
            "including after response item IDs were removed"
        )
    elif full_exact == 0 and no_id_exact == 0:
        verdict = "not_compatible_in_this_probe"
        reason = "candidate recovered none of the trusted encrypted challenge states"
    else:
        verdict = "inconclusive"
        reason = "partial replay evidence did not reach the configured threshold"

    return {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
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
            "requested_valid_trials": args.trials,
            "max_attempts": max_attempts,
            "required_matches_per_positive_condition": required_matches,
            "min_match_rate": args.min_match_rate,
            "min_matches": args.min_matches,
            "keys_persisted": False,
            "raw_ciphertext_persisted": False,
        },
        "summary": {
            "valid_trials": valid_count,
            "rejected_trusted_attempts": len(rejected_attempts),
            "candidate_full_exact": full_exact,
            "candidate_without_ids_exact": no_id_exact,
            "candidate_message_only_exact": message_exact,
            "candidate_corrupted_ciphertext_exact": corrupt_exact,
            "candidate_request_plaintext_leaks": plaintext_leaks,
            "candidate_request_errors": candidate_request_errors,
            "blind_guess_upper_tail_full": f"{blind_guess_tail_probability(full_exact, valid_count):.3e}",
            "blind_guess_upper_tail_without_ids": f"{blind_guess_tail_probability(no_id_exact, valid_count):.3e}",
        },
        "valid_trials": valid_trials,
        "rejected_attempts": rejected_attempts,
        "limitations": [
            "A candidate can pass by proxying to a compatible GPT-5.6 backend.",
            "A future or different model with backward-compatible reasoning decryption can pass.",
            "The probe establishes capability compatibility, not model weights, ownership, or hosting identity.",
            "Sol, Terra, and Luna share this observable compatibility and cannot be reliably distinguished here.",
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
    print("self-test: PASS")


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
    return args


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        return 0
    report = run_probe(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"verdict": report["verdict"], "reason": report["reason"], "summary": report["summary"]}, ensure_ascii=False, indent=2))
    print(f"Sanitized report: {args.output.resolve()}")
    return 0 if report["verdict"] == "gpt_5_6_encrypted_state_compatible" else 1


if __name__ == "__main__":
    raise SystemExit(main())
