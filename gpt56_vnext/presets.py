from __future__ import annotations

from copy import deepcopy
import hashlib
import math
from typing import Any

from .generator import probe_document
from .utils import canonical_json


CONFIG_SCHEMA_VERSION = 2
FORMATS = ("normal", "native_codex")
CONTEXTS = ("no_history", "fixed_32k_history")
PROBABILITY_PROBES = ("rand_country", "rand_bird", "b80_letter_count")
DEFAULT_PROBABILITY_NORMALIZER = {"id": "exact_trimmed_casefold", "parameters": {}}


SINGLE_PRESETS: dict[str, dict[str, Any]] = {
    "low": {
        "mode": "single", "workers": 8, "retries": 2,
        "request_formats": ["normal"], "context_modes": ["no_history"],
        "probes": {
            "juice_high": {"enabled": True, "requests": 5, "effort": "high"},
            "juice_low": {"enabled": True, "requests": 2, "effort": "low"},
            "output_luna_48": {"enabled": True, "requests": 1},
            "output_terra_32": {"enabled": True, "requests": 1},
            "juice_coverage": {"enabled": True, "requests": 1},
            "rand_country": {"enabled": True, "requests": 3, "effort": "low", "window": 3},
            "rand_bird": {"enabled": True, "requests": 3, "effort": "low", "window": 3},
            "b80_letter_count": {"enabled": True, "requests": 3, "effort": "low", "window": 3},
        },
    },
    "medium": {
        "mode": "single", "workers": 8, "retries": 2,
        "request_formats": ["normal"], "context_modes": ["no_history"],
        "probes": {
            "juice_high": {"enabled": True, "requests": 6, "effort": "high"},
            "juice_low": {"enabled": True, "requests": 3, "effort": "low"},
            "juice_xhigh": {"enabled": True, "requests": 3, "effort": "xhigh"},
            "juice_max": {"enabled": True, "requests": 3, "effort": "max"},
            "output_luna_48": {"enabled": True, "requests": 1},
            "output_terra_32": {"enabled": True, "requests": 1},
            "juice_coverage": {"enabled": True, "requests": 2},
            "rand_country": {"enabled": True, "requests": 10, "effort": "low", "window": 10},
            "rand_bird": {"enabled": True, "requests": 10, "effort": "low", "window": 10},
            "b80_letter_count": {"enabled": True, "requests": 10, "effort": "low", "window": 10},
        },
    },
    "high": {
        "mode": "single", "workers": 8, "retries": 2,
        "request_formats": ["normal", "native_codex"],
        "context_modes": ["no_history", "fixed_32k_history"],
        "probes": {
            "juice_high": {"enabled": True, "requests": 5, "effort": "high"},
            "juice_low": {"enabled": True, "requests": 2, "effort": "low"},
            "juice_medium": {"enabled": True, "requests": 2, "effort": "medium"},
            "juice_xhigh": {"enabled": True, "requests": 2, "effort": "xhigh"},
            "juice_max": {"enabled": True, "requests": 2, "effort": "max"},
            "output_luna_48": {"enabled": True, "requests": 1},
            "output_terra_32": {"enabled": True, "requests": 1},
            "juice_coverage": {"enabled": True, "requests": 2},
            "rand_country": {"enabled": True, "requests": 10, "effort": "low", "window": 10},
            "rand_bird": {"enabled": True, "requests": 10, "effort": "low", "window": 10},
            "b80_letter_count": {
                "enabled": True, "requests": 10, "effort": "low", "window": 10,
                "profiles": ["normal+no_history"],
            },
        },
    },
}

CONTINUOUS_PRESETS: dict[str, dict[str, Any]] = {
    "low": {
        "mode": "continuous", "workers": 8, "retries": 2,
        "min_interval_seconds": 150, "max_interval_seconds": 210, "slots_per_cycle": 1,
        "request_formats": ["normal"], "context_modes": ["no_history"],
        "probes": {
            "juice_high": {"enabled": True, "probability_percent": 100, "window": 10, "effort": "high"},
            "juice_low": {"enabled": True, "probability_percent": 50, "window": 5, "effort": "low"},
            "output_integrity": {"enabled": True, "probability_percent": 25, "window": 5},
            "juice_coverage": {"enabled": True, "probability_percent": 25, "window": 5},
            "rand_country": {"enabled": True, "probability_percent": 50, "window": 3, "effort": "low"},
            "rand_bird": {"enabled": True, "probability_percent": 50, "window": 3, "effort": "low"},
            "b80_letter_count": {"enabled": True, "probability_percent": 50, "window": 3, "effort": "low"},
        },
    },
    "medium": {
        "mode": "continuous", "workers": 8, "retries": 2,
        "min_interval_seconds": 240, "max_interval_seconds": 360, "slots_per_cycle": 1,
        "request_formats": ["normal"], "context_modes": ["no_history"],
        "probes": {
            "juice_high": {"enabled": True, "probability_percent": 100, "window": 10, "effort": "high"},
            "juice_low": {"enabled": True, "probability_percent": 50, "window": 5, "effort": "low"},
            "juice_xhigh": {"enabled": True, "probability_percent": 25, "window": 10, "effort": "xhigh"},
            "juice_max": {"enabled": True, "probability_percent": 25, "window": 10, "effort": "max"},
            "output_integrity": {"enabled": True, "probability_percent": 25, "window": 5},
            "juice_coverage": {"enabled": True, "probability_percent": 25, "window": 5},
            "rand_country": {"enabled": True, "probability_percent": 50, "window": 10, "effort": "low"},
            "rand_bird": {"enabled": True, "probability_percent": 50, "window": 10, "effort": "low"},
            "b80_letter_count": {"enabled": True, "probability_percent": 50, "window": 10, "effort": "low"},
        },
    },
    "high": {
        "mode": "continuous", "workers": 8, "retries": 2,
        "min_interval_seconds": 480, "max_interval_seconds": 720, "slots_per_cycle": 1,
        "request_formats": ["normal", "native_codex"],
        "context_modes": ["no_history", "fixed_32k_history"],
        "probes": {
            "juice_high": {"enabled": True, "probability_percent": 100, "window": 20, "effort": "high"},
            "juice_low": {"enabled": True, "probability_percent": 25, "window": 10, "effort": "low"},
            "juice_medium": {"enabled": True, "probability_percent": 25, "window": 10, "effort": "medium"},
            "juice_xhigh": {"enabled": True, "probability_percent": 25, "window": 10, "effort": "xhigh"},
            "juice_max": {"enabled": True, "probability_percent": 25, "window": 10, "effort": "max"},
            "output_integrity": {"enabled": True, "probability_percent": 25, "window": 20},
            "juice_coverage": {"enabled": True, "probability_percent": 25, "window": 20},
            "rand_country": {"enabled": True, "probability_percent": 50, "window": 20, "effort": "low"},
            "rand_bird": {"enabled": True, "probability_percent": 50, "window": 20, "effort": "low"},
            "b80_letter_count": {
                "enabled": True, "probability_percent": 50, "window": 20, "effort": "low",
                "profiles": ["normal+no_history"],
            },
        },
    },
}


def _source(mode: str) -> dict[str, dict[str, Any]]:
    if mode == "single":
        return SINGLE_PRESETS
    if mode == "continuous":
        return CONTINUOUS_PRESETS
    raise ValueError("mode must be single or continuous")


def _detection_parameters(config: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": CONFIG_SCHEMA_VERSION,
        "mode": config["mode"],
        "workers": int(config["workers"]),
        "retries": int(config["retries"]),
        "request_formats": list(config["request_formats"]),
        "context_modes": list(config["context_modes"]),
        "probes": deepcopy(config["probes"]),
        "custom_probes": deepcopy(config.get("custom_probes", [])),
        **({
            "min_interval_seconds": int(config["min_interval_seconds"]),
            "max_interval_seconds": int(config["max_interval_seconds"]),
            "slots_per_cycle": int(config["slots_per_cycle"]),
        } if config["mode"] == "continuous" else {}),
    }


def config_hash(config: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(_detection_parameters(config)).encode("utf-8")).hexdigest()


def get_preset(mode: str, preset: str) -> dict[str, Any]:
    source = _source(mode)
    if preset not in source:
        raise ValueError(f"unsupported preset: {preset}")
    value = deepcopy(source[preset])
    value.update({
        "schema_version": CONFIG_SCHEMA_VERSION,
        "preset": preset,
        "base_preset": preset,
        "official": True,
    })
    value["config_hash"] = config_hash(value)
    return value


def selected_profiles(config: dict[str, Any]) -> list[str]:
    return [
        f"{request_format}+{context_mode}"
        for request_format in config["request_formats"]
        for context_mode in config["context_modes"]
    ]


def normalize_config(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("config must be an object")
    mode = str(value.get("mode") or "")
    source = _source(mode)
    requested = str(value.get("base_preset") or value.get("preset") or "low")
    if requested not in source:
        requested = "low"
    base = get_preset(mode, requested)
    config = deepcopy(base)
    for key in (
        "workers", "retries", "request_formats", "context_modes", "probes", "custom_probes",
        "min_interval_seconds", "max_interval_seconds", "slots_per_cycle",
    ):
        if key in value:
            config[key] = deepcopy(value[key])
    workers = int(config.get("workers", 8))
    retries = int(config.get("retries", 2))
    if not 1 <= workers <= 32:
        raise ValueError("workers must be 1-32")
    if not 0 <= retries <= 2:
        raise ValueError("retries must be 0-2")
    formats = list(dict.fromkeys(str(item) for item in config.get("request_formats") or []))
    contexts = list(dict.fromkeys(str(item) for item in config.get("context_modes") or []))
    if not formats or any(item not in FORMATS for item in formats):
        raise ValueError("invalid request_formats")
    if not contexts or any(item not in CONTEXTS for item in contexts):
        raise ValueError("invalid context_modes")
    probes = config.get("probes")
    if not isinstance(probes, dict):
        raise ValueError("probes must be an object")
    normalized_probes: dict[str, dict[str, Any]] = {}
    for probe_id, raw in probes.items():
        if not isinstance(raw, dict):
            raise ValueError(f"probe config is invalid: {probe_id}")
        probe = deepcopy(raw)
        probe["enabled"] = bool(probe.get("enabled"))
        if mode == "single":
            requests = int(probe.get("requests", 0))
            if not 0 <= requests <= 100000:
                raise ValueError(f"requests out of range: {probe_id}")
            probe["requests"] = requests
        else:
            probability = int(probe.get("probability_percent", 0))
            window = int(probe.get("window", 1))
            if not 0 <= probability <= 100 or not 1 <= window <= 100000:
                raise ValueError(f"continuous probe parameters out of range: {probe_id}")
            probe["probability_percent"] = probability
            probe["window"] = window
        if "profiles" in probe:
            profiles = [str(item) for item in probe["profiles"]]
            if any("+" not in item for item in profiles):
                raise ValueError(f"invalid probe profiles: {probe_id}")
            probe["profiles"] = profiles
        normalized_probes[str(probe_id)] = probe
    custom_values = config.get("custom_probes") or []
    if not isinstance(custom_values, list):
        raise ValueError("custom_probes must be an array")
    normalized_custom: list[dict[str, Any]] = []
    for raw_custom in custom_values:
        if not isinstance(raw_custom, dict):
            raise ValueError("custom probe config is invalid")
        custom = deepcopy(raw_custom)
        custom["enabled"] = bool(custom.get("enabled", True))
        runtime_requests = int(custom.get("runtime_requests", 10))
        probability = int(custom.get("probability_percent", 100))
        window = int(custom.get("window", 20))
        if not 1 <= runtime_requests <= 100000:
            raise ValueError("custom probe runtime_requests must be 1-100000")
        if not 0 <= probability <= 100 or not 1 <= window <= 100000:
            raise ValueError("custom continuous probe parameters are out of range")
        custom.update({"runtime_requests": runtime_requests, "probability_percent": probability, "window": window})
        normalized_custom.append(custom)
    config.update({
        "schema_version": CONFIG_SCHEMA_VERSION,
        "mode": mode,
        "workers": workers,
        "retries": retries,
        "request_formats": formats,
        "context_modes": contexts,
        "probes": normalized_probes,
        "custom_probes": normalized_custom,
        "base_preset": requested,
    })
    if mode == "continuous":
        minimum = int(config.get("min_interval_seconds", 0))
        maximum = int(config.get("max_interval_seconds", minimum))
        slots = int(config.get("slots_per_cycle", 1))
        if minimum < 0 or maximum < minimum or slots < 1:
            raise ValueError("invalid continuous scheduler parameters")
        config.update({"min_interval_seconds": minimum, "max_interval_seconds": maximum, "slots_per_cycle": slots})
    observed_hash = config_hash(config)
    matched = None
    for name in source:
        if observed_hash == get_preset(mode, name)["config_hash"]:
            matched = name
            break
    config["official"] = matched is not None
    config["preset"] = matched or "custom"
    config["config_hash"] = observed_hash
    return config


def preset_catalog() -> dict[str, Any]:
    return {
        "schema_version": CONFIG_SCHEMA_VERSION,
        "single_presets": {name: get_preset("single", name) for name in SINGLE_PRESETS},
        "continuous_presets": {name: get_preset("continuous", name) for name in CONTINUOUS_PRESETS},
        "schema": {
            "workers": {"type": "integer", "min": 1, "max": 32, "default": 8},
            "retries": {"type": "integer", "min": 0, "max": 2, "default": 2},
            "request_formats": list(FORMATS),
            "context_modes": list(CONTEXTS),
            "official_rule": "normalized detection parameter hash must exactly match an embedded preset hash",
        },
    }


def estimate_single_requests(config: dict[str, Any]) -> dict[str, int]:
    config = normalize_config(config)
    profiles = selected_profiles(config)
    total = 0
    long_context = 0
    for probe in config["probes"].values():
        if not probe.get("enabled"):
            continue
        applicable = probe.get("profiles") or profiles
        count = int(probe.get("requests", 0))
        total += count * len(applicable)
        long_context += count * sum(profile.endswith("fixed_32k_history") for profile in applicable)
    for custom in config.get("custom_probes", []):
        if custom.get("enabled", True) is False:
            continue
        document = probe_document(custom)
        probe_id = str((document.get("probe_identity") or {}).get("probe_id") or "")
        artifact = document.get("baseline_artifact") or {}
        available = set(((artifact.get("raw_counts") or {}).get(probe_id, {}).get("profiles") or {}))
        if not available:
            available = set(document.get("trusted_counts_by_model", {}))
        applicable = [profile for profile in profiles if profile in available]
        count = int(custom.get("runtime_requests", 10))
        total += count * len(applicable)
        long_context += count * sum(profile.endswith("fixed_32k_history") for profile in applicable)
    return {
        "total_requests": total,
        "fixed_32k_requests": long_context,
        "approximate_fixed_32k_input_tokens": long_context * 33792,
    }


def _estimate_messages(probe_id: str, probe: dict[str, Any], catalog: dict[str, Any]) -> list[dict[str, str]]:
    if probe_id.startswith("juice_") and probe_id != "juice_coverage":
        effort = str(probe.get("effort") or probe_id.removeprefix("juice_") or "high")
        candidates = [
            str(catalog["templates"][template_id]["prompt"]).replace("{nonce}", "000000000000")
            for template_id in (catalog["pools"].get(effort) or [])
        ]
        if not candidates:
            raise ValueError(f"no calibrated Juice templates for {effort}")
        return [{"role": "user", "content": max(candidates, key=lambda value: len(value.encode('utf-8')))}]
    if probe_id == "output_luna_48" or probe_id == "output_integrity":
        return [{"role": "user", "content": "Reply with exactly the two ASCII digits 48. Do not add any other text."}]
    if probe_id == "output_terra_32":
        return [{"role": "user", "content": "Reply with exactly the two ASCII digits 32. Do not add any other text."}]
    if probe_id == "juice_coverage":
        return [
            {"role": str(item["role"]), "content": str(item["content"]).replace("{synthetic_value}", "55555")}
            for item in catalog["coverage_probe"]["messages"]
        ]
    behavior = catalog["behavior_probes"].get(probe_id)
    if behavior:
        return [{"role": "user", "content": str(behavior["prompt"])}]
    raise ValueError(f"unknown probe for estimate: {probe_id}")


def _message_token_estimate(messages: list[dict[str, str]]) -> int:
    return sum(math.ceil(len(str(item.get("content") or "").encode("utf-8")) / 3) + 8 for item in messages)


def _native_base_token_estimate() -> int:
    from .transport import RAW_PROFILE

    raw = RAW_PROFILE.read_bytes()
    separator = b"\r\n\r\n"
    if separator not in raw:
        raise ValueError("原生请求模板缺少HTTP正文")
    return math.ceil(len(raw.split(separator, 1)[1]) / 3)


def estimate_plan(config: dict[str, Any]) -> dict[str, Any]:
    from .catalog import load_catalog

    config = normalize_config(config)
    catalog = load_catalog()
    profiles = selected_profiles(config)
    native_base = _native_base_token_estimate()
    totals = {
        "total_requests": 0.0,
        "fixed_32k_requests": 0.0,
        "short_request_input_tokens": 0.0,
        "native_base_input_tokens": 0.0,
        "fixed_32k_input_tokens": 0.0,
    }

    def add(messages: list[dict[str, str]], applicable: list[str], multiplier: float) -> None:
        short = _message_token_estimate(messages)
        for profile in applicable:
            totals["total_requests"] += multiplier
            totals["short_request_input_tokens"] += short * multiplier
            if profile.startswith("native_codex+"):
                totals["native_base_input_tokens"] += native_base * multiplier
            if profile.endswith("fixed_32k_history"):
                totals["fixed_32k_requests"] += multiplier
                totals["fixed_32k_input_tokens"] += 33792 * multiplier

    for probe_id, probe in config["probes"].items():
        if not probe.get("enabled"):
            continue
        applicable = list(probe.get("profiles") or profiles)
        multiplier = (
            float(probe.get("requests", 0))
            if config["mode"] == "single"
            else float(config.get("slots_per_cycle", 1)) * float(probe.get("probability_percent", 0)) / 100.0
        )
        add(_estimate_messages(probe_id, probe, catalog), applicable, multiplier)
    for custom in config.get("custom_probes", []):
        if custom.get("enabled", True) is False:
            continue
        document = probe_document(custom)
        prompts = document.get("exact_prompts_and_hashes") or {}
        developer = str(prompts.get("developer_prompt") or "")
        user = str(prompts.get("user_prompt") or "")
        messages = ([{"role": "developer", "content": developer}] if developer else []) + [{"role": "user", "content": user}]
        artifact = document.get("baseline_artifact") or {}
        probe_id = str((document.get("probe_identity") or {}).get("probe_id") or "")
        available = set((((artifact.get("raw_counts") or {}).get(probe_id) or {}).get("profiles") or {}).keys())
        if not available:
            available.update((document.get("trusted_counts_by_model") or {}).keys())
        applicable = [profile for profile in profiles if profile in available]
        multiplier = (
            float(custom.get("runtime_requests", 10))
            if config["mode"] == "single"
            else float(config.get("slots_per_cycle", 1)) * float(custom.get("probability_percent", 100)) / 100.0
        )
        add(messages, applicable, multiplier)
    total_tokens = totals["short_request_input_tokens"] + totals["native_base_input_tokens"] + totals["fixed_32k_input_tokens"]
    result: dict[str, Any] = {
        **{key: (int(value) if config["mode"] == "single" else round(value, 3)) for key, value in totals.items()},
        "approximate_input_tokens_total": int(math.ceil(total_tokens)) if config["mode"] == "single" else round(total_tokens, 3),
        "estimate_method": "UTF-8字节/3 + 每条消息8；Native基础取原始模板正文；固定32K每条加33792",
        "estimate_disclaimer_cn": "仅用于比较档位消耗，不是上游账单精确值。",
        "continuous": config["mode"] == "continuous",
    }
    if config["mode"] == "continuous":
        result["expected_requests_per_cycle"] = result.pop("total_requests")
        result["expected_fixed_32k_requests_per_cycle"] = result.pop("fixed_32k_requests")
        result["expected_input_tokens_per_cycle"] = result.pop("approximate_input_tokens_total")
    return result


def custom_changes(config: dict[str, Any], base_preset: str | None = None) -> list[str]:
    normalized = normalize_config(config)
    base_name = base_preset or normalized.get("base_preset") or "low"
    base = get_preset(normalized["mode"], str(base_name))
    current = _detection_parameters(normalized)
    reference = _detection_parameters(base)
    return sorted(key for key in set(current) | set(reference) if current.get(key) != reference.get(key))


def _contract_from_metadata(probe_id: str, profile: str, metadata: dict[str, Any]) -> dict[str, Any]:
    request_format, context_mode = profile.split("+", 1)
    normalizer = deepcopy(metadata.get("normalizer") or DEFAULT_PROBABILITY_NORMALIZER)
    return {
        "probe_id": probe_id,
        "profile": profile,
        "user_prompt_sha256": str(metadata.get("user_prompt_sha256") or ""),
        "developer_prompt_sha256": str(metadata.get("developer_prompt_sha256") or hashlib.sha256(b"").hexdigest()),
        "effort": str(metadata.get("effort") or "low"),
        "request_format": request_format,
        "context_mode": context_mode,
        "normalizer_hash": str(metadata.get("normalizer_hash") or hashlib.sha256(canonical_json(normalizer).encode("utf-8")).hexdigest()),
    }


def _builtin_probability_metadata() -> dict[str, dict[str, Any]]:
    from .catalog import load_catalog
    from .normalizers import builtin_probability_normalizer

    empty_hash = hashlib.sha256(b"").hexdigest()
    result: dict[str, dict[str, Any]] = {}
    for probe_id, value in load_catalog()["behavior_probes"].items():
        if probe_id not in PROBABILITY_PROBES:
            continue
        normalizer = builtin_probability_normalizer(probe_id)
        result[probe_id] = {
            "user_prompt_sha256": str(value["prompt_sha256"]),
            "developer_prompt_sha256": empty_hash,
            "effort": "low",
            "normalizer": normalizer,
            "normalizer_hash": hashlib.sha256(canonical_json(normalizer).encode("utf-8")).hexdigest(),
        }
    return result


def _custom_probability_metadata(custom: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    custom = probe_document(custom)
    identity = custom.get("probe_identity") or {}
    prompts = custom.get("exact_prompts_and_hashes") or {}
    profile = custom.get("profile") or {}
    probe_id = str(identity.get("probe_id") or "")
    normalizer = deepcopy(custom.get("normalizer") or DEFAULT_PROBABILITY_NORMALIZER)
    metadata = {
        "user_prompt_sha256": str(prompts.get("user_prompt_sha256") or ""),
        "developer_prompt_sha256": str(prompts.get("developer_prompt_sha256") or hashlib.sha256(b"").hexdigest()),
        "effort": str(profile.get("effort") or "low"),
        "normalizer": normalizer,
        "normalizer_hash": hashlib.sha256(canonical_json(normalizer).encode("utf-8")).hexdigest(),
    }
    return probe_id, metadata


def probability_runtime_spec(config: dict[str, Any]) -> dict[str, Any] | None:
    config = normalize_config(config)
    profiles = selected_profiles(config)
    cells: dict[str, int] = {}
    contracts: dict[str, dict[str, Any]] = {}
    builtin_metadata = _builtin_probability_metadata()
    for probe_id in PROBABILITY_PROBES:
        probe = config["probes"].get(probe_id, {})
        if not probe.get("enabled"):
            continue
        applicable = probe.get("profiles") or profiles
        required = int(probe.get("requests" if config["mode"] == "single" else "window", 0))
        for profile in applicable:
            key = f"{probe_id}|{profile}"
            cells[key] = required
            contracts[key] = _contract_from_metadata(probe_id, profile, builtin_metadata[probe_id])
    for custom in config.get("custom_probes", []):
        if custom.get("enabled", True) is False:
            continue
        document = probe_document(custom)
        probe_id, metadata = _custom_probability_metadata(custom)
        if not probe_id:
            continue
        available = set()
        artifact = document.get("baseline_artifact") or {}
        for key in artifact.get("raw_counts", {}):
            if key == probe_id:
                available.update((artifact["raw_counts"][key].get("profiles") or {}).keys())
        if not available:
            available.update((document.get("trusted_counts_by_model") or {}).keys())
        applicable = [profile for profile in profiles if profile in available]
        required = int(custom.get("runtime_requests" if config["mode"] == "single" else "window", custom.get("runtime_requests", 10)))
        for profile in applicable:
            key = f"{probe_id}|{profile}"
            cells[key] = required
            contracts[key] = _contract_from_metadata(probe_id, profile, metadata)
    if not cells:
        return None
    return {
        "name": f"{config['mode']}:{config['preset']}:{config['config_hash'][:12]}",
        "cells": cells,
        "contracts": contracts,
    }


__all__ = [
    "CONFIG_SCHEMA_VERSION",
    "CONTINUOUS_PRESETS",
    "DEFAULT_PROBABILITY_NORMALIZER",
    "PROBABILITY_PROBES",
    "SINGLE_PRESETS",
    "config_hash",
    "custom_changes",
    "estimate_single_requests",
    "estimate_plan",
    "get_preset",
    "normalize_config",
    "preset_catalog",
    "probability_runtime_spec",
    "selected_profiles",
]
