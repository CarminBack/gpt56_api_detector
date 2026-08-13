from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any

from .probability_model import COMPLETION_RATIO, MODELS, load_baseline, runtime_signature
from .utils import canonical_json


POLICY_SCHEMA_VERSION = 1
POLICY_VERSION = "fingerprint-runtime-policy-v4.1.1"


def _file_sha256(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


def verify_runtime_policy(
    policy: dict[str, Any],
    *,
    baseline_path: str | Path,
) -> None:
    if int(policy.get("schema_version", 0)) != POLICY_SCHEMA_VERSION:
        raise ValueError("不支持的指纹运行策略版本")
    if policy.get("policy_version") != POLICY_VERSION:
        raise ValueError("指纹运行策略标识不匹配")
    expected = str(policy.get("content_sha256") or "")
    body = deepcopy(policy)
    body.pop("content_sha256", None)
    observed = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
    if expected != observed:
        raise ValueError("指纹运行策略内容哈希不匹配")
    baseline = load_baseline(baseline_path)
    binding = policy.get("baseline_binding") or {}
    if str(binding.get("file_sha256") or "").upper() != _file_sha256(baseline_path):
        raise ValueError("指纹运行策略绑定的基础指纹文件不匹配")
    if binding.get("content_sha256") != baseline.get("content_sha256"):
        raise ValueError("指纹运行策略绑定的基础指纹内容不匹配")
    if policy.get("comparison") != "strictly_greater_than":
        raise ValueError("指纹运行策略的阈值比较方式不匹配")
    if float(policy.get("completion_ratio", -1)) != COMPLETION_RATIO:
        raise ValueError("指纹运行策略的完成度门禁不匹配")
    thresholds = policy.get("thresholds") or {}
    if set(thresholds) != {"low", "medium", "high"}:
        raise ValueError("指纹运行策略缺少三档强指向线")
    for level, model_thresholds in thresholds.items():
        if set(model_thresholds or {}) != set(MODELS):
            raise ValueError(f"指纹运行策略的型号阈值不完整：{level}")
        if any(not 0.0 <= float(value) <= 1.0 for value in model_thresholds.values()):
            raise ValueError(f"指纹运行策略的阈值超出范围：{level}")
    contracts = policy.get("official_contracts") or {}
    if set(contracts) != {
        "single:low", "single:medium", "single:high",
        "continuous:low", "continuous:medium", "continuous:high",
    }:
        raise ValueError("指纹运行策略缺少官方运行契约")
    cells = baseline.get("cells") or {}
    for name, contract in contracts.items():
        level = str(contract.get("decision_level") or "")
        if level not in thresholds or level != name.split(":", 1)[1]:
            raise ValueError(f"官方运行契约的判定档位无效：{name}")
        if "thresholds" in contract or "formal_eligible" in contract:
            raise ValueError(f"官方运行契约包含重复的判定权威：{name}")
        required = contract.get("required_samples") or {}
        if not required:
            raise ValueError(f"官方运行契约没有概率探针格：{name}")
        missing = [key for key in required if key not in cells]
        positive_families = {
            key.split("|", 1)[0]
            for key in required
            if float((cells.get(key) or {}).get("weight", 0.0)) > 0
        }
        if missing or not positive_families:
            raise ValueError(f"官方运行契约的基础指纹资源损坏：{name}")


def load_runtime_policy(
    path: str | Path,
    *,
    baseline_path: str | Path,
) -> dict[str, Any]:
    policy = json.loads(Path(path).read_text(encoding="utf-8"))
    verify_runtime_policy(policy, baseline_path=baseline_path)
    return policy


def resolve_decision_policy(
    policy: dict[str, Any],
    config: dict[str, Any],
    runtime_spec: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if not config.get("official") or runtime_spec is None:
        return None
    key = f"{config.get('mode')}:{config.get('preset')}"
    contract = (policy.get("official_contracts") or {}).get(key)
    if not contract:
        return None
    if contract.get("config_hash") != config.get("config_hash"):
        return None
    if contract.get("runtime_signature") != runtime_signature(runtime_spec):
        return None
    decision = deepcopy(contract)
    decision["thresholds"] = deepcopy(policy["thresholds"][contract["decision_level"]])
    return decision


__all__ = [
    "POLICY_SCHEMA_VERSION",
    "POLICY_VERSION",
    "load_runtime_policy",
    "resolve_decision_policy",
    "verify_runtime_policy",
]
