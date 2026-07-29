#!/usr/bin/env python3
"""One-click interactive launcher for the GPT-5.6 API detector."""

from __future__ import annotations

from datetime import datetime
import getpass
import os
from pathlib import Path
import subprocess
import sys


# Keep the detector strict. The wizard reduces setup effort, not evidence quality.
TRIALS = 20
MIN_MATCH_RATE = 0.75
MIN_MATCHES = 15


def ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        value = input(f"{prompt}{suffix}: ").strip()
        if value:
            return value
        if default is not None:
            return default
        print("此项不能为空，请重新输入。")


def ask_secret(prompt: str) -> str:
    while True:
        value = getpass.getpass(f"{prompt}: ").strip()
        if value:
            return value
        print("API key 不能为空，请重新输入。")


def normalize_base_url(value: str) -> str:
    return value.rstrip("/")


def main() -> int:
    print("=" * 62)
    print("GPT-5.6 API 综合检测器 v3.1")
    print("第一层检测 GPT-5.6 加密状态能力，第二层区分 Sol、Terra、Luna 并检查混用。")
    print("强检测固定运行 20 个候选挑战；随后自动运行五档 juice 型号指纹。")
    print("API key 输入时不会显示，也不会写入报告。")
    print("=" * 62)

    print("\n[1/2] 可信 GPT-5.6 API")
    trusted_url = normalize_base_url(ask("API 地址，例如 https://host/v1"))
    trusted_model = ask("模型名", "gpt-5.6-sol")
    trusted_key = ask_secret("API key")

    print("\n[2/2] 待测 API")
    candidate_url = normalize_base_url(ask("API 地址，例如 https://host/v1"))
    candidate_model = ask("模型名", "gpt-5.6-sol")
    same_key = input("是否与可信 API 使用相同 key？[y/N]: ").strip().lower()
    candidate_key = trusted_key if same_key in {"y", "yes"} else ask_secret("API key")

    default_report = f"probe-report-{datetime.now():%Y%m%d-%H%M%S}.json"
    report_path = Path(ask("报告文件名", default_report)).expanduser().resolve()
    detector = Path(__file__).with_name("gpt56_reasoning_probe.py")
    if not detector.is_file():
        print(f"错误：找不到检测脚本 {detector}", file=sys.stderr)
        return 2

    command = [
        sys.executable,
        str(detector),
        "--trusted-base-url", trusted_url,
        "--trusted-model", trusted_model,
        "--candidate-base-url", candidate_url,
        "--candidate-model", candidate_model,
        "--trials", str(TRIALS),
        "--min-match-rate", str(MIN_MATCH_RATE),
        "--min-matches", str(MIN_MATCHES),
        "--candidate-retries", "2",
        "--candidate-min-gap", "2",
        "--candidate-max-gap", "5",
        "--juice-repeats", "3",
        "--output", str(report_path),
    ]

    # Keys exist only in the child process environment for this run.
    child_env = os.environ.copy()
    child_env["TRUSTED_API_KEY"] = trusted_key
    child_env["CANDIDATE_API_KEY"] = candidate_key

    print("\n开始 v3.1 综合检测：20 个强挑战 + 15 个浅层型号指纹。")
    print("这可能需要几分钟，请不要关闭窗口。\n")
    try:
        try:
            completed = subprocess.run(command, env=child_env, check=False)
            return_code = completed.returncode
        except OSError as exc:
            print(f"无法启动检测脚本：{exc}", file=sys.stderr)
            return_code = 2
    finally:
        child_env.pop("TRUSTED_API_KEY", None)
        child_env.pop("CANDIDATE_API_KEY", None)
        trusted_key = ""
        candidate_key = ""

    if report_path.is_file():
        print(f"\n报告位置：{report_path}")
    if return_code != 0:
        print("检测未正常完成，请查看上方错误信息。", file=sys.stderr)
    return return_code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n已取消检测。")
        raise SystemExit(130)

