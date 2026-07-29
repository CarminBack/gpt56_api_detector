#!/usr/bin/env python3
"""GPT-5.6 持续路由监控的一键交互启动器。"""

from __future__ import annotations

from datetime import datetime
import getpass
import os
from pathlib import Path
import subprocess
import sys


def ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        value = input(f"{prompt}{suffix}: ").strip()
        if value:
            return value
        if default is not None:
            return default
        print("此项不能为空，请重新输入。")


def ask_int(prompt: str, default: int, minimum: int) -> int:
    while True:
        raw = input(f"{prompt} [{default}]: ").strip()
        if not raw:
            return default
        try:
            value = int(raw)
            if value >= minimum:
                return value
        except ValueError:
            pass
        print(f"请输入不小于 {minimum} 的整数。")


def ask_secret(prompt: str) -> str:
    while True:
        value = getpass.getpass(f"{prompt}: ").strip()
        if value:
            return value
        print("API key 不能为空。")


def main() -> int:
    print("=" * 66)
    print("GPT-5.6 持续路由监控")
    print("程序会使用稳定提示、随机时间和随机请求顺序持续检测，按 Ctrl+C 停止。")
    print("严格标准固定为最近 20 个候选尝试至少命中 15 个，错误和重试不能通过。")
    print("=" * 66)

    print("\n[1/3] 可信 GPT-5.6 API")
    trusted_url = ask("API 地址，例如 https://host/v1").rstrip("/")
    trusted_model = ask("模型名", "gpt-5.6-sol")
    trusted_key = ask_secret("API key")

    print("\n[2/3] 待测 API")
    candidate_url = ask("API 地址").rstrip("/")
    candidate_model = ask("模型名", "gpt-5.6-sol")
    same_key = input("是否与可信 API 使用相同 key？[y/N]: ").strip().lower()
    candidate_key = trusted_key if same_key in {"y", "yes"} else ask_secret("API key")

    print("\n[3/3] 监控频率")
    print("直接按回车会在每轮结束后随机等待 20 到 40 秒。")
    minimum = ask_int("最短间隔（秒）", 20, 1)
    maximum = ask_int("最长间隔（秒）", 40, minimum)
    default_report = f"monitor-report-{datetime.now():%Y%m%d-%H%M%S}.json"
    report = Path(ask("报告文件名", default_report)).expanduser().resolve()

    monitor = Path(__file__).with_name("gpt56_reasoning_monitor.py")
    if not monitor.is_file():
        print(f"错误：找不到监控脚本 {monitor}", file=sys.stderr)
        return 2
    command = [
        sys.executable, str(monitor),
        "--trusted-base-url", trusted_url,
        "--trusted-model", trusted_model,
        "--candidate-base-url", candidate_url,
        "--candidate-model", candidate_model,
        "--min-interval", str(minimum),
        "--max-interval", str(maximum),
        "--window", "20",
        "--required-matches", "15",
        "--candidate-retries", "2",
        "--candidate-min-gap", "2",
        "--candidate-max-gap", "5",
        "--output", str(report),
    ]
    child_env = os.environ.copy()
    child_env["TRUSTED_API_KEY"] = trusted_key
    child_env["CANDIDATE_API_KEY"] = candidate_key

    print(f"\n监控已启动，报告会持续更新到：{report}")
    print("请保持窗口开启。停止时按一次 Ctrl+C，最新报告不会丢失。\n")
    try:
        try:
            return subprocess.run(command, env=child_env, check=False).returncode
        except OSError as exc:
            print(f"无法启动监控：{exc}", file=sys.stderr)
            return 2
    finally:
        child_env.pop("TRUSTED_API_KEY", None)
        child_env.pop("CANDIDATE_API_KEY", None)
        trusted_key = ""
        candidate_key = ""


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n监控已停止。")
        raise SystemExit(130)


