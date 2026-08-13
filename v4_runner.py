#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
import os
from pathlib import Path
import signal
import threading
import time

from gpt56_vnext.detector import DetectorSession
from gpt56_vnext.presets import get_preset


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--claimed-model", required=True)
    parser.add_argument("--request-model", required=True)
    parser.add_argument("--preset", choices=("low", "medium", "high"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--retention-directory", type=Path)
    args = parser.parse_args()

    api_key = os.environ.pop("CANDIDATE_API_KEY", "")
    if not api_key:
        raise SystemExit("CANDIDATE_API_KEY is required")

    config = get_preset("single", args.preset)
    session = DetectorSession(
        base_url=args.base_url,
        claimed_model=args.claimed_model,
        request_model=args.request_model,
        api_key=api_key,
        config=config,
        directory=args.run_dir,
        retention_enabled=args.retention_directory is not None,
        retention_directory=args.retention_directory,
    )
    api_key = ""
    stop_requested = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        if stop_requested.is_set():
            return
        stop_requested.set()
        result = session.stop()
        print(
            f"停止请求已接受，正在取消 {result['active_requests_cancelled']} 条在途请求",
            flush=True,
        )

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    finished = threading.Event()

    def show_progress() -> None:
        while not finished.wait(2):
            progress = session.progress_snapshot()
            print(
                "进度 "
                f"{progress['logical_completed']}/{progress['planned']}，"
                f"成功 {progress['successful']}，错误 {progress['errors']}，"
                f"取消 {progress['cancelled']}",
                flush=True,
            )

    progress_thread = threading.Thread(target=show_progress, daemon=True)
    progress_thread.start()
    version = (Path(__file__).resolve().parent / "VERSION").read_text(encoding="utf-8").strip()
    print(f"GPT-5.6 detector v{version} {args.preset} 档开始", flush=True)
    try:
        report = session.run_single()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        args.output.chmod(0o600)
        title = html.escape(str(report.get("title_cn") or "检测完成"))
        subtitle = html.escape(str(report.get("subtitle_cn") or ""))
        report_json = html.escape(json.dumps(report, ensure_ascii=False, indent=2))
        html_path = args.output.with_suffix(".html")
        html_path.write_text(
            "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>{title}</title><style>body{{font-family:system-ui,sans-serif;"
            "max-width:960px;margin:40px auto;padding:0 20px;color:#17202a}}"
            "h1{font-size:26px}p{line-height:1.7;color:#475569}"
            "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f7f9;"
            "border:1px solid #dce2e8;padding:18px;font-size:12px}</style></head><body>"
            f"<h1>{title}</h1><p>{subtitle}</p><pre>{report_json}</pre></body></html>",
            encoding="utf-8",
        )
        html_path.chmod(0o600)
        print(report.get("title_cn") or report.get("overall_verdict"), flush=True)
        print(f"报告 schema {report.get('schema_version')} 已生成", flush=True)
        return 130 if report.get("run_stopped") else 0
    finally:
        finished.set()
        progress_thread.join(timeout=3)
        session.api_key = ""
        session.transport.api_key = ""
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
