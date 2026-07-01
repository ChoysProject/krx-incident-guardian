#!/usr/bin/env python3
"""KRX Incident Guardian - Main monitoring script.

Reads KRX trading logs and triggers AI analysis when anomalies are detected.
  Stage 1 : response latency exceeds LATENCY_THRESHOLD_MS
  Stage 2 : ERROR log or error_code present  (also triggers Stage 3 automatically)
"""

import argparse
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

LATENCY_THRESHOLD_MS = 1000
POLL_INTERVAL_SEC = 5
PROJECT_ROOT = Path(__file__).parent
LOG_DIR = PROJECT_ROOT / "logs"
INCIDENT_LIST = PROJECT_ROOT / "incident_list.md"
REPORTS_DIR = PROJECT_ROOT / "reports"

_LOG_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)"
    r" \[(?P<level>\w+)\]"
    r" KRX_API endpoint=(?P<endpoint>\S+)"
    r" latency=(?P<latency>-?\d+)ms"
    r" status=(?P<status>\S+)"
    r"(?:\s+error_code=(?P<error_code>\S+))?"
)


def parse_log(raw: str) -> list[dict]:
    entries = []
    for line in raw.splitlines():
        m = _LOG_PATTERN.match(line.strip())
        if m:
            d = m.groupdict()
            d["latency_ms"] = int(d.pop("latency"))
            entries.append(d)
    return entries


def assess_stage(entries: list[dict]) -> int:
    stage = 0
    for e in entries:
        if e["level"] == "ERROR" or e.get("error_code"):
            return 2
        if e["latency_ms"] >= LATENCY_THRESHOLD_MS:
            stage = 1
    return stage


def build_prompt(raw: str, stage: int, log_file: str) -> str:
    stage_label = {
        1: "응답 시간 임계값 초과 (1단계: 사전 감지)",
        2: "에러 코드 발생 / 연결 차단 (2단계: 신속 대응 + 3단계: 재발 방지)",
    }
    return (
        f"[KRX 장애예방 가디언] {stage_label[stage]}\n\n"
        f"로그 파일: {log_file}\n"
        f"탐지 시각: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        f"--- 로그 내용 ---\n{raw.strip()}\n--- 끝 ---\n\n"
        "SKILL.md 지침에 따라 단계를 판단하고 분석 결과를 출력해 주세요."
    )


def call_ai(prompt: str) -> str:
    for cli in ["claude", "codex"]:
        try:
            result = subprocess.run(
                [cli, "-p", prompt],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except FileNotFoundError:
            continue
        except subprocess.TimeoutExpired:
            print(f"[WARN] {cli} timed out", file=sys.stderr)
    return "[ERROR] AI CLI를 찾을 수 없습니다. claude 또는 codex를 설치해 주세요."


def save_incident(entries: list[dict], ai_output: str) -> None:
    """Append a new row to incident_list.md (Stage 3)."""
    errors = [e for e in entries if e["level"] == "ERROR" or e.get("error_code")]
    if not errors:
        return

    first = errors[0]
    ts = first["ts"]
    endpoint = first["endpoint"]
    error_code = first.get("error_code") or "N/A"
    now_str = datetime.now().strftime("%Y%m%d_%H%M%S")

    row = (
        f"| {ts} | {endpoint} | {error_code} | {first['status']} "
        f"| [report_{now_str}.md](reports/report_{now_str}.md) |\n"
    )

    with open(INCIDENT_LIST, "a", encoding="utf-8") as f:
        f.write(row)

    REPORTS_DIR.mkdir(exist_ok=True)
    report_path = REPORTS_DIR / f"report_{now_str}.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"# 장애 분석 리포트 — {ts}\n\n")
        f.write(f"**장애 구간**: {endpoint}  \n")
        f.write(f"**에러 코드**: {error_code}  \n")
        f.write(f"**생성 시각**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n\n")
        f.write("## AI 분석 결과\n\n")
        f.write(ai_output + "\n")

    print(f"[3단계] 장애 내용 저장 완료: {report_path}")


def monitor_once(log_file: str) -> None:
    path = LOG_DIR / log_file
    if not path.exists():
        print(f"[WARN] 로그 파일 없음: {path}")
        return

    print(f"[{datetime.now().strftime('%H:%M:%S')}] {log_file} 분석 중...")

    raw = path.read_text(encoding="utf-8")
    entries = parse_log(raw)
    if not entries:
        print("  파싱 가능한 로그 항목 없음.")
        return

    stage = assess_stage(entries)
    print(f"  감지 단계: {stage}")

    if stage == 0:
        print("  정상 — 추가 조치 없음.")
        return

    prompt = build_prompt(raw, stage, log_file)
    ai_output = call_ai(prompt)
    print(ai_output)

    if stage == 2:
        save_incident(entries, ai_output)


def main() -> None:
    parser = argparse.ArgumentParser(description="KRX Incident Guardian Monitor")
    parser.add_argument(
        "log_file", nargs="?", default="stage2_incident.log",
        help="분석할 로그 파일명 (기본: stage2_incident.log)",
    )
    parser.add_argument(
        "--watch", action="store_true",
        help=f"로그 파일을 {POLL_INTERVAL_SEC}초 간격으로 지속 감시",
    )
    args = parser.parse_args()

    if args.watch:
        print(f"{args.log_file} 감시 중 ({POLL_INTERVAL_SEC}초 간격). 종료: Ctrl+C")
        try:
            while True:
                monitor_once(args.log_file)
                time.sleep(POLL_INTERVAL_SEC)
        except KeyboardInterrupt:
            print("\n감시 종료.")
    else:
        monitor_once(args.log_file)


if __name__ == "__main__":
    main()
