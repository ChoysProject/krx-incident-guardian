#!/usr/bin/env python3
"""KRX Incident Guardian - Main monitoring script.

Parses KRX socket 전문(電文) communication logs:
  [SEND]  요청 전문 발송
  [RECV]  응답 전문 수신  (result_cd, elapsed 포함)
  [SOCK]  소켓 연결 이벤트

SEND/RECV 쌍 매칭(tr_cd + tr_seq) 및 result_cd 분석으로 단계 판정:
  Stage 0 : 정상
  Stage 1 : 예방  (elapsed >= ELAPSED_WARN_MS — 점진적 증가 또는 급격한 스파이크)
  Stage 2 : 장애  (SOCK 오류 / 미응답 SEND / result_cd 2x·3x·9x)
"""

import argparse
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ELAPSED_WARN_MS = 300     # 1단계 예방 임계값 (ms)
POLL_INTERVAL_SEC = 5
PROJECT_ROOT = Path(__file__).parent          # src/
LOG_DIR = PROJECT_ROOT / "sample-logs"        # src/sample-logs/
INCIDENT_LIST = PROJECT_ROOT / "incident_list.md"
REPORTS_DIR = PROJECT_ROOT / "reports"

_SEND_PAT = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)"
    r" \[(?P<level>\w+)\] \[SEND\]"
    r" tr_cd=(?P<tr_cd>\S+) tr_seq=(?P<tr_seq>\S+)"
    r" data_len=(?P<data_len>\d+) conn_id=(?P<conn_id>\S+)"
)
_RECV_PAT = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)"
    r" \[(?P<level>\w+)\] \[RECV\]"
    r" tr_cd=(?P<tr_cd>\S+) tr_seq=(?P<tr_seq>\S+)"
    r" data_len=(?P<data_len>\d+)"
    r" result_cd=(?P<result_cd>\S+) result_msg=(?P<result_msg>\S+)"
    r" elapsed=(?P<elapsed>-?\d+)ms conn_id=(?P<conn_id>\S+)"
)
_SOCK_PAT = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)"
    r" \[(?P<level>\w+)\] \[SOCK\]"
    r" event=(?P<event>\S+) conn_id=(?P<conn_id>\S+)"
    r"(?:\s+reason=(?P<reason>\S+))?"
)

_SOCK_ERROR_EVENTS = {"DISCONNECTED", "CONNECTION_LOST", "CONNECTION_ERROR", "ERROR"}


def parse_messages(raw: str) -> dict:
    sends, recvs, socks = [], [], []
    for line in raw.splitlines():
        s = line.strip()
        for pat, bucket in ((_SEND_PAT, sends), (_RECV_PAT, recvs), (_SOCK_PAT, socks)):
            m = pat.match(s)
            if m:
                d = m.groupdict()
                if "elapsed" in d and d["elapsed"] is not None:
                    d["elapsed_ms"] = int(d.pop("elapsed"))
                bucket.append(d)
                break
    return {"sends": sends, "recvs": recvs, "socks": socks}


def match_pairs(messages: dict) -> dict:
    """SEND/RECV를 (tr_cd, tr_seq) 기준으로 매칭."""
    recv_index: dict[tuple, dict] = {}
    for r in messages["recvs"]:
        recv_index[(r["tr_cd"], r["tr_seq"])] = r

    paired, unmatched = [], []
    for s in messages["sends"]:
        r = recv_index.get((s["tr_cd"], s["tr_seq"]))
        if r:
            paired.append((s, r))
        else:
            unmatched.append(s)
    return {"paired": paired, "unmatched_sends": unmatched}


def assess_stage(messages: dict, pairs: dict) -> int:
    # 1. 소켓 오류 이벤트 → 즉시 2단계
    for s in messages["socks"]:
        if s.get("event", "").upper() in _SOCK_ERROR_EVENTS:
            return 2

    # 2. 오류 result_cd (2x / 3x / 9x 계열) → 2단계
    for r in messages["recvs"]:
        if r.get("result_cd", "")[:2] in ("20", "30", "99"):
            return 2

    # 3. 미응답 SEND 존재 → 2단계 (타임아웃)
    if pairs["unmatched_sends"]:
        return 2

    stage = 0
    for _, r in pairs["paired"]:
        if r.get("elapsed_ms", 0) >= ELAPSED_WARN_MS:
            stage = 1
    return stage


def build_prompt(raw: str, stage: int, log_file: str, messages: dict, pairs: dict) -> str:
    stage_label = {
        1: "응답 지연 감지 (1단계: 사전 예방)",
        2: "전문 오류 / 소켓 장애 (2단계: 신속 대응 + 3단계: 재발 방지)",
    }

    elapsed_series = [
        f"  tr_cd={r['tr_cd']} tr_seq={r['tr_seq']} elapsed={r.get('elapsed_ms')}ms"
        for _, r in pairs["paired"]
    ]
    slow_pairs = [
        f"  tr_cd={r['tr_cd']} tr_seq={r['tr_seq']} elapsed={r.get('elapsed_ms')}ms result_cd={r.get('result_cd')}"
        for _, r in pairs["paired"]
        if r.get("elapsed_ms", 0) >= ELAPSED_WARN_MS
    ]
    unmatched = [
        f"  tr_cd={s['tr_cd']} tr_seq={s['tr_seq']} (RECV 없음 — 타임아웃 추정)"
        for s in pairs["unmatched_sends"]
    ]
    sock_errors = [
        f"  event={s['event']} conn_id={s['conn_id']} reason={s.get('reason', 'N/A')}"
        for s in messages["socks"]
        if s.get("event", "").upper() in _SOCK_ERROR_EVENTS
    ]

    summary_lines = []
    if elapsed_series:
        summary_lines.append("[elapsed 시계열 — 전체 전문]\n" + "\n".join(elapsed_series))
    if slow_pairs:
        summary_lines.append("[임계값 초과 전문]\n" + "\n".join(slow_pairs))
    if unmatched:
        summary_lines.append("[미응답 전문]\n" + "\n".join(unmatched))
    if sock_errors:
        summary_lines.append("[소켓 오류 이벤트]\n" + "\n".join(sock_errors))

    return (
        f"[KRX 장애예방 가디언] {stage_label[stage]}\n\n"
        f"로그 파일: {log_file}\n"
        f"탐지 시각: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        + ("\n\n".join(summary_lines) + "\n\n" if summary_lines else "")
        + f"--- 로그 전문 ---\n{raw.strip()}\n--- 끝 ---\n\n"
        "SKILL.md 지침에 따라 단계를 판단하고 분석 결과를 출력해 주세요."
    )


def call_ai(prompt: str) -> str:
    for cli in ["claude", "codex"]:
        try:
            result = subprocess.run(
                [cli, "-p", prompt],
                capture_output=True, text=True, timeout=120,
                encoding="utf-8", errors="replace",
            )
            if result.returncode == 0 and result.stdout:
                return result.stdout.strip()
        except FileNotFoundError:
            continue
        except subprocess.TimeoutExpired:
            print(f"[WARN] {cli} timed out", file=sys.stderr)
    return "[ERROR] AI CLI를 찾을 수 없습니다. claude 또는 codex를 설치해 주세요."


def save_incident(messages: dict, pairs: dict, ai_output: str) -> None:
    """incident_list.md에 장애 행 추가 + 분석 리포트 저장 (3단계)."""
    error_recvs = [
        r for r in messages["recvs"]
        if r.get("result_cd", "")[:2] in ("20", "30", "99")
    ]
    sock_errors = [
        s for s in messages["socks"]
        if s.get("event", "").upper() in _SOCK_ERROR_EVENTS
    ]

    if not error_recvs and not pairs["unmatched_sends"] and not sock_errors:
        return

    now_str = datetime.now().strftime("%Y%m%d_%H%M%S")

    if error_recvs:
        ts = error_recvs[0]["ts"]
        tr_cd = error_recvs[0]["tr_cd"]
        result_cd = error_recvs[0]["result_cd"]
        result_msg = error_recvs[0]["result_msg"]
    elif pairs["unmatched_sends"]:
        ts = pairs["unmatched_sends"][0]["ts"]
        tr_cd = pairs["unmatched_sends"][0]["tr_cd"]
        result_cd = "TIMEOUT"
        result_msg = "미응답"
    else:
        ts = sock_errors[0]["ts"]
        tr_cd = "SOCKET"
        result_cd = "DISCONNECT"
        result_msg = sock_errors[0].get("reason", "소켓단절")

    row = (
        f"| {ts} | {tr_cd} | {result_cd} | {result_msg} "
        f"| [report_{now_str}.md](reports/report_{now_str}.md) |\n"
    )
    with open(INCIDENT_LIST, "a", encoding="utf-8") as f:
        f.write(row)

    REPORTS_DIR.mkdir(exist_ok=True)
    report_path = REPORTS_DIR / f"report_{now_str}.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"# 장애 분석 리포트 — {ts}\n\n")
        f.write(f"**전문 코드**: {tr_cd}  \n")
        f.write(f"**결과 코드**: {result_cd}  \n")
        f.write(f"**결과 메시지**: {result_msg}  \n")
        f.write(f"**생성 시각**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n\n")
        if pairs["unmatched_sends"]:
            f.write(f"**미응답 전문 수**: {len(pairs['unmatched_sends'])}건  \n\n")
        f.write("## AI 분석 결과\n\n")
        f.write(ai_output + "\n")

    print(f"[3단계] 장애 내용 저장 완료: {report_path}")


_watched_offsets: dict[str, int] = {}


def monitor_once(log_file: str) -> None:
    path = LOG_DIR / log_file
    if not path.exists():
        print(f"[WARN] 로그 파일 없음: {path}")
        return

    current_size = path.stat().st_size
    last_offset = _watched_offsets.get(log_file, 0)
    if current_size <= last_offset:
        return

    print(f"[{datetime.now().strftime('%H:%M:%S')}] {log_file} 분석 중...")

    with path.open(encoding="utf-8") as f:
        f.seek(last_offset)
        raw = f.read()
    _watched_offsets[log_file] = current_size

    messages = parse_messages(raw)
    pairs = match_pairs(messages)

    print(
        f"  전문: SEND {len(messages['sends'])}건 / "
        f"RECV {len(messages['recvs'])}건 / "
        f"미응답 {len(pairs['unmatched_sends'])}건"
    )

    stage = assess_stage(messages, pairs)
    print(f"  감지 단계: {stage}")

    if stage == 0:
        print("  정상 - 추가 조치 없음.")
        return

    prompt = build_prompt(raw, stage, log_file, messages, pairs)
    ai_output = call_ai(prompt)
    print(ai_output)

    if stage == 2:
        save_incident(messages, pairs, ai_output)


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
