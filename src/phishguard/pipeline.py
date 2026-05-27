"""Pipeline：串接 Stage 1→2→3 + 寫鑑識紀錄 + 匯出 IOC。

流程（claude_task_build.md 第 6 節）：
  1. s1 = stage1.run(msg)
  2. 若 s1.label == "safe"：只寫鑑識紀錄（stopped_at=stage1），結束。
  3. 否則 s2 = stage2.run(msg) → s3 = stage3.run(s2)。
  4. record = forensics.make_record(...)（內部先 hash 原文、後 redact）→ append_audit。
  5. 若 s2.verdict == "phishing"：ioc.write_bundle(...) 寫出 STIX。
  6. 回傳整合結果。

process() 回傳的就是「已遮蔽」的鑑識紀錄（+ stix_path），因此印到 stdout 也不會洩漏個人 PII
（CLAUDE.md：對外文字前一律先 redact）。各 stage 仍以原文分析，只有落地 / 輸出時才遮蔽。

CLI：python -m phishguard.pipeline --input <file.json>
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import forensics, ioc, stage1_filter, stage2_intent, stage3_briefing
from .schema import Message


def process(msg: Message) -> dict:
    """對單封郵件跑完整 pipeline，回傳已遮蔽的鑑識紀錄（含 stix_path）。"""
    s1 = stage1_filter.run(msg)

    # Stage 1 判 safe：保守地只留鑑識紀錄，不進階分析、不匯出 IOC。
    if s1.label == "safe":
        record = forensics.make_record(msg, s1)
        forensics.append_audit(record)
        record["stix_path"] = None
        return record

    s2 = stage2_intent.run(msg)
    s3 = stage3_briefing.run(s2)

    record = forensics.make_record(msg, s1, s2, s3)
    forensics.append_audit(record)

    stix_path = None
    if s2.verdict == "phishing":
        path = ioc.write_bundle(msg, s2)
        stix_path = str(path) if path else None

    record["stix_path"] = stix_path
    return record


def _load_message(path: str) -> Message:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return Message.model_validate(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="phishguard.pipeline",
        description="多階段防釣魚偵測 pipeline（讀單封郵件 JSON）。",
    )
    parser.add_argument("--input", required=True, help="郵件 JSON 檔路徑（Message 結構）。")
    args = parser.parse_args(argv)

    msg = _load_message(args.input)
    result = process(msg)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
