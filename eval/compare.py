"""比較 CLI：在同一份資料集上比較「單一大模型」與「三階段級聯」的準確率與成本。

用法：python eval/compare.py --dataset data/eval/labeled.jsonl

這是 handout 的核心實驗（省成本 vs 準確率）。真實跑分需有效 .env（會呼叫 LLM）。
真正邏輯在 phishguard.evaluation.compare；本檔只負責參數解析與輸出。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# 讓本腳本可直接 `python eval/compare.py` 執行（src-layout 需手動補 path）。
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from phishguard.evaluation import compare, format_comparison, load_dataset  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="compare",
        description="單一大模型 vs 三階段級聯：準確率與 LLM 呼叫數（成本）對照。",
    )
    parser.add_argument("--dataset", required=True, help="labeled.jsonl 路徑。")
    args = parser.parse_args(argv)

    dataset = load_dataset(args.dataset)
    print(format_comparison(compare(dataset)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
