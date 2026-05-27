"""評估 CLI：對標註資料集跑 pipeline，印 Precision / Recall / F1。

用法：python eval/evaluate.py --dataset data/eval/labeled.jsonl

真正邏輯在 phishguard.evaluation；本檔只負責參數解析與輸出。
真實跑分需有效 .env（會呼叫 LLM）；目標 F1 >= 0.85，未達標回頭調 prompt。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# 讓本腳本可直接 `python eval/evaluate.py` 執行（src-layout 需手動補 path）。
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from phishguard.evaluation import TARGET_F1, load_dataset, score  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="evaluate", description="多階段防釣魚偵測評估（Precision / Recall / F1）。"
    )
    parser.add_argument("--dataset", required=True, help="labeled.jsonl 路徑。")
    args = parser.parse_args(argv)

    dataset = load_dataset(args.dataset)
    result = score(dataset)

    print(result["report"])
    print(f"Precision: {result['precision']:.3f}")
    print(f"Recall:    {result['recall']:.3f}")
    print(f"F1:        {result['f1']:.3f}  (target >= {TARGET_F1})")
    if result["f1"] < TARGET_F1:
        print(f"⚠️  F1 未達標（< {TARGET_F1}）——回頭調整 prompt，並把調整記錄在 commit。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
