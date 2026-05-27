"""評估：對 labeled.jsonl 跑 pipeline，算 Precision / Recall / F1。

M6 實作。取 Stage 2 verdict（safe 視為 legitimate）對比 gold label，
用 sklearn.metrics 印 classification_report。目標 F1 >= 0.85。
CLI：python eval/evaluate.py --dataset data/eval/labeled.jsonl
"""

# TODO(M6): 載入 jsonl → 跑 pipeline → classification_report。


def main() -> None:
    raise NotImplementedError("evaluate 將於 M6 實作")


if __name__ == "__main__":
    main()
