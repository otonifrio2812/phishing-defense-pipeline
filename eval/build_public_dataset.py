"""把公開語料庫的真實郵件轉成評估用的 labeled.jsonl（與自製集同格式）。

用途：Task 6 後半——換成更難的真實郵件（SpamAssassin ham = 正常、Nazario/Nigerian
Fraud = 釣魚），讓 compare.py / evaluate.py 在真實資料上重跑。

設計：
- 解析 RFC822 郵件（支援「資料夾內一封一檔」與「單一 mbox 多封」兩種）。
- 抽出 sender / subject / body / urls，body 過長截斷（預設 2000 字，省 LLM 成本）。
- **入站套用 evaluation.ingest_record**：遮蔽 body/subject 的受害者 PII，保留 sender/urls
  （硬規則 4 & 5），與專案其他流程一致。
- 各類別隨機抽 N 筆（--per-class，可重現 seed），輸出與 data/eval/labeled.jsonl 同格式。

用法（在能上網的機器上，已先下載好原始郵件到 data/raw/）：
  python eval/build_public_dataset.py \
      --ham   data/raw/easy_ham \
      --phish data/raw/nazario.mbox \
      --out   data/eval/labeled_public.jsonl \
      --per-class 50

之後：
  python eval/compare.py  --dataset data/eval/labeled_public.jsonl
  python eval/evaluate.py --dataset data/eval/labeled_public.jsonl
"""

from __future__ import annotations

import argparse
import csv
import email
import email.header
import json
import mailbox
import random
import re
import sys
from email.parser import BytesParser
from pathlib import Path

# src-layout：讓 import phishguard 可用。
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from phishguard.evaluation import ingest_record  # noqa: E402

# 大型郵件 body 常超過 csv 預設欄位上限（~128KB）；提高上限避免 _csv.Error（Windows 安全值）。
csv.field_size_limit(10_000_000)

_TAG_RE = re.compile(r"<[^>]+>")
_URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)


def _decode_header(raw: object) -> str:
    """把可能被 MIME 編碼的標頭（=?utf-8?...?=）解成乾淨字串。"""
    if not raw:
        return ""
    try:
        parts = email.header.decode_header(str(raw))
        out = []
        for text, enc in parts:
            if isinstance(text, bytes):
                out.append(text.decode(enc or "utf-8", errors="replace"))
            else:
                out.append(text)
        return "".join(out).strip()
    except Exception:
        return str(raw)


def _payload_text(part) -> str:
    try:
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")
    except Exception:
        return ""


def _strip_html(html: str) -> str:
    if not html:
        return ""
    return re.sub(r"\s+", " ", _TAG_RE.sub(" ", html)).strip()


def _get_body(msg) -> str:
    """取 text/plain；沒有就拿 text/html 去標籤。略過附件。"""
    plain = html = None
    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            disp = str(part.get("Content-Disposition") or "").lower()
            if "attachment" in disp:
                continue
            ctype = part.get_content_type()
            if ctype == "text/plain" and plain is None:
                plain = _payload_text(part)
            elif ctype == "text/html" and html is None:
                html = _payload_text(part)
    else:
        if msg.get_content_type() == "text/html":
            html = _payload_text(msg)
        else:
            plain = _payload_text(msg)
    return (plain or _strip_html(html or "") or "").strip()


def _extract_urls(text: str) -> list[str]:
    # 去重、保序、最多 20 個。
    return list(dict.fromkeys(_URL_RE.findall(text)))[:20]


def iter_messages(path: Path):
    """支援資料夾（一封一檔）或單一 mbox 檔（多封）。"""
    if path.is_dir():
        for f in sorted(path.rglob("*")):
            if not f.is_file() or f.name.startswith("."):
                continue
            data = f.read_bytes()
            if data.startswith(b"From "):  # 去掉 mbox 分隔行
                data = data.split(b"\n", 1)[1] if b"\n" in data else b""
            try:
                yield BytesParser().parsebytes(data)
            except Exception:
                continue
    else:
        try:
            box = mailbox.mbox(str(path))
            count = 0
            for msg in box:
                count += 1
                yield msg
            if count == 0:  # 不是 mbox：當成單一封
                yield BytesParser().parsebytes(path.read_bytes())
        except Exception:
            try:
                yield BytesParser().parsebytes(path.read_bytes())
            except Exception:
                return


def _url_source(msg) -> str:
    """收集所有 text/plain 與「原始 text/html」內容，供 URL 抽取（含 <a href> 連結）。"""
    chunks: list[str] = []
    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        if part.is_multipart():
            continue
        if part.get_content_type() in ("text/plain", "text/html"):
            chunks.append(_payload_text(part))
    return "\n".join(chunks)


def build_record(msg, label: str, case_id: str, max_body: int) -> dict:
    body = _get_body(msg)[:max_body]
    rec = {
        "case_id": case_id,
        "channel": "email",
        "sender": _decode_header(msg.get("From")) or None,
        "subject": _decode_header(msg.get("Subject")) or None,
        "body": body,
        "urls": _extract_urls(_url_source(msg)),  # 從原始（含 html href）抽 URL
        "label": label,
    }
    return ingest_record(rec)  # 入站遮蔽：硬規則 4 & 5


# CSV 標籤值對照（用於混合標籤的 CSV，依 --ham/--phish 過濾出對應類別的列）。
_PHISH_TOKENS = {"1", "1.0", "phishing", "phish", "spam", "fraud", "malicious", "scam"}
_LEGIT_TOKENS = {"0", "0.0", "legitimate", "legit", "ham", "safe", "normal"}


def _row_matches(label_val: object, target: str) -> bool:
    v = str(label_val).strip().lower()
    return v in (_PHISH_TOKENS if target == "phishing" else _LEGIT_TOKENS)


def _records_from_csv(path: Path, label: str, max_body: int):
    """讀 CSV（如 Kaggle 的 Nazario.csv / Nigerian_Fraud.csv / SpamAssassin.csv）。

    欄位名稱有彈性；若有標籤欄，則只取與本類別（--ham/--phish）相符的列
    （混合檔也能正確分類），沒有標籤欄就視為單一類別全收。
    """
    with path.open(newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        cols = {c.lower().strip(): c for c in (reader.fieldnames or [])}

        def pick(*names):
            for n in names:
                if n in cols:
                    return cols[n]
            return None

        body_c = pick("body", "text", "text_combined", "email", "content", "message")
        send_c = pick("sender", "from", "sender_email")
        subj_c = pick("subject", "title")
        url_c = pick("urls", "url", "links")
        lab_c = pick("label", "class", "target", "category")

        for i, row in enumerate(reader):
            if lab_c and not _row_matches(row.get(lab_c, ""), label):
                continue
            body = ((row.get(body_c) or "") if body_c else "")[:max_body]
            if not body.strip():
                continue
            urls = _extract_urls(row[url_c]) if (url_c and row.get(url_c)) else []
            if not urls:
                urls = _extract_urls(body)
            rec = {
                "case_id": f"{label[:4]}-csv-{i:05d}",
                "channel": "email",
                "sender": (row.get(send_c) or None) if send_c else None,
                "subject": (row.get(subj_c) or None) if subj_c else None,
                "body": body,
                "urls": urls,
                "label": label,
            }
            yield ingest_record(rec)  # 入站遮蔽：硬規則 4 & 5


def collect(path: Path, label: str, n: int, rng: random.Random, max_body: int) -> list[dict]:
    if path.suffix.lower() == ".csv":
        recs = list(_records_from_csv(path, label, max_body))
    else:
        recs = []
        for i, msg in enumerate(iter_messages(path)):
            try:
                rec = build_record(msg, label, f"{label[:4]}-{i:04d}", max_body)
            except Exception:
                continue
            if rec["body"].strip():  # 跳過空白內文
                recs.append(rec)
    rng.shuffle(recs)
    return recs[:n]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="build_public_dataset",
        description="把 SpamAssassin / Nazario 等真實郵件轉成 labeled.jsonl（含 PII 遮蔽）。",
    )
    parser.add_argument("--ham", required=True, help="正常郵件來源（資料夾或 mbox）。")
    parser.add_argument("--phish", required=True, help="釣魚郵件來源（資料夾或 mbox）。")
    parser.add_argument("--out", default="data/eval/labeled_public.jsonl", help="輸出 jsonl 路徑。")
    parser.add_argument("--per-class", type=int, default=50, help="每類抽幾筆（預設 50）。")
    parser.add_argument("--seed", type=int, default=42, help="隨機種子（可重現）。")
    parser.add_argument("--max-body", type=int, default=2000, help="內文最長字數（預設 2000）。")
    args = parser.parse_args(argv)

    rng = random.Random(args.seed)
    ham = collect(Path(args.ham), "legitimate", args.per_class, rng, args.max_body)
    phish = collect(Path(args.phish), "phishing", args.per_class, rng, args.max_body)

    rows = ham + phish
    rng.shuffle(rows)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"正常 {len(ham)} 筆 / 釣魚 {len(phish)} 筆 → 共 {len(rows)} 筆")
    print(f"已寫入：{out}")
    if len(ham) < args.per_class or len(phish) < args.per_class:
        print("⚠️ 某類別不足 --per-class，請確認來源路徑與內容。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
