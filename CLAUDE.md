# CLAUDE.md — 多階段防釣魚與社交工程防禦網

> 專案憲法。每個 session 自動載入。詳細建置步驟見 `claude_task_build.md`——**動工前請先讀它**。

## 專案一句話

以 LLM 驅動的三階段釣魚郵件偵測 pipeline。對齊指導教授（林俊叡，台科大資安研究中心）專長：**AI 輔助威脅狩獵 / 資安資料交換標準 / 數位鑑識 / 隱私設計 / 敏捷開發**。

## Tech stack

- Python 3.11+
- LLM 呼叫：`openai` SDK（指向 Glows.ai 的 OpenAI 相容端點，由環境變數設定）
- 結構驗證：`pydantic` v2
- 資料交換標準：`stix2`（OASIS STIX 2.1）
- 評估：`scikit-learn`、`pandas`
- 測試：`pytest`
- 設定：`python-dotenv`

## Commands

```bash
# 安裝
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 跑單一郵件（讀 stdin 或檔案）
python -m phishguard.pipeline --input data/self_made/case_01.json

# 跑評估，輸出 Precision / Recall / F1
python eval/evaluate.py --dataset data/eval/labeled.jsonl

# 測試
pytest -q
```

## Architecture（一段話）

郵件先正規化成統一 `Message` 物件 → **Stage 1**（輕量 LLM）快速二元過濾 safe / suspicious，保守取向、寧錯殺不放過 → 若 suspicious 才送 **Stage 2**（旗艦 LLM）做意圖分析，輸出 verdict / confidence / tactics / **MITRE ATT&CK technique** / evidence → **Stage 3**（旗艦 LLM）把技術報告轉成員工可讀的白話警示。每次處理都寫一筆 forensic 稽核紀錄，並把可疑 URL/網域匯出成 STIX IOC bundle。

## Conventions

- 三階段的 prompt 一律放在 `prompts/*.txt`，**用檔案管理、不要寫死在程式裡**（敏捷：prompt 也要版本控管）。
- 每個 LLM 回傳的 JSON 都必須用對應的 pydantic model 驗證；解析失敗就重試一次再 raise，**絕不直接信任或 eval LLM 輸出**。
- 所有設定（API base、key、模型名）走 `.env` + `config.py`，**不得硬編碼**。
- 程式碼模組化放在 `src/phishguard/`，每個模組要有對應 `tests/` 測試。
- commit 訊息用英文、一個里程碑一個 commit。

## 教授對齊五條硬規則（不可省略）

1. **威脅狩獵**：Stage 2 的 `tactics` 必須附帶 MITRE ATT&CK technique ID（見 `mitre.py`），讓輸出可被 hunt / 比對標準。
2. **資料交換標準**：偵測到的 URL / 網域 / 寄件者必須能由 `ioc.py` 匯出成 STIX 2.1 Indicator bundle。
3. **數位鑑識**：每封郵件入站時記錄 `case_id`、ISO8601 時戳、原文 SHA-256；稽核日誌 append-only（`forensics.py`）。
4. **隱私設計**：寫入 log / 報告前，一律先經 `privacy.redact()` 遮蔽收件人個資（email、身分證、卡號、電話）。
5. **保留證據**：**不要**遮蔽攻擊者的 URL / 網域——那是 IOC、是證據，redaction 只針對受害者 / 個人 PII。

## Gotchas

- LLM 偶爾回傳含 ```json 圍欄或多餘文字 → 解析前先 strip 圍欄，再 pydantic 驗證。
- Glows.ai 端點若非 OpenAI 相容，改 `llm_client.py` 的 adapter 即可，其餘程式不動。
- `data/raw/`（Enron、Nigerian Fraud 真實郵件）與 `.env` 一律 gitignore，**不得 commit**。
- `Message.channel` 預設 `"email"`；保留 `"line"` 欄位供未來擴充，現階段固定 email。
