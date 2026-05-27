# claude_task_build.md — 建置藍圖

給 Claude Code 的指示：**請依本文件從零建置整個專案。** 一個里程碑做完就 commit 一次（敏捷）。每個里程碑下方有「驗收標準」，做到才算完成。先讀 `CLAUDE.md` 的五條硬規則，全程遵守。

---

## 0. 目標與範圍（重要：不要擴大範圍）

- 沿用原定計畫：**email 釣魚偵測**、三階段 pipeline、資料集用 **Enron + Nigerian Fraud + 自製 10 封**。
- **不要**改成 LINE / 即時通訊版本。`channel` 欄位保留 `"email"` 即可。
- 各成員報告裡的三段 prompt 是團隊既有成果，**語意不要改寫**，只在指定處「附加」MITRE 輸出欄位。

---

## 1. 目錄結構（請完整建立）

```
<repo-root>/
├── CLAUDE.md                     # 已存在，勿覆蓋
├── claude_task_build.md          # 本檔
├── README.md
├── requirements.txt
├── .env.example
├── .gitignore
├── prompts/
│   ├── stage1_filter.txt
│   ├── stage2_intent.txt
│   └── stage3_briefing.txt
├── src/phishguard/
│   ├── __init__.py
│   ├── config.py                 # 讀 .env
│   ├── schema.py                 # pydantic models
│   ├── llm_client.py             # OpenAI 相容 client（指向 Glows.ai）
│   ├── privacy.py                # 隱私設計：PII 遮蔽
│   ├── forensics.py              # 數位鑑識：雜湊 + 稽核日誌
│   ├── mitre.py                  # 威脅狩獵：ATT&CK 對照
│   ├── ioc.py                    # 資料交換標準：STIX 匯出
│   ├── stage1_filter.py
│   ├── stage2_intent.py
│   ├── stage3_briefing.py
│   └── pipeline.py               # 串接 1→2→3 + 寫鑑識紀錄 + 匯出 IOC
├── data/
│   ├── raw/                      # Enron, Nigerian Fraud（gitignore）
│   ├── self_made/                # 自製 10 封 .json
│   └── eval/labeled.jsonl        # 標註評估集
├── eval/evaluate.py              # Precision / Recall / F1
├── reports/                      # 產出的鑑識報告 + STIX bundle（gitignore）
├── logs/                         # append-only 稽核日誌（gitignore）
└── tests/
    ├── test_schema.py
    ├── test_privacy.py
    ├── test_mitre.py
    └── test_pipeline.py
```

---

## 2. 設定檔內容（請照建）

**requirements.txt**
```
openai>=1.0
pydantic>=2.0
python-dotenv>=1.0
stix2>=3.0
scikit-learn>=1.3
pandas>=2.0
pytest>=8.0
```

**.env.example**
```
GLOWS_API_BASE=https://<填入 Glows.ai 的 OpenAI 相容端點>/v1
GLOWS_API_KEY=<填入你的金鑰>
MODEL_STAGE1=<輕量模型名>
MODEL_STAGE2=<旗艦模型名>
MODEL_STAGE3=<旗艦模型名，可同 STAGE2>
```

**.gitignore**（至少包含）
```
.venv/
__pycache__/
.env
data/raw/
reports/
logs/
*.pyc
```

---

## 3. 資料模型 `schema.py`（參考實作，請依此建並補完）

```python
from enum import Enum
from typing import Literal, Optional
from pydantic import BaseModel, Field

class Channel(str, Enum):
    email = "email"
    line = "line"          # 保留，現階段固定 email

class Message(BaseModel):
    case_id: str
    channel: Channel = Channel.email
    sender: Optional[str] = None
    subject: Optional[str] = None
    body: str
    urls: list[str] = []
    received_at: Optional[str] = None      # ISO8601

class Stage1Result(BaseModel):
    label: Literal["safe", "suspicious"]
    reason: str

class Stage2Result(BaseModel):
    verdict: Literal["phishing", "legitimate"]
    confidence: int = Field(ge=0, le=100)
    tactics: list[str]
    attack_techniques: list[str] = []      # 教授對齊：MITRE ID，如 "T1566.002"
    evidence: list[str]
    summary: str

class Stage3Result(BaseModel):
    briefing_text: str                      # 員工可讀警示（含 emoji 條列）
```

---

## 4. 三階段 Prompt（沿用各成員原稿，放進 `prompts/`）

### `prompts/stage1_filter.txt`（成員 A 原稿）
```
你是一個電子郵件安全分析師，負責初步判斷郵件是否可疑。
請閱讀以下郵件內容，並以 JSON 格式回答：{"label": "safe" 或 "suspicious", "reason": "一句話說明理由"}
判斷標準：若郵件含有緊迫語氣、要求個資、可疑連結或寄件者網域異常，請標記為 suspicious。
原則：寧可把正常郵件誤標為可疑，也不能讓釣魚郵件通過（Recall 優先）。

郵件內容：
{message}
```

### `prompts/stage2_intent.txt`（成員 B 原稿 + 教授對齊附加欄位）
```
你是一位資深資安分析師，專門識別商業電子郵件詐騙（BEC）與釣魚攻擊。
請針對以下被初步標記為可疑的郵件，進行深度意圖分析。

分析步驟：
1) 識別郵件中使用的社交工程手法（如緊迫性、權威性、稀缺性）。
2) 判斷攻擊者的最終意圖（竊取憑證 / 誘導匯款 / 散播惡意程式）。
3) 列出關鍵證據。
4) 對應到 MITRE ATT&CK technique ID（如 T1566.002 Spearphishing Link）。

請以 JSON 格式回答：
{"verdict": "phishing" 或 "legitimate", "confidence": 0-100,
 "tactics": [...], "attack_techniques": ["T1566.002", ...],
 "evidence": [...], "summary": "一段話說明"}

郵件內容：
{message}
```
> 說明：原稿只到第 3 步，第 4 步與 `attack_techniques` 欄位是為對齊教授「威脅狩獵 / 資料交換標準」新增的。`mitre.py` 會再驗證 / 補正模型給的 ID。

### `prompts/stage3_briefing.txt`（成員 C 原稿）
```
你是一位友善的企業資安教練，負責將技術性的釣魚偵測報告，轉化為員工可理解的警戒通知。
請根據以下分析結果，生成一份警戒摘要，格式如下：

【⚠️ 釣魚郵件警戒通知】
🔍 這封郵件哪裡有問題？（用2-3句白話說明）
🎯 攻擊者想要達到什麼目的？（一句話）
✅ 你應該怎麼做？（3個具體行動建議）
📚 下次如何識別類似郵件？（2個識別技巧）

分析結果（JSON）：
{stage2_json}
```

---

## 5. 教授對齊模組（參考規格）

### `privacy.py` — 隱私設計
- `redact(text: str) -> str`：以 regex 遮蔽**收件人 / 個人** PII，替換成 token。
  - email → `[EMAIL]`；台灣身分證 `[A-Z][12]\d{8}` → `[ID]`；卡號 13–16 連續數字 → `[CARD]`；電話 → `[PHONE]`。
- **關鍵**：傳入時要能標記哪些是攻擊者 IOC（URL/網域），這些**不遮蔽**。實作上建議只 redact `body` 與 `sender`，`urls` 原樣保留。
- 在 `forensics.py` 寫紀錄前、`stage3` 產出對外文字前都要呼叫。

### `forensics.py` — 數位鑑識
- `make_record(msg, s1, s2, s3) -> dict`：產生鑑識紀錄：
  ```json
  {"case_id": "...", "ingested_at": "ISO8601", "sha256": "<原文雜湊>",
   "channel": "email", "redacted": true,
   "stage1": {...}, "stage2": {...}, "stage3": {...},
   "chain_of_custody": [{"stage":"ingest","ts":"..."}, {"stage":"stage1","ts":"..."}, ...]}
  ```
- `append_audit(record)`：append-only 寫入 `logs/audit.jsonl`（一行一筆，**不可覆寫既有行**）。
- SHA-256 對「原始 body」做雜湊，確保事後可驗證完整性（chain of custody）。

### `mitre.py` — 威脅狩獵 / ATT&CK 對照
```python
# 釣魚相關 technique（請上 attack.mitre.org 再核對一次正確性）
ATTACK_TECHNIQUES = {
    "T1566":     "Phishing",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1566.003": "Spearphishing via Service",
    "T1598":     "Phishing for Information",
    "T1657":     "Financial Theft",        # BEC / 誘導匯款
}
# 中文 tactic → technique，供後處理補正模型輸出
TACTIC_TO_TECHNIQUE = {
    "仿冒品牌": "T1566", "可疑網域": "T1566.002", "誘導點擊連結": "T1566.002",
    "惡意附件": "T1566.001", "誘導匯款": "T1657", "竊取憑證": "T1566.002",
}
def validate_techniques(ids: list[str]) -> list[str]:
    return [i for i in ids if i in ATTACK_TECHNIQUES]
```

### `ioc.py` — 資料交換標準 / STIX 2.1
- `to_stix_bundle(msg, s2) -> stix2.Bundle`：把可疑 URL / 網域包成 STIX `Indicator`：
  ```python
  import stix2
  ind = stix2.Indicator(
      name="Phishing URL",
      pattern=f"[url:value = '{url}']",
      pattern_type="stix",
  )
  bundle = stix2.Bundle(ind)   # 多個 indicator 一起放
  ```
- 寫出 `reports/<case_id>.stix.json`。依 `stix2` 套件實際 API 為準（2.1 欄位需求由套件處理）。

---

## 6. 各 Stage 與 pipeline 行為

- `stage1_filter.run(msg) -> Stage1Result`：載入 prompt → 呼叫 `MODEL_STAGE1` → 解析驗證。
- `stage2_intent.run(msg) -> Stage2Result`：呼叫 `MODEL_STAGE2`；拿到後用 `mitre.validate_techniques()` 過濾、必要時用 `TACTIC_TO_TECHNIQUE` 補。
- `stage3_briefing.run(s2) -> Stage3Result`：呼叫 `MODEL_STAGE3`。
- `pipeline.process(msg)`：
  1. `s1 = stage1.run(msg)`
  2. 若 `s1.label == "safe"`：只寫鑑識紀錄（標記 stopped_at=stage1），結束。
  3. 否則 `s2 = stage2.run(msg)` → `s3 = stage3.run(s2)`。
  4. `record = forensics.make_record(...)`（先 `privacy.redact`）→ `forensics.append_audit(record)`。
  5. 若 `s2.verdict == "phishing"`：`ioc.to_stix_bundle(...)` 寫出 STIX。
  6. 回傳整合結果。
- 提供 CLI：`python -m phishguard.pipeline --input <file.json>`。

---

## 7. 資料與評估計畫

- `data/eval/labeled.jsonl`：每行 `{"case_id","channel":"email","sender","subject","body","urls","label":"phishing"|"legitimate"}`。
- 來源：Enron（legitimate 基準）、Nigerian Fraud（phishing）、自製 10 封。目標**至少 50 筆、正常與釣魚各半**（呼應組長 Week 15 計畫）。
- **入站即 redact**：把資料載進 jsonl 時就先過 `privacy.redact`（個人 PII），但保留攻擊者 URL。
- `eval/evaluate.py`：對每筆跑 pipeline，取 Stage 2 `verdict`（safe 直接視為 legitimate）對比 gold label，用 `sklearn.metrics` 算 Precision / Recall / F1 並印 `classification_report`。**目標 F1 ≥ 0.85。**

---

## 8. 建置順序（里程碑，做完各 commit 一次）

- **M0 Scaffold**：建目錄、venv、`requirements.txt`、`.env.example`、`.gitignore`、空模組與 tests 骨架。`git init` 首次 commit。
  - 驗收：`pip install -r requirements.txt` 成功、`pytest` 能跑（即使全 skip）。
- **M1 基礎層**：`config.py`、`schema.py`、`llm_client.py`、`privacy.py`（含測試）。
  - 驗收：`test_privacy` 通過——email/身分證/卡號被遮蔽，URL 不被遮蔽。
- **M2 Stage 1**：`prompts/stage1_filter.txt` + `stage1_filter.py`，JSON 解析失敗會重試。
  - 驗收：用成員 A 報告的 5 筆樣本測試，輸出皆能通過 `Stage1Result` 驗證。
- **M3 Stage 2 + MITRE**：`stage2_intent.py` + `mitre.py`。
  - 驗收：用成員 B 的 Microsoft 365 樣本，`verdict="phishing"` 且 `attack_techniques` 含有效 ID（如 T1566.002）。
- **M4 Stage 3**：`stage3_briefing.py`，輸出符合成員 C 的 emoji 五段格式。
- **M5 Pipeline + 鑑識 + IOC**：`pipeline.py`、`forensics.py`、`ioc.py` 串起來。
  - 驗收：跑一封釣魚郵件 → `logs/audit.jsonl` 多一筆（含 sha256）、`reports/<id>.stix.json` 產出、log 內無未遮蔽個資。
- **M6 資料 + 評估**：建 `labeled.jsonl`、`eval/evaluate.py`。
  - 驗收：印出 P/R/F1；若 < 0.85，回頭調 prompt（記錄在 commit）。
- **M7 收尾**：`README.md`、CLI、補測試。

---

## 9. 絕對不要做（Do NOT）

- 不要 commit `data/raw/` 真實郵件或 `.env` / API key。
- 不要在 log / 報告寫入未遮蔽的個人 PII（一律先 `privacy.redact`）。
- 不要遮蔽攻擊者的 URL / 網域——那是 IOC、是證據。
- 不要直接信任或 `eval()` LLM 回傳；一律 pydantic 驗證。
- 不要改寫各成員 prompt 的原意；只在 Stage 2 指定處附加 MITRE 欄位。
- 不要把範圍擴大到 LINE / 多管道。
