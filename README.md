# PhishGuard — 多階段防釣魚與社交工程防禦網

以 LLM 驅動的三階段釣魚郵件偵測 pipeline，對齊台科大資安研究中心（林俊叡教授）專長：
**AI 輔助威脅狩獵 / 資安資料交換標準 / 數位鑑識 / 隱私設計 / 敏捷開發**。

> 專案憲法見 [CLAUDE.md](CLAUDE.md)，建置藍圖見 [claude_task_build.md](claude_task_build.md)。

---

## 架構

郵件正規化為統一的 `Message` 物件後，依序流經三階段，全程留下鑑識軌跡：

```
Message
   │
   ▼
[Stage 1] 輕量 LLM 二元過濾  safe / suspicious   (Recall 優先，保守取向)
   │  safe ─────────────► 只寫鑑識紀錄 (stopped_at=stage1)，結束
   ▼ suspicious
[Stage 2] 旗艦 LLM 意圖分析  verdict / confidence / tactics
   │                       + MITRE ATT&CK technique（威脅狩獵）/ evidence
   ▼
[Stage 3] 旗艦 LLM 白話警示  員工可讀的 emoji 五段通知
   │                       （對應緩解措施 M1017 User Training）
   ▼
每封 → 鑑識稽核紀錄 (logs/audit.jsonl, append-only)
phishing → STIX 2.1 IOC bundle (reports/<case_id>.stix.json)
```

| 模組 | 職責 |
|---|---|
| [schema.py](src/phishguard/schema.py) | pydantic v2 模型（`Message`、`Stage1/2/3Result`） |
| [config.py](src/phishguard/config.py) | 讀 `.env`（API base/key、各 stage 模型名），lazy、缺值報錯 |
| [llm_client.py](src/phishguard/llm_client.py) | OpenAI 相容 client（指向 Glows.ai），`temperature=0` |
| [parsing.py](src/phishguard/parsing.py) | 共用：Message 渲染、JSON 抽取、驗證 + 重試一次 |
| [privacy.py](src/phishguard/privacy.py) | 隱私設計：遮蔽受害者 PII、保留攻擊者 URL |
| [stage1_filter.py](src/phishguard/stage1_filter.py) / [stage2_intent.py](src/phishguard/stage2_intent.py) / [stage3_briefing.py](src/phishguard/stage3_briefing.py) | 三階段 |
| [mitre.py](src/phishguard/mitre.py) | 威脅狩獵：ATT&CK technique 驗證/補正 + 緩解措施對照 |
| [forensics.py](src/phishguard/forensics.py) | 數位鑑識：SHA-256 + append-only 稽核日誌 |
| [ioc.py](src/phishguard/ioc.py) | 資料交換標準：STIX 2.1 IOC 匯出 |
| [pipeline.py](src/phishguard/pipeline.py) | 串接 1→2→3 + 鑑識 + IOC + CLI |
| [evaluation.py](src/phishguard/evaluation.py) | 入站遮蔽、預測、P/R/F1、單一模型 vs 級聯成本比較 |

---

## 安裝與設定

```powershell
# Windows PowerShell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .                 # 讓 `python -m phishguard.pipeline` 可直接執行
Copy-Item .env.example .env      # 再填入 Glows.ai 端點與金鑰
```

```bash
# macOS / Linux
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt && pip install -e .
cp .env.example .env
```

`.env` 必填（**不得硬編碼、不得 commit**）。本專案以 Glows.ai 雲端 GPU 透過 **Ollama** 部署 **Qwen2.5**；`GLOWS_API_BASE` 指向該 Ollama 的 OpenAI 相容端點（在 GPU 機器上直接執行即為 `localhost:11434`，遠端則以 SSH tunnel 轉埠）。亦可替換為任何 OpenAI 相容端點：

```
GLOWS_API_BASE=http://localhost:11434/v1   # Glows.ai GPU 上的 Ollama（OpenAI 相容）
GLOWS_API_KEY=ollama                        # Ollama 不驗金鑰，填任意非空字串
MODEL_STAGE1=qwen2.5:7b                      # 輕量（Stage 1）
MODEL_STAGE2=qwen2.5:14b                     # 旗艦（Stage 2）
MODEL_STAGE3=qwen2.5:14b                     # 旗艦（Stage 3，可同 STAGE2）
```

---

## 用法

```bash
# 跑單一郵件（JSON 為 Message 結構）
python -m phishguard.pipeline --input data/self_made/case_01.json

# 啟動網頁介面（貼上郵件 → 三階段判讀 → STIX 下載）
streamlit run app.py

# 評估：印 Precision / Recall / F1（目標 F1 >= 0.85）
python eval/evaluate.py --dataset data/eval/labeled.jsonl

# 比較單一大模型 vs 三階段級聯（準確率 + 旗艦/輕量呼叫成本）
python eval/compare.py --dataset data/eval/labeled.jsonl

# 由公開語料庫（SpamAssassin / Nazario）建立真實郵件評估集
python eval/build_public_dataset.py --ham data/raw/easy_ham --phish data/raw/Nazario.csv \
  --out data/eval/labeled_public.jsonl --per-class 50

# 測試（不需 .env、不打真實 LLM）
pytest -q
```

輸入 JSON 範例：

```json
{
  "case_id": "case_01",
  "channel": "email",
  "sender": "it-support@company-secure-portal.com",
  "subject": "【重要】密碼即將到期",
  "body": "IT 部門通知：請於今日更新密碼，否則帳號停用",
  "urls": ["http://company-secure-portal.com/reset"]
}
```

`pipeline.process()` 回傳的是**已遮蔽**的鑑識紀錄，因此印到 stdout 也不會洩漏個人 PII。

---

## 教授對齊五條硬規則

| # | 規則 | 落實處 |
|---|---|---|
| 1 | **威脅狩獵**：tactics 附帶 MITRE ATT&CK technique ID | [mitre.py](src/phishguard/mitre.py) `enrich_techniques`，Stage 2 套用 |
| 2 | **資料交換標準**：URL/網域/寄件者匯出 STIX 2.1 | [ioc.py](src/phishguard/ioc.py) |
| 3 | **數位鑑識**：case_id + ISO8601 時戳 + 原文 SHA-256、append-only | [forensics.py](src/phishguard/forensics.py) |
| 4 | **隱私設計**：寫 log/報告前先遮蔽受害者 PII | [privacy.py](src/phishguard/privacy.py)，forensics/eval 入站套用 |
| 5 | **保留證據**：不遮蔽攻擊者 URL/網域（IOC） | 見下方設計重點 |

---

## 設計重點（幾個刻意做對的細節）

### 1. `redact()` 的 URL 保護——讓 IOC 在遮蔽中存活
釣魚 URL 常嵌在郵件 body 裡，而 URL query 可能含像 `?id=9876543210987654` 的長數字串。
若直接套用「卡號 = 13–16 連續數字」regex，會把這段**攻擊者 IOC 證據誤遮**。
因此 [privacy.py](src/phishguard/privacy.py) 的 `redact()` 採「**先抽出並保護所有 URL → 遮蔽個人 PII → 還原 URL**」的順序：
受害者 email / 身分證 / 卡號 / 電話被遮成 token，但攻擊者 URL（連同其中的數字）原樣保留（硬規則 5）。

### 2. 鑑識雜湊順序——先 hash 原文，後 redact
[forensics.py](src/phishguard/forensics.py) 的 `make_record()` 嚴格遵守：
**① 先對「原始 body」算 SHA-256（chain of custody 錨點）→ ② 再 `redact` → ③ 存「遮蔽版內容」+「原文 hash」**。
順序不可顛倒：若先 redact 再 hash，存進去的會是遮蔽版的 hash，無法與原件比對，鑑識完整性就驗不了。
（測試 `test_forensics.py` 反向鎖住：遮蔽版的 hash ≠ 紀錄裡的 hash。）

### 3. 寄件者的雙重處理——內部留存 vs 對外情資
同一個寄件者在兩處的待遇刻意不同，反映兩種用途：
- **稽核日誌 (`logs/audit.jsonl`)**：走**內部留存、隱私保守**，`sender` 經 `redact` 遮蔽。
- **STIX bundle (`reports/`)**：走**對外情資共享**，`sender` 原樣保留為攻擊者 IOC（硬規則 2 & 5）。

### 4. Prompt 注入用 `.replace`，不用 `str.format`
三階段 prompt 檔內含字面 JSON 範例（如 `{"label": ...}`）。用 `str.format()` 會把這些大括號當成
格式佔位符而出錯，因此一律用 `prompt.replace("{message}", ...)` 只替換指定佔位符。

### 5. ATT&CK 兩端對齊——攻擊 technique + 防禦 mitigation
Stage 2 標的是攻擊面的 **technique**（T1566 系列等）；Stage 3 的員工警示對應防禦面的緩解措施
**M1017 User Training（員工教育）**（[mitre.py](src/phishguard/mitre.py) `STAGE3_MITIGATION`）。偵測與防禦兩端都能扣到 ATT&CK 標準。

### 6. 絕不信任 LLM 原始輸出
每個 LLM 回傳都先 strip ```json 圍欄 / 多餘文字，再經對應 pydantic model 驗證；
解析或驗證失敗會重試一次再 raise，**絕不 `eval()` 或直接信任**（[parsing.py](src/phishguard/parsing.py)）。

---

## 測試

```bash
pytest -q          # 全程不打真實 LLM：mock 掉 chat() 與各 stage，亦不需 .env
```

涵蓋：schema 驗證、privacy 遮蔽（含 URL 保留）、三階段解析/重試、MITRE 對照、
鑑識雜湊順序與 append-only、STIX 匯出、pipeline 整合、評估 P/R/F1。

---

## 評估結果

> 完整方法、逐類別表現與取捨討論見報告「評估結果與成本分析」一節。以下為摘要（對應 tag `v1.0`）。

在兩份資料集上比較「單一大模型」與「三階段級聯」：

| 資料集 | 方法 | Precision | Recall | F1 | 旗艦呼叫 |
|---|---|---|---|---|---|
| 自製 50 | 單一大模型 | 1.000 | 1.000 | 1.000 | 50 |
| 自製 50 | 三階段級聯 | 1.000 | 1.000 | 1.000 | 25 |
| 公開 100 | 單一大模型 | 0.766 | 0.980 | 0.860 | 100 |
| 公開 100 | 三階段級聯 | 0.863 | 0.880 | 0.871 | 51 |

- 自製集兩種做法皆滿分，因樣本同質、過於理想，無法區分優劣（假性滿分）。
- 公開真實郵件上，級聯 **F1 較高（0.871 > 0.860）、誤報明顯較少（Precision 0.863 > 0.766）**，且**旗艦呼叫減半**（100 → 51）。
- 公開集：正常 50（SpamAssassin easy_ham）＋ 釣魚 50（Nazario，經 Kaggle phishing-email-dataset 彙整）。

---

## 重現評估

評估分兩個層次：

**（1）程式與測試——完全確定性，不需 LLM / GPU**

```bash
pip install -r requirements.txt
pytest -q        # → 86 passed；驗證所有邏輯（解析、遮蔽、MITRE、鑑識、STIX、級聯比較）
```

**（2）偵測數字——需 LLM 後端（Ollama + Qwen2.5 + GPU）**

```bash
# 模型（本研究用 Glows.ai 雲端 GPU）
ollama pull qwen2.5:7b      # 輕量（Stage 1）
ollama pull qwen2.5:14b     # 旗艦（Stage 2、3）
cp .env.example .env        # 確認指向你的 Ollama 端點

# 自製集（已隨 repo 提供）
python eval/compare.py  --dataset data/eval/labeled.jsonl
python eval/evaluate.py --dataset data/eval/labeled.jsonl

# 公開集：若 data/eval/labeled_public.jsonl 已隨 repo 提供，可直接評估它；
# 否則用下列指令由公開語料庫重建（seed=42 → 可重現的同一組 100 封）：
mkdir -p data/raw
wget -P data/raw https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2
tar xjf data/raw/20030228_easy_ham.tar.bz2 -C data/raw
kaggle datasets download -d naserabdullahalam/phishing-email-dataset -p data/raw --unzip
python eval/build_public_dataset.py --ham data/raw/easy_ham --phish data/raw/Nazario.csv \
  --out data/eval/labeled_public.jsonl --per-class 50
python eval/compare.py  --dataset data/eval/labeled_public.jsonl
python eval/evaluate.py --dataset data/eval/labeled_public.jsonl
```

> **註**：本評估對應 tag `v1.0`（評估程式自 commit `dcefbee` 起未再變更）。LLM 在 `temperature=0` 大致穩定，但跨 Ollama 版本、量化與硬體可能略有差異，故重現數字應與報告**接近、未必逐位元相同**。

---

## 目前限制 / 後續

- **資料集語言**：公開評估集（SpamAssassin、Nazario）為英文，而 prompt 為中文；模型仍能正確處理（間接驗證中英文混雜穩定性），惟中文真實釣魚語料將更貼近目標場景。
- **樣本規模**：自製 50 封、公開 100 封，受 GPU 成本限制；更大樣本可使估計更穩定。
- **時間漂移**：Nazario 語料年代較早，而真實釣魚手法持續演化（temporal drift）。
- **LLM 變異**：評估為單次執行（temperature=0），跨環境數字會接近但未必完全一致。
- **範圍固定 email**：`Message.channel` 保留 `"line"` 欄位供未來擴充，現階段固定 `"email"`。

## 不入版控

`.env`、`data/raw/`（真實郵件）、`reports/`、`logs/`、`.venv/` 皆於 [.gitignore](.gitignore) 排除。
