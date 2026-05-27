# PhishGuard — 多階段防釣魚與社交工程防禦網

以 LLM 驅動的三階段釣魚郵件偵測 pipeline。詳見 [CLAUDE.md](CLAUDE.md)（專案憲法）與 [claude_task_build.md](claude_task_build.md)（建置藍圖）。

> 🚧 建置中。目前進度：**M0 Scaffold**。README 將於 M7 收尾時補完。

## 快速開始

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1          # Windows PowerShell
# source .venv/bin/activate         # macOS / Linux
pip install -r requirements.txt
cp .env.example .env                 # 填入 Glows.ai 端點與金鑰
pytest -q
```

## 三階段架構

1. **Stage 1**（輕量 LLM）— 快速二元過濾 safe / suspicious，Recall 優先。
2. **Stage 2**（旗艦 LLM）— 意圖分析，輸出 verdict / confidence / tactics / MITRE ATT&CK / evidence。
3. **Stage 3**（旗艦 LLM）— 轉成員工可讀的白話警示。

每筆處理寫入 append-only 鑑識稽核紀錄，並把可疑 URL/網域匯出成 STIX 2.1 IOC bundle。
