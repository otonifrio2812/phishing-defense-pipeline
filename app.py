"""PhishGuard Streamlit 網頁：貼上郵件 → 跑三階段 pipeline → 顯示結果 + STIX 下載。

啟動：streamlit run app.py
注意：實際分析會呼叫 LLM，需先依 .env.example 建立 .env（填入 Glows.ai 端點與金鑰），
      建立後請「重新啟動」streamlit（停掉再重跑），.env 才會生效。
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

# src-layout：確保不論是否 pip install -e . 都能 import phishguard。
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from phishguard import pipeline  # noqa: E402
from phishguard.config import get_settings  # noqa: E402
from phishguard.mitre import ATTACK_TECHNIQUES  # noqa: E402
from phishguard.schema import Message  # noqa: E402

st.set_page_config(page_title="PhishGuard 釣魚郵件偵測", page_icon="🛡️", layout="centered")


# --- 範例郵件（方便 demo / 報告展示，不必每次手打） ---------------------------
PHISH_SAMPLE = {
    "sender": "finance-dept@company-secure-verify.com",
    "subject": "【緊急】報銷補件：請於今日下班前完成",
    "body": (
        "您好，我是財務長 David Chen。您的報銷申請需要補充一份授權文件，"
        "請在今日下班前將您的員工憑證與系統密碼填入此表單，逾期申請將作廢。"
    ),
    "urls": "https://forms-internal-hr.net/verify",
}
LEGIT_SAMPLE = {
    "sender": "hr@company.com",
    "subject": "Q2 業績檢討會議通知",
    "body": "各位同仁，Q2 檢討會議訂於 6/10 上午 10:00 於 3F 會議室舉行，請準備各部門簡報。",
    "urls": "",
}


def _load_sample(sample: dict) -> None:
    """把範例填進輸入欄位。用 on_click callback（在 widget 建立前執行才安全）。"""
    st.session_state["in_sender"] = sample["sender"]
    st.session_state["in_subject"] = sample["subject"]
    st.session_state["in_body"] = sample["body"]
    st.session_state["in_urls"] = sample["urls"]


def _risk(verdict: str, confidence: int) -> tuple[str, str]:
    """由 verdict + confidence 推導風險等級（標籤, 顏色）。"""
    if verdict != "phishing":
        return "低風險", "green"
    if confidence >= 80:
        return "高風險", "red"
    if confidence >= 50:
        return "中風險", "orange"
    return "偏低風險", "orange"


def _show_forensics(record: dict) -> None:
    """展開即可看到「已遮蔽的鑑識紀錄」：展示隱私遮蔽 + 原文 SHA-256 + chain of custody。"""
    with st.expander("🔒 鑑識紀錄（已遮蔽個資，含原文 SHA-256）"):
        st.json(record)


def _show_result(record: dict) -> None:
    # --- 第一階段：初步過濾 ---------------------------------------------------
    st.divider()
    st.markdown("### 第一階段：初步過濾")
    s1 = record.get("stage1", {})
    if s1.get("label") == "safe":
        st.success("判定：safe（正常）", icon="✅")
    else:
        st.warning("判定：suspicious（可疑，升級分析）", icon="🚩")
    if s1.get("confidence"):  # 做完 Stage 1 v1.2（加 confidence）後才有；沒有也不會壞
        st.caption(f"初篩信心：{s1['confidence']}")
    st.caption(f"理由：{s1.get('reason', '')}")

    # Stage 1 判 safe：流程在此結束（節省旗艦模型）。
    if record.get("stopped_at") == "stage1":
        st.info("郵件在第一階段即判定為正常，流程結束（節省旗艦模型運算）。", icon="🛑")
        _show_forensics(record)
        return

    # --- 第二階段：意圖分析 ---------------------------------------------------
    st.divider()
    st.markdown("### 第二階段：意圖分析")
    s2 = record.get("stage2", {})
    verdict = s2.get("verdict", "?")
    confidence = int(s2.get("confidence", 0))
    risk_label, risk_color = _risk(verdict, confidence)

    if verdict == "phishing":
        st.error("判定為釣魚郵件", icon="🎣")
    else:
        st.success("判定為正常郵件", icon="📩")

    m1, m2 = st.columns(2)
    m1.metric("信心分數", f"{confidence} / 100")
    m2.markdown(f"**風險等級**  \n:{risk_color}[**{risk_label}**]")

    if s2.get("summary"):
        st.markdown(f"**摘要**：{s2['summary']}")
    if s2.get("tactics"):
        st.markdown("**社交工程手法**：" + "、".join(str(t) for t in s2["tactics"]))

    techs = s2.get("attack_techniques", [])
    if techs:
        st.markdown("**MITRE ATT&CK**：")
        for t in techs:
            name = ATTACK_TECHNIQUES.get(t, "")
            st.markdown(f"- `{t}`" + (f" — {name}" if name else ""))

    if s2.get("evidence"):
        st.markdown("**關鍵證據**：")
        for e in s2["evidence"]:
            st.markdown(f"- {e}")

    # --- 第三階段：員工警示 ---------------------------------------------------
    st.divider()
    st.markdown("### 第三階段：員工警示")
    briefing = record.get("stage3", {}).get("briefing_text", "")
    if briefing:
        st.markdown(briefing)

    # --- 威脅情資（STIX 2.1）下載 --------------------------------------------
    stix_path = record.get("stix_path")
    if stix_path and Path(stix_path).exists():
        st.divider()
        st.markdown("### 威脅情資（STIX 2.1）")
        st.download_button(
            "⬇️ 下載 STIX 2.1 IOC bundle",
            data=Path(stix_path).read_text(encoding="utf-8"),
            file_name=Path(stix_path).name,
            mime="application/json",
        )

    _show_forensics(record)


# --- 頁面標題 -----------------------------------------------------------------
st.title("🛡️ PhishGuard 釣魚郵件偵測")
st.caption("多階段 LLM 防釣魚與社交工程防禦網（Stage 1 初篩 → Stage 2 意圖分析 → Stage 3 員工警示）")

# --- 檢查 .env 是否就緒（缺了給友善提示，不崩潰） -----------------------------
config_ok = True
try:
    get_settings()
except RuntimeError as exc:
    config_ok = False
    st.warning(
        "尚未設定 LLM 連線，目前無法實際分析。\n\n"
        "請在專案根目錄把 `.env.example` 複製成 `.env`，填入 Glows.ai 的端點與金鑰"
        "（GLOWS_API_BASE / GLOWS_API_KEY / MODEL_STAGE1 / MODEL_STAGE2 / MODEL_STAGE3），"
        "存檔後「重新啟動」streamlit（停掉再重跑）。",
        icon="⚠️",
    )
    st.caption(f"（系統訊息：{exc}）")

# --- 輸入區 -------------------------------------------------------------------
st.subheader("貼上要檢查的郵件")
c1, c2 = st.columns(2)
c1.button("載入釣魚範例", on_click=_load_sample, args=(PHISH_SAMPLE,), use_container_width=True)
c2.button("載入正常範例", on_click=_load_sample, args=(LEGIT_SAMPLE,), use_container_width=True)

sender = st.text_input("寄件者", key="in_sender", placeholder="someone@example.com")
subject = st.text_input("主旨", key="in_subject")
body = st.text_area("正文", key="in_body", height=180, placeholder="把郵件內文貼在這裡…")
urls_raw = st.text_area("連結（每行一個，可留空）", key="in_urls", height=80, placeholder="https://...")

run = st.button("🔍 開始分析", type="primary", disabled=not config_ok, use_container_width=True)

# --- 執行 ---------------------------------------------------------------------
if run:
    if not body.strip():
        st.error("請至少填入郵件「正文」再分析。")
    else:
        urls = [u.strip() for u in urls_raw.splitlines() if u.strip()]
        msg = Message(
            case_id=f"web-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}",
            sender=sender.strip() or None,
            subject=subject.strip() or None,
            body=body.strip(),
            urls=urls,
        )
        try:
            with st.spinner("分析中…（呼叫 LLM 跑三階段）"):
                result = pipeline.process(msg)
        except Exception as exc:  # noqa: BLE001 — 對使用者顯示友善錯誤而非崩潰
            st.error(f"分析時發生錯誤：{exc}")
        else:
            _show_result(result)
