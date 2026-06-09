"""compare()：單一大模型 baseline vs 三階段級聯（準確率 + 成本）。

與 test_evaluate.py 風格一致，但**刻意不 mock 各 stage 的 run()**：
改成只 mock 最底層的 `llm_client._client`（OpenAI factory），讓「真實的 stage 流程、
真實的 parse_with_retry、以及 llm_client.chat() 內的呼叫計數器」全部實際執行——
這樣才能驗證 compare() 量到的「旗艦／輕量呼叫數」是真的、不是寫死的。

玩具資料集（4 封）刻意安排出可驗證的成本與混淆矩陣：
  - 級聯：每封都先過 Stage 1（輕量 1 次）；只有 suspicious 才進 Stage 2（旗艦 1 次）。
  - baseline：每封固定 1 次旗艦呼叫。
"""

import json
from types import SimpleNamespace

import pytest

from phishguard import evaluation, llm_client, stage1_filter, stage2_intent

LIGHT_MODEL = "toy-light"  # = settings.model_stage1（Stage 1 用）
FLAGSHIP_MODEL = "toy-flagship"  # = settings.model_stage2（Stage 2 與 baseline 用）

# (case_id, gold, stage1_label, stage2_verdict, baseline_verdict)
# a,b：真釣魚，級聯與 baseline 都判對。
# c  ：正常，Stage 1 即 safe（級聯在此停，不進旗艦）；baseline 也判對。
# d  ：正常，Stage 1 誤升 suspicious 但 Stage 2 救回 legitimate；baseline 卻誤判 phishing（FP）。
_TOY = [
    ("a", "phishing", "suspicious", "phishing", "phishing"),
    ("b", "phishing", "suspicious", "phishing", "phishing"),
    ("c", "legitimate", "safe", None, "legitimate"),
    ("d", "legitimate", "suspicious", "legitimate", "phishing"),
]
_SPEC = {cid: {"s1": s1, "s2": s2, "base": base} for cid, _g, s1, s2, base in _TOY}

# 級聯：每封 1 次輕量；suspicious 的 a,b,d 各再 1 次旗艦 → light=4, flagship=3。
_EXPECT_CASCADE_LIGHT = 4
_EXPECT_CASCADE_FLAGSHIP = 3
# baseline：每封 1 次旗艦 → flagship=4, light=0。
_EXPECT_BASELINE_FLAGSHIP = 4


def _case_of(prompt: str) -> str:
    """從 rendered prompt 反查是哪一筆（body 內嵌唯一 token [[cid]]）。"""
    for cid in _SPEC:
        if f"[[{cid}]]" in prompt:
            return cid
    raise AssertionError(f"prompt 無法對應到玩具案件：{prompt!r}")


def _route(model: str, prompt: str) -> str:
    """依「呼叫者」回傳對應的假 LLM JSON：baseline(片語) / Stage1(輕量模型) / Stage2(其餘)。"""
    spec = _SPEC[_case_of(prompt)]
    if "整封郵件是否為釣魚" in prompt:  # 單一大模型 baseline 的獨有片語
        return json.dumps({"verdict": spec["base"]}, ensure_ascii=False)
    if model == LIGHT_MODEL:  # Stage 1（輕量模型）
        return json.dumps({"label": spec["s1"], "reason": "toy"}, ensure_ascii=False)
    return json.dumps(  # Stage 2（旗艦模型）
        {
            "verdict": spec["s2"],
            "confidence": 90,
            "tactics": ["緊迫性"],
            "attack_techniques": ["T1566.002"],
            "evidence": ["可疑連結"],
            "summary": "toy",
        },
        ensure_ascii=False,
    )


# --- 假的 OpenAI client：只實作 chat.completions.create 用到的最小介面 -----------
class _FakeResp:
    def __init__(self, content: str):
        self.choices = [SimpleNamespace(message=SimpleNamespace(content=content))]


class _FakeCompletions:
    def create(self, *, model, messages, temperature=0.0):
        return _FakeResp(_route(model, messages[0]["content"]))


class _FakeClient:
    chat = SimpleNamespace(completions=_FakeCompletions())


@pytest.fixture(autouse=True)
def _wire_fakes(monkeypatch):
    """只 mock 最底層 client + 各模組的 get_settings；stage 與計數器照常真實執行。"""
    settings = SimpleNamespace(model_stage1=LIGHT_MODEL, model_stage2=FLAGSHIP_MODEL)
    monkeypatch.setattr(stage1_filter, "get_settings", lambda: settings)
    monkeypatch.setattr(stage2_intent, "get_settings", lambda: settings)
    monkeypatch.setattr(evaluation, "get_settings", lambda: settings)
    # 取代 lazy factory：chat() 仍會 +1 計數、仍跑真實 parse_with_retry。
    monkeypatch.setattr(llm_client, "_client", lambda: _FakeClient())
    llm_client.reset_call_count()


def _dataset():
    return [
        {"case_id": cid, "channel": "email", "body": f"玩具郵件 [[{cid}]]", "label": gold}
        for cid, gold, *_ in _TOY
    ]


def test_compare_costs_baseline_vs_cascade():
    """成本：baseline 每封 1 次旗艦；級聯只有 suspicious 進旗艦、其餘止於 Stage 1。"""
    result = evaluation.compare(_dataset())
    casc, base = result["cascade"], result["baseline"]

    assert result["n"] == 4

    # 級聯：每封 1 次輕量（4），僅 a,b,d 進旗艦（3）。
    assert casc["light_calls"] == _EXPECT_CASCADE_LIGHT
    assert casc["flagship_calls"] == _EXPECT_CASCADE_FLAGSHIP
    assert casc["total_calls"] == _EXPECT_CASCADE_LIGHT + _EXPECT_CASCADE_FLAGSHIP

    # baseline：每封固定 1 次旗艦、無輕量。
    assert base["flagship_calls"] == _EXPECT_BASELINE_FLAGSHIP
    assert base["light_calls"] == 0
    assert base["total_calls"] == _EXPECT_BASELINE_FLAGSHIP

    # 核心結論：級聯比 baseline 少打旗艦（省成本）。
    assert casc["flagship_calls"] < base["flagship_calls"]


def test_compare_prf_baseline_vs_cascade():
    """準確率：級聯全對(F1=1.0)；baseline 把 d 誤判成 phishing → precision=2/3, recall=1, f1=0.8。"""
    result = evaluation.compare(_dataset())
    casc, base = result["cascade"], result["baseline"]

    # 級聯：a,b→phishing；c→Stage1 safe→legitimate；d→Stage2 救回 legitimate → 全對。
    assert casc["precision"] == 1.0
    assert casc["recall"] == 1.0
    assert casc["f1"] == 1.0

    # baseline：[phish, phish, legit, phish] vs gold [phish, phish, legit, legit]
    # TP=2, FP=1(d), FN=0 → P=2/3、R=1.0、F1=0.8。
    assert base["precision"] == pytest.approx(2 / 3)
    assert base["recall"] == 1.0
    assert base["f1"] == pytest.approx(0.8)


def test_format_comparison_reports_savings():
    """format_comparison() 應反映「旗艦呼叫從 4 降到 3」的省成本敘述。"""
    text = evaluation.format_comparison(evaluation.compare(_dataset()))
    assert "資料集：4 封郵件" in text
    assert "從 4 降到 3" in text  # 省下 1 次旗艦呼叫
