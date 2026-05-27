"""讀 .env 設定（API base / key / 各 stage 模型名）。

所有設定走 .env，不得硬編碼（CLAUDE.md 慣例）。
import 本模組會嘗試載入 .env，但**不會**因缺值報錯——只有真正要呼叫 LLM 時，
get_settings() 才會檢查必要變數是否齊全，讓不需要金鑰的測試（schema/privacy）可正常 import。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

from dotenv import load_dotenv

# import 時載入 .env（若存在）；找不到檔案不報錯。
load_dotenv()


@dataclass(frozen=True)
class Settings:
    """執行期所需的所有外部設定。皆來自環境變數，無預設值、不硬編碼。"""

    api_base: str
    api_key: str
    model_stage1: str
    model_stage2: str
    model_stage3: str


_REQUIRED = {
    "api_base": "GLOWS_API_BASE",
    "api_key": "GLOWS_API_KEY",
    "model_stage1": "MODEL_STAGE1",
    "model_stage2": "MODEL_STAGE2",
    "model_stage3": "MODEL_STAGE3",
}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """讀取並快取設定。缺任何必要變數時，丟出可讀錯誤指向 .env.example。"""
    missing = [env for env in _REQUIRED.values() if not os.environ.get(env)]
    if missing:
        raise RuntimeError(
            "缺少必要環境變數：" + ", ".join(missing) + "；請依 .env.example 建立 .env。"
        )
    return Settings(**{field: os.environ[env] for field, env in _REQUIRED.items()})
