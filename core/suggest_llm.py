# core/suggest_llm.py
from __future__ import annotations
import os, json
from typing import List, Dict, Any, Optional

try:
    from openai import AzureOpenAI
    HAS_AZURE_OPENAI = True
except Exception:
    HAS_AZURE_OPENAI = False

AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT")
AZURE_OPENAI_KEY = os.getenv("AZURE_OPENAI_KEY")
AZURE_OPENAI_API_VERSION = os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-15-preview")
AZURE_OPENAI_DEPLOYMENT = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o-mini")

def suggest_after_mask(masked_text: str, hits: List[Dict[str, Any]], locale: str="ko-KR") -> Optional[Dict[str, Any]]:
    """
    2차 LLM 검사/안전 리라이트 스텁.
    환경이 없으면 None 반환. 응답은 JSON 파싱 시도.
    """
    if not (HAS_AZURE_OPENAI and AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_KEY):
        return None

    client = AzureOpenAI(
        api_key=AZURE_OPENAI_KEY,
        api_version=AZURE_OPENAI_API_VERSION,
        azure_endpoint=AZURE_OPENAI_ENDPOINT
    )

    sys = "너는 보안/프라이버시 감수관이다. JSON만 반환하라. 확실하지 않으면 warn."
    user = {
        "locale": locale,
        "text_masked": masked_text,
        "hits_v1": hits,
        "requirements": [
            "verdict(block|warn|allow)",
            "residual_findings[]",
            "masking_recommendations[]",
            "safe_text",
            "rationale",
            "policy_citations[]"
        ]
    }

    resp = client.chat.completions.create(
        model=AZURE_OPENAI_DEPLOYMENT,
        messages=[
            {"role": "system", "content": sys},
            {"role": "user", "content": json.dumps(user, ensure_ascii=False)}
        ],
        temperature=0.1,
        response_format={"type": "json_object"}
    )
    try:
        return json.loads(resp.choices[0].message.content)
    except Exception:
        return None
