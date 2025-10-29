# core/suggest_llm.py
from __future__ import annotations
import os, json
from typing import List, Dict, Any, Optional
from openai import AzureOpenAI

from dotenv import load_dotenv
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "config", ".env"))


def llm_after_mask(original_text: str,
    grounds: Optional[List[Dict[str, Any]]] = None,   # RAG 검색 스니펫
    locale: str = "ko-KR"
) -> Optional[Dict[str, Any]]:
    
    print("@@@@LLM 호출 준비:")
    
    AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT")
    AZURE_OPENAI_KEY = os.getenv("AZURE_OPENAI_KEY")
    AZURE_OPENAI_API_VERSION = os.getenv("AZURE_OPENAI_API_VERSION")
    AZURE_OPENAI_DEPLOYMENT = os.getenv("AZURE_OPENAI_DEPLOYMENT")
    """
    원문 only + (필요 시) 정책 RAG 근거 스니펫 기반
    LLM이 독립적으로 block/warn/allow + 마스킹/삭제 권고 + 정책근거 인용까지 수행
    """
    print("client 생성")
    client = AzureOpenAI(
        api_key=AZURE_OPENAI_KEY,
        api_version=AZURE_OPENAI_API_VERSION,
        azure_endpoint=AZURE_OPENAI_ENDPOINT
    )

    system_prompt = (
        "You are a corporate security compliance assistant for a Korean enterprise.\n"
        "Your role is to identify ONLY truly sensitive information that poses security risks.\n\n"
        "답변은 무조건 한국어로 부탁해요.\n\n"

        "=== STRICT RULES ===\n"
        "1. **NOT Sensitive** (일반적인 사내 커뮤니케이션):\n"
        "   - Employee names with job titles (e.g., 'ktds 홍길동 전임', '김과장님')\n"
        "   - General greetings and business courtesy phrases\n"
        "   - Project names that are already public or internal-only but not confidential\n\n"
        
        "2. **Sensitive - WARN** (경고 수준):\n"
        "   - Names + partial contact info (e.g., '홍길동 010-1234-****')\n"
        "   - Internal project codenames (if explicitly marked confidential)\n"
        "   - Pricing information in negotiation context\n\n"
        
        "3. **Sensitive - BLOCK** (차단 필수):\n"
        "   - Full SSN/RRN (주민등록번호 13자리)\n"
        "   - API Keys (especially starting with 'sk-', 'Bearer', etc.)\n"
        "   - Passwords, access tokens, secrets\n"
        "   - Full bank account numbers\n"
        "   - Complete credit card numbers\n\n"
        
        "=== OUTPUT FORMAT ===\n"
        "Return JSON only:\n"
        "{\n"
        "  \"verdict\": \"allow\" | \"warn\" | \"block\",\n"
        "  \"residual_findings\": [{\"value\": string, \"reason\": string, \"suggestion\": string}],\n"
        "  \"masking_recommendations\": [{\"before\": string, \"after\": string, \"reason\": string}],\n"
        "  \"safe_text\": string,\n"
        "  \"rationale\": string,\n"
        "  \"policy_citations\": [{\"source\": string, \"page\": number, \"snippet\": string}]\n"
        "}\n\n"
        
        "=== CRITICAL GUIDELINES ===\n"
        "- When in doubt, choose 'allow' over 'warn'\n"
        "- Only cite policies (policy_citations) that DIRECTLY support your decision\n"
        "- Never duplicate the same source in policy_citations\n"
        "- Snippet must be <50 characters and directly relevant\n"
        "- Korean workplace culture: mentioning colleague names is normal, not sensitive\n"
    )
    payload = {
        "locale": locale,
        "text_original": original_text,
    }

    # 필요한 경우에만 정책 스니펫 전달 (5개 이하로 제한)
    if grounds:
        payload["ground_snippets"] = [
            {
                "source": g.get("source"),
                "snippet": g.get("snippet"),
                "title": g.get("title"),
                "content": g.get("content"),
            }
            for g in grounds[:5]
        ]

    print ("@@@@LLM Payload:", payload)
    response = client.chat.completions.create(
        model=AZURE_OPENAI_DEPLOYMENT,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)}

        ],
        temperature=0.1,
        response_format={"type": "json_object"}
    )

    try:
        # print("LLM Response:", response.choices)
        return json.loads(response.choices[0].message.content)
    except Exception:
        return None