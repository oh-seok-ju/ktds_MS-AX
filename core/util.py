from __future__ import annotations
import os
import streamlit as st
import requests
from azure.storage.blob import BlobServiceClient
from typing import List, Dict, Any

from dotenv import load_dotenv
# .env 파일 로드 (개발용)
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "config", ".env"))


# ===== 연결 테스트 함수들 =====
@st.cache_data(ttl=180, show_spinner=False)  # 1분간 캐시
def test_blob_connection() -> bool:
    """Azure Blob Storage 연결 테스트"""
    try:
        account_url  = os.getenv("AZURE_BLOB_ACCOUNT_URL")   
        account_name = os.getenv("AZURE_STORAGE_ACCOUNT_NAME")
        account_key  = os.getenv("AZURE_STORAGE_ACCOUNT_KEY")

        if not all([account_url, account_name, account_key]):
            return False

        credential = {"account_name": account_name, "account_key": account_key}

        client = BlobServiceClient(account_url=account_url, credential=credential)
        client.get_service_properties()  # 아주 가벼운 핑 수준
        return True

    except Exception as e:
        print(f"[DEBUG] Blob 연결 실패: {e}")
        return False
    
@st.cache_data(ttl=180, show_spinner=False)
def test_openai_connection() -> bool:
    """Azure OpenAI 설정 유효성만 간단 확인 (실제 모델 호출 없음, 빠른 Ping 수준)"""
    try:
        endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
        key      = os.getenv("AZURE_OPENAI_KEY")
        deploy   = os.getenv("AZURE_OPENAI_DEPLOYMENT")
        if not all([endpoint, key, deploy]):
            return False

        # 최소한의 endpoint 접근 확인 (HEAD / ping)
        r = requests.head(endpoint, timeout=3)
        return r.status_code < 400
    except Exception as e:
        print(f"[DEBUG] OpenAI ping 실패: {e}")
        return False

@st.cache_data(ttl=180, show_spinner=False)
def test_search_connection() -> bool:
    """Azure AI Search endpoint ping 확인"""
    try:
        endpoint = os.getenv("AZURE_SEARCH_ENDPOINT")
        key      = os.getenv("AZURE_SEARCH_KEY")
        if not all([endpoint, key]):
            return False

        import requests
        r = requests.head(endpoint, timeout=3)
        
        # Azure Cognitive Search는 정상이어도 대부분 403/401을 반환 → 연결 정상으로 간주
        return r.status_code in (200, 401, 403)
    
    except Exception as e:
        print(f"[DEBUG] Search ping 실패: {e}")
        return False


# ===== 상태 표시 함수 =====
def status_badge(ready: bool, testing: bool = False):
    if testing:
        return "🔄 **테스트 중...**"
    color = "green" if ready else "red"
    emoji = "✅" if ready else "❌"
    state = "Ready" if ready else "Failed"
    return f":{color}[{emoji} **{state}**]"



# =========================
# 유틸
# =========================
## 점수 기반 판정
def decide_level(total_score: int, scoring: Dict[str, Any]) -> str:
    block_th = scoring.get("block_threshold", 5)
    warn_th  = scoring.get("warn_threshold", 3)
    if total_score >= block_th:
        return "warn"
    if total_score >= warn_th:
        return "warn"
    return "allow"

# 
def render_hits(hits: List[Dict[str, Any]]):
    if not hits:
        # st.success("탐지 항목 없음 (룰 기반).")
        return
    st.subheader("단순 탐지 결과(조건식)")
    st.write(f"**총 {len(hits)}건**")
    st.table([
        {
            "category": h.get("id"),
            "type": h.get("type"),
            "value": h.get("value"),
            "severity": h.get("severity"),
            "action": ",".join(h.get("action") or []),
            "pattern_id": h.get("pattern_id","")
        } for h in hits
    ])

def split_hits_for_actions(hits: List[Dict[str, Any]]):
    """
    hits: detector.detect() 결과 (각 hit에 action 리스트가 들어있다고 가정)
    반환: (maskable, warn_only)
    """
    maskable, warn_only = [], []
    for h in hits:
        acts = set((h.get("action") or []))
        if "mask" in acts:
            maskable.append(h)
        else:
            warn_only.append(h)
    return maskable, warn_only

# def llm_policy_query(hits: List[Dict[str, Any]]) -> str:
#     """간단 생성: 감지된 카테고리를 기반으로 정책 검색 질의 구성"""
#     if not hits:
#         return "민감정보/보안 위반 정책"
#     cats = sorted(set(h["id"] for h in hits if h.get("id")))
#     return " / ".join(cats) + " 정책 근거"


def code_uploaded_text(uploaded_file) -> str:
    """
    Streamlit UploadedFile -> 텍스트로 안전 변환.
    우선순위: utf-8 -> cp949(ms949) -> latin-1
    """
    raw = uploaded_file.read()
    # 파일 재사용을 위해 포인터 리셋
    try:
        uploaded_file.seek(0)
    except Exception:
        pass

    for enc in ("utf-8", "cp949", "latin-1"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    # 최후 수단: 손실치환
    return raw.decode("utf-8", errors="ignore")