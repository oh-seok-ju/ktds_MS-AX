# app.py
from __future__ import annotations
import os
import json
import streamlit as st
from typing import List, Dict, Any
import requests

# 내부 모듈
from core.loader import load_rules_from_blob
from core.detector import detect, score, auto_mask_pairs, ai_warn_items
from core.suggest_llm import llm_after_mask  # 환경 미설정이면 None 반환
from core.policy_search import search_snippets   # 환경 미설정이면 예외 -> 아래 try/except 처리
from azure.storage.blob import BlobServiceClient

from dotenv import load_dotenv
# .env 파일 로드 (개발용)
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "config", ".env"))


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
    st.subheader("탐지 결과 (정책 기반)")
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

def llm_policy_query(hits: List[Dict[str, Any]]) -> str:
    """간단 생성: 감지된 카테고리를 기반으로 정책 검색 질의 구성"""
    if not hits:
        return "민감정보/보안 위반 정책"
    cats = sorted(set(h["id"] for h in hits if h.get("id")))
    return " / ".join(cats) + " 정책 근거"

# =========================
# 룰 로드 (Blob)
# =========================
@st.cache_data(ttl=300, show_spinner=False)
def _load_rules_cached() -> Dict[str, Any]:
    """규칙을 Blob에서 로드 (5분간 캐시)"""
    rules = load_rules_from_blob()
    return rules

def run_analyzer_ui(kind: str):
    """
    kind: 'email' | 'code'
    """
    keyp = kind  # key prefix
    ph = "안녕하세요, KTds 000 입니다. \n\n여기에 메일 내용을 작성하거나 복사해보세요! " if kind == "email" else "여기에 코드/로그/설정을 작성하거나 붙여 넣으세요..."
    default_text = ""
    text = st.text_area("**입력 창(POC)**", default_text, height=220, placeholder=ph, key=f"input_{keyp}")

    col_a, col_c = st.columns([1, 1])
    with col_a:
        do_llm = st.toggle("AI 검사", value=True, key=f"toggle_llm_{keyp}")
    with col_c:
        run_btn = st.button("검사 실행", type="primary", use_container_width=True, key=f"run_{keyp}")

    if not run_btn:
        st.info("입력 후 **검사 실행**을 눌러주세요.")
        return

    if not text.strip():
        st.warning("분석할 텍스트가 비어 있습니다.")
        return

    # =========================
    # # 1) 룰 로드 
    # ========================
    try:
        rules = _load_rules_cached()
    except Exception as e:
        st.error(f"규칙 로드 실패: {e}")
        return

    # =========================
    # # 2) 룰 기반 1차 검사
    # ========================
    hits = detect(text, rules)
    total = score(hits, rules)
    level = decide_level(total, rules.get("scoring", {}))

    render_hits(hits)
    st.write(f"**Risk Score: {total}**  |  **`{level}`**")

    # 액션별로 분리
    maskable, warn_only = split_hits_for_actions(hits)

    # 마스킹 섹션: mask 대상이 있을 때만 표시
    if maskable:
        pairs = auto_mask_pairs(text, maskable, rules)
        if pairs:
            with st.expander("🔒 마스킹 대상 항목", expanded=True):
                for before, after in pairs:
                    st.code(f"{before}  →  {after}   (🔒 마스킹)", language="markdown" if kind == "email" else "python")
        else:
            st.info("마스킹 대상은 있으나 미리보기를 생성할 항목이 없습니다.")

    # 비마스킹 섹션: 경고/권고만 표시
    if warn_only:
        with st.expander("⚠️ 삭제 권장", expanded=True):
            for h in warn_only:
                value = h.get("value")
                suggestion = h.get("suggestion_kr") or h.get("suggestion_en") or "⚠️ 삭제 권장"
                st.code(f"{value}   →   {suggestion}", language="markdown" if kind == "email" else "python")

    # 탐지 항목이 없으면 추가 마스킹/LLM/근거 표시를 생략하고 종료
    if not hits:
        if level == "allow":
            st.success("✅추가 마스킹/조치 불필요 AI 검사로 상세 검사를 진행해 보세요!")
        elif level == "warn":
            st.warning("⚠️탐지 항목은 없지만 점수 상 경고 임계치에 근접했습니다. 내용 재확인을 권장합니다.")
        else:  # block는 사실 hits 없으면 거의 안 나옵니다. 방어적 처리
            st.error("🚫차단 등급으로 판정되었습니다.")

    # =========================
    # # 3) LLM 2차 검사 및 정책 근거 인용
    # ========================
    llm_result = None
    if do_llm:

        try:
            # 정책 검색
            with st.spinner("🔍 정책 근거 검색 중..."):
                grounds = search_snippets(text, top_k=3)
            
            # 검색 결과 검증
            has_valid_grounds = grounds and isinstance(grounds, list) and not grounds[0].get("error")
            
            if has_valid_grounds:
                st.write("---")
            else:
                grounds = None  # LLM에는 None 전달
            
        except Exception as e:
            print(f"[ERROR] 정책 찾는 중 오류: {e}") 



        # ===== LLM 호출 (정책 유무와 무관하게 실행) =====
        try:
            with st.spinner("🔍 AI 분석 중..."):
                llm_result = llm_after_mask(text, grounds=grounds, locale="ko-KR")
        
                if not llm_result:
                    llm_result = None
        except Exception as e:
            st.error(f"❌AI 검사 실패: {e}")
            # =============================================
    

        # 결과 표시
        if llm_result:
            st.subheader("AI를 통한 2차 검사 결과")
            verdict = llm_result.get("verdict", "unknown")
            print(f"[DEBUG] LLM 결과: {llm_result}")
            # 판정 결과 표시
            if verdict == "allow":
                st.success(f"**AI 판정:** ✅ `{verdict}` (문제 없음)")
            elif verdict == "warn":
                st.warning(f"**AI 판정:** ⚠️ `{verdict}` (주의 필요)")
            else:
                st.error(f"**AI 판정:** 🚫 `{verdict}` (차단 권장)")

            # 권장 항목
            ai_warns = ai_warn_items(llm_result)
            if ai_warns:
                with st.expander("⚠️🔒 삭제/마스킹/조치 권장 항목", expanded=True):
                    for value, suggestion in ai_warns:
                        st.code(f"{value}   →   {suggestion}", language="markdown" if kind=="email" else "python")

            # 인용 근거 (정책이 있을 때만)
            if has_valid_grounds:
                cites = llm_result.get("policy_citations") or []
                if cites:
                    st.subheader("📎 인용(내부 정책)")
                    
                    by_key = {k: g for g in grounds 
                            for k in [g.get("source"), g.get("title")] if k}
                    
                    seen_sources = set()
                    for c in cites:
                        source = c.get("source") or c.get("title")
                        if source in seen_sources:
                            continue
                        seen_sources.add(source)
                        
                        ref = by_key.get(c.get("source")) or by_key.get(c.get("title"))
                        title = c.get("title") or (ref or {}).get("title") or "내부 정책 문서"
                        snippet = c.get("snippet") or (ref or {}).get("snippet", "")
                        
                        st.markdown(f"참고 정책 - **{title}**")
                        if snippet:
                            brief = snippet[:150] + ("…" if len(snippet) > 150 else "")
                            st.info(brief)
            else:
                # 정책 없이 판단한 경우
                print("[DEBUG] 정책 문서 없이 LLM 판단")
                st.caption("💡 관련 정책 문서가 없어 일반 기준으로 분석했습니다.")    

# =========================
# Streamlit UI
# =========================
st.set_page_config(page_title="(MVP) AI Governance Assistant", page_icon="🛡️", layout="wide")
st.title("🛡️ AI 보안/교정/감사 Assistant 🛡️")
# st.caption("룰 기반 1차 필터 → AI 2차 감수 → AI Search 정책 근거 인용")

tab1, tab2 = st.tabs(["📧 이메일 검사", "🧰 코드 검사"])

with tab1:
    st.write("메일/메시지 본문 등을 입력해 검사합니다.")
    run_analyzer_ui(kind="email")
       
with tab2:
    st.write("코드/로그/설정 텍스트 등을 입력해 검사합니다.")
    run_analyzer_ui(kind="code")

with st.sidebar:
    st.header("💭 연결 상태")
    
    # ===== 연결 테스트 함수들 =====
    @st.cache_data(ttl=60, show_spinner=False)  # 1분간 캐시
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
        
    @st.cache_data(ttl=60, show_spinner=False)
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

    @st.cache_data(ttl=60, show_spinner=False)
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
    

    # Blob Storage
    with st.spinner("Blob Storage 확인 중..."):
        blob_ok = test_blob_connection()
    st.markdown(f"**Azure Blob Storage:** {str(status_badge(blob_ok))}")
    
    # OpenAI
    with st.spinner("OpenAI 확인 중..."):
        openai_ok = test_openai_connection()
    st.markdown(f"**Azure OpenAI:** {str(status_badge(openai_ok))}")
    
    # AI Search
    with st.spinner("AI Search 확인 중..."):
        search_ok = test_search_connection()
    st.markdown(f"**Azure AI Search:**{str(status_badge(search_ok))}")
    st.markdown("---")
