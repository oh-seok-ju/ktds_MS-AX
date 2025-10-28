# app.py
from __future__ import annotations
import os
import json
import streamlit as st
from typing import List, Dict, Any

# 내부 모듈
from core.loader import load_rules_from_blob
from core.detector import detect, score, auto_mask, auto_mask_pairs
from core.suggest_llm import suggest_after_mask  # 환경 미설정이면 None 반환
from core.policy_search import search_snippets   # 환경 미설정이면 예외 -> 아래 try/except 처리

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
@st.cache_data(ttl=300)
def _load_rules_cached() -> Dict[str, Any]:
    # 환경변수로 Blob 연결 (RulesLoader 내부에서 처리)
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

    col_a, col_b, col_c = st.columns([1, 1, 1])
    with col_a:
        do_llm = st.toggle("AI 검사", value=True, key=f"toggle_llㄴm_{keyp}")
    with col_b:
        show_policy = st.toggle("정책 근거 보기", value=False, key=f"toggle_policy_{keyp}")
    with col_c:
        run_btn = st.button("검사 실행", type="primary", use_container_width=True, key=f"run_{keyp}")

    if not run_btn:
        st.info("입력 후 **검사 실행**을 눌러주세요.")
        return

    if not text.strip():
        st.warning("분석할 텍스트가 비어 있습니다.")
        return

    # 1) 룰 로드
    try:
        rules = _load_rules_cached()
    except Exception as e:
        st.error(f"규칙 로드 실패: {e}")
        return

    # 2) 룰 기반 탐지/점수/마스킹
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
            # st.code([{
            #     "category": h.get("id"),
            #     "severity": h.get("severity"),
            #     "action": ",".join(h.get("action") or []),
            #     "value": h.get("value"),
            #     # suggestion 필드가 hit에 없다면 detector에서 붙여주거나 아래 두 줄은 제거하세요.
            #     "suggestion": h.get("suggestion_kr") or h.get("suggestion_en") or "-"
            # } for h in warn_only])


    # 탐지 항목이 없으면 추가 마스킹/LLM/근거 표시를 생략하고 종료
    if not hits:
        if level == "allow":
            st.success("탐지 항목 없음 → 현재 입력은 이미 안전한 것으로 판단됩니다. (추가 마스킹/조치 불필요)")
        elif level == "warn":
            st.warning("탐지 항목은 없지만 점수 상 경고 임계치에 근접했습니다. 내용 재확인을 권장합니다.")
        else:  # block는 사실 hits 없으면 거의 안 나옵니다. 방어적 처리
            st.error("차단 등급으로 판정되었습니다.")
        # return  # ← 여기서 UI 흐름 종료 (아래 마스킹/LLM/RAG 섹션 표시 안 함)


    # 3) LLM 2차 검사 
    llm_result = None
    if do_llm:
        with st.spinner("AI 2차 검사/안전 리라이트 실행 중..."):
            try:
                llm_result = suggest_after_mask(masked, hits, locale="ko-KR")
            except Exception as e:
                st.warning(f"AI 검사 실패(무시하고 계속): {e}")
                llm_result = None

        if llm_result:
            st.subheader("AI 2차 검사 결과")
            verdict = llm_result.get("verdict", "unknown")
            st.write(f"**AI 판정:** `{verdict}`")
            if llm_result.get("residual_findings"):
                st.write("잔여 위험 항목:")
                st.json(llm_result["residual_findings"])
            if llm_result.get("masking_recommendations"):
                st.write("마스킹 보강 권고:")
                st.json(llm_result["masking_recommendations"])

            safe_text = llm_result.get("safe_text")
            if safe_text:
                with st.expander("AI 안전 리라이트(safe_text)", expanded=False):
                    st.code(safe_text, language="markdown" if kind == "email" else "python")

            rationale = llm_result.get("rationale")
            if rationale:
                st.info(f"AI 안내 사유: {rationale}")

    # 4) 정책 근거 (옵션)
    if show_policy:
        st.subheader("정책 근거 (Azure AI Search)")
        q = llm_policy_query(hits)
        st.caption(f"검색 질의: {q}")
        try:
            snippets = search_snippets(q, top_k=3)
            if snippets and isinstance(snippets, list) and not ("error" in (snippets[0] or {})):
                for s in snippets:
                    st.markdown(f"- **{s.get('title','(untitled)')}** — {s.get('snippet','')}")
            else:
                err = snippets[0].get("error") if snippets else "검색 결과 없음"
                st.warning(f"정책 검색 실패/없음: {err}")
        except Exception as e:
            st.warning(f"정책 검색 호출 실패(무시하고 계속): {e}")

    # 5) 후검증
    if do_llm and llm_result and llm_result.get("safe_text"):
        safe_text = llm_result["safe_text"]
        re_hits = detect(safe_text, rules)
        if re_hits:
            st.error("⚠️ AI safe_text 재검사에서 민감 요소가 다시 탐지되었습니다.")
            st.table([{
                "category": h.get("id"),
                "value": h.get("value"),
                "severity": h.get("severity")
            } for h in re_hits])
        else:
            st.success("AI safe_text 재검사: 추가 민감 요소 없음.")

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
    # 상태 및 상태의 색상 선택
    def status_text(ready: bool):
        color = "blue" if ready else "red"
        state = "Ready" if ready else "Stop"
        return f"<span style='color:{color}'><b>{state}</b></span>"

    # env에 키 값 기준으로 준비 or 미준비 판단 (나중에 연동에 대한 걸로 수정 해보자~)
    def is_valid_env(var_name: str) -> bool:
        """빈 문자열, 'none', 'null'도 Stop 처리"""
        value = os.getenv(var_name)
        if not value:
            return False
        return value.strip().lower() not in ("none", "null", "")

    st.header("💭연결 상태")
    st.markdown("**Azure Blob Storage**: " + status_text(is_valid_env("AZURE_BLOB_ACCOUNT_URL")), unsafe_allow_html=True)
    st.markdown("**Azure OpenAI**: " + status_text(is_valid_env("AZURE_OPENAI_KEY")), unsafe_allow_html=True)
    st.markdown("**Azure AI Search**: " + status_text(is_valid_env("AZURE_SEARCH_KEY")), unsafe_allow_html=True)

    st.divider()
    st.caption("환경이 일부 미설정이어도 \n 기본 검사는 항상 동작합니다.")