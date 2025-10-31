# app.py
from __future__ import annotations
import os
import json
import streamlit as st
from typing import List, Dict, Any
import requests
import mimetypes
from datetime import datetime
from io import BytesIO

from azure.storage.blob import BlobServiceClient, ContentSettings
from azure.core.credentials import AzureKeyCredential
from azure.search.documents.indexes import SearchIndexerClient

# 내부 모듈
from core.loader import load_rules_from_blob
from core.detector import detect, score, auto_mask_pairs, ai_warn_items
from core.suggest_llm import llm_after_mask, llm_after_mask_rag  # 환경 미설정이면 None 반환
from core.policy_search import search_snippets   # 환경 미설정이면 예외 -> 아래 try/except 처리
# 함수 모음 (시간 나면 함수 내부 정리) llm_policy_query
from core.util import test_blob_connection, test_openai_connection, test_search_connection, status_badge, decide_level, render_hits, split_hits_for_actions, code_uploaded_text

from dotenv import load_dotenv
# .env 파일 로드 (개발용)
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "config", ".env"))


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
    # ph = "안녕하세요, KTds 000 입니다. \n\n여기에 메일 내용을 작성하거나 복사해보세요! " if kind == "email" else "여기에 코드/로그/설정을 작성하거나 붙여 넣으세요..."
    # default_text = ""
    # text = st.text_area("**입력 창(POC)**", default_text, height=220, placeholder=ph, key=f"input_{keyp}")

    # === [변경] 입력부: email은 text_area, code는 file_uploader ===
    if kind == "email":
        ph = "안녕하세요, KTds 000 입니다. \n\n여기에 메일 내용을 작성하거나 복사해보세요! \n\n 텍스트가 너무 길면 오류가 발생합니다."
        default_text = ""
        text = st.text_area("**Text**", default_text, height=220, placeholder=ph, key=f"input_{keyp}")
        source_name = "입력 텍스트"
    else:
        # st.caption("코드/로그/설정 파일을 업로드해 검사합니다. (.py/.log/.json/.yaml 등 텍스트 파일)")
        uploaded = st.file_uploader(
            "**Upload**",
            type=["txt", "py", "log", "json", "yaml", "yml", "cfg", "ini", "toml", ".env"],
            accept_multiple_files=False,
            key=f"uploader_{keyp}"
        )
        text = ""
        source_name = ""
        if uploaded:
            source_name = uploaded.name
            text = code_uploaded_text(uploaded)
            # 파일명이 길 경우 축약 표시
            shown_name = (source_name[:40] + "…") if len(source_name) > 40 else source_name
            st.success(f"업로드됨: **{shown_name}**  | 사이즈: ~{len(text):,} chars")

    col_a, col_b, col_c = st.columns([1, 1, 1])
    with col_a:
        do_llm = st.toggle("AI 검사 (내부 정책)", value=True, key=f"toggle_llm_{keyp}")

    with col_b:
        do_rag = st.toggle("AI 검사 (하이브리드)", value=True, key=f"toggle_rag_{keyp}")

    with col_c:
        run_btn = st.button("검사 실행", type="primary", use_container_width=True, key=f"run_{keyp}")

    if not run_btn:
        st.success("입력 후 **검사 실행**을 눌러주세요.")
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
                if do_rag:
                    llm_result = llm_after_mask_rag(text, grounds=grounds, use_rag=True)
                
                else:
                    llm_result = llm_after_mask(text, grounds=grounds, locale="ko-KR")

                # ✅ Azure Search grounds 추출
                if llm_result and '_azure_search_grounds' in llm_result:
                    azure_grounds = llm_result.pop('_azure_search_grounds')  # 결과에서 제거하고 가져옴
                    # 기존 grounds와 병합 (또는 대체)
                    if not has_valid_grounds:
                        grounds = azure_grounds
                        has_valid_grounds = True
                        print(f"[DEBUG] Azure Search에서 {len(azure_grounds)}개 정책 문서 참조")
                
                if not llm_result:
                    llm_result = None
        except Exception as e:
            st.error(f"❌AI 검사 실패: {e}")

        # =============================================
        # 결과 표시 (기존 코드 그대로 사용)

        if llm_result:
            st.subheader("AI 정밀 검사 결과")
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

            # ✅ 인용 근거 (has_valid_grounds로 판단)
            if has_valid_grounds:
                cites = llm_result.get("policy_citations") or []
                if cites:
                    st.subheader("📎 인용(내부 정책)")
                    
                    # grounds를 검색 가능하도록 딕셔너리로 변환
                    by_key = {}
                    for g in grounds:
                        for k in [g.get("source"), g.get("title")]:
                            if k:
                                by_key[k] = g
                    
                    seen_sources = set()
                    for c in cites:
                        source = c.get("source") or c.get("title")
                        if source in seen_sources:
                            continue
                        seen_sources.add(source)
                        
                        ref = by_key.get(c.get("source")) or by_key.get(c.get("title"))
                        title = c.get("title") or (ref or {}).get("title") or "AI의 생각"
                        snippet = c.get("snippet") or (ref or {}).get("snippet", "")
                        
                        st.markdown(f"참고 정책 - **{title}**")
                        if snippet:
                            brief = snippet[:150] + ("…" if len(snippet) > 150 else "")
                            st.info(brief)
            else:
                # 정책 없이 판단한 경우
                print("[DEBUG] 정책 문서 없이 LLM 판단")
                st.caption("💡 관련 정책 문서가 없어 일반 기준으로 분석했습니다.")

        # ===== LLM 호출 (정책 유무와 무관하게 실행) =====
        # try:

        #     with st.spinner("🔍 AI 분석 중..."):
        #         # llm_result = llm_after_mask(text, grounds=grounds, locale="ko-KR")
        #         llm_result = llm_after_mask_rag(text, use_rag=True)
        #         if not llm_result:
        #             llm_result = None
        # except Exception as e:
        #     st.error(f"❌AI 검사 실패: {e}")
        #     # =============================================
        #     # 결과 표시

        # if llm_result:
        #     st.subheader("AI 정밀 검사 결과")
        #     verdict = llm_result.get("verdict", "unknown")
        #     print(f"[DEBUG] LLM 결과: {llm_result}")
        #     # 판정 결과 표시
        #     if verdict == "allow":
        #         st.success(f"**AI 판정:** ✅ `{verdict}` (문제 없음)")
        #     elif verdict == "warn":
        #         st.warning(f"**AI 판정:** ⚠️ `{verdict}` (주의 필요)")
        #     else:
        #         st.error(f"**AI 판정:** 🚫 `{verdict}` (차단 권장)")

        #     # 권장 항목
        #     ai_warns = ai_warn_items(llm_result)
        #     if ai_warns:
        #         with st.expander("⚠️🔒 삭제/마스킹/조치 권장 항목", expanded=True):
        #             for value, suggestion in ai_warns:
        #                 st.code(f"{value}   →   {suggestion}", language="markdown" if kind=="email" else "python")

        #     # 인용 근거 (정책이 있을 때만)
        #     if has_valid_grounds:
        #         cites = llm_result.get("policy_citations") or []
        #         if cites:
        #             st.subheader("📎 인용(내부 정책)")
                    
        #             by_key = {k: g for g in grounds 
        #                     for k in [g.get("source"), g.get("title")] if k}
                    
        #             seen_sources = set()
        #             for c in cites:
        #                 source = c.get("source") or c.get("title")
        #                 if source in seen_sources:
        #                     continue
        #                 seen_sources.add(source)
                        
        #                 ref = by_key.get(c.get("source")) or by_key.get(c.get("title"))
        #                 title = c.get("title") or (ref or {}).get("title") or "내부 정책 문서"
        #                 snippet = c.get("snippet") or (ref or {}).get("snippet", "")
                        
        #                 st.markdown(f"참고 정책 - **{title}**")
        #                 if snippet:
        #                     brief = snippet[:150] + ("…" if len(snippet) > 150 else "")
        #                     st.info(brief)
        #     else:
        #         # 정책 없이 판단한 경우
        #         print("[DEBUG] 정책 문서 없이 LLM 판단")
        #         st.caption("💡 관련 정책 문서가 없어 일반 기준으로 분석했습니다.")    

        
# =========================
# Streamlit UI
# =========================
st.set_page_config(page_title="(MVP) SecureAI Assistant", page_icon="🛡️", layout="wide")
st.title("SecureAI Assistant")
# st.caption("룰 기반 1차 필터 → AI 2차 감수 → AI Search 정책 근거 인용")

tab1, tab2 = st.tabs(["📧 이메일/메시지 검사", "🧰 문서 검사(코드/로그/텍스트)"])

with tab1:
    st.info("메일/메시지 본문 등을 입력해 보세요!")
    run_analyzer_ui(kind="email")
       
with tab2:
    st.info("코드/로그/텍스트등 파일을 업로드 해보세요!")
    run_analyzer_ui(kind="code")

with st.sidebar:
    st.header("💭 연결 상태")
    
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
    
    # === 여기부터 추가: 업로드 타이틀은 항상 노출, 컨트롤은 blob_ok 일 때만 ===
with st.sidebar:
    st.markdown("---")
    st.subheader("📤 정책 문서 업로드")

   # blob_ok 는 위에서 이미 계산된 값(Blob Storage 연결 상태)
    if not blob_ok:
        st.caption("⚠️ Blob 연결 준비 중이어서 업로드 컨트롤은 일시 숨김입니다.")
    else:
        # .env에서 업로드용 컨테이너 이름 읽기
        policy_container = os.getenv("AZURE_BLOB_CONTAINER_POLICIES")
        account_url  = os.getenv("AZURE_BLOB_ACCOUNT_URL")
        account_name = os.getenv("AZURE_STORAGE_ACCOUNT_NAME")
        account_key  = os.getenv("AZURE_STORAGE_ACCOUNT_KEY")


        # AI Search 관련 환경 변수
        search_endpoint = os.getenv("AZURE_SEARCH_ENDPOINT")
        search_key = os.getenv("AZURE_SEARCH_KEY")
        indexer_name = os.getenv("AZURE_SEARCH_INDEXER_NAME")  # .env에 추가 필요

        # # 📁 폴더 선택 라디오 버튼 추가
        # folder_choice = st.radio(
        #     "정책 저장 대상",
        #     options=["email", "code"],
        #     horizontal=True,
        #     key="folder_selector"
        # )


    uploaded_files = st.file_uploader(
        "정책 문서 파일을 선택하세요 (.pdf/.docx/.md/.txt 등)",
        type=["pdf", "docx", "md", "txt", "html"],
        accept_multiple_files=True,
        key="policy_uploader"
    )

    if uploaded_files:
        if st.button("업로드", use_container_width=True, key="btn_upload_policies"):
            try:
                credential = {"account_name": account_name, "account_key": account_key}
                bsc = BlobServiceClient(account_url=account_url, credential=credential)
                cc  = bsc.get_container_client(policy_container)

                success, fail = 0, 0
                time = datetime.now().strftime('%y%m%d%H%M%S')
                progress = st.progress(0.0, text="업로드 준비 중...")
                for idx, f in enumerate(uploaded_files, start=1):
                    try:
                        # 선택한 폴더 경로 + 파일명 + time
                        # blob_name = f"{folder_choice}/{f.name}_{time}"
                        blob_name = f"{f.name}_{time}"
                        mime, _ = mimetypes.guess_type(f.name)
                        content_settings = ContentSettings(content_type=mime or "application/octet-stream")

                        # Streamlit UploadedFile 은 .read()로 바이트 획득
                        cc.upload_blob(
                            name=blob_name,
                            data=f.read(),
                            overwrite=True,
                            content_settings=content_settings
                        )
                        success += 1
                    except Exception as e:
                        fail += 1
                        st.error(f"업로드 실패: {f.name} - {e}")

                    progress.progress(idx / len(uploaded_files), text=f"업로드 진행 {idx}/{len(uploaded_files)}")
                
                progress.empty()  # 진행바 제거

                if success:
                    # st.success(f"✅ 업로드 완료: {success}개 → `{folder_choice}/` 폴더")
                    st.success(f"✅ 업로드 완료: {success}개 ")
                    # 인덱서 재실행 진행
                    try:
                        with st.spinner("🔄 동기화 진행 중..."):
                            indexer_client = SearchIndexerClient(
                                endpoint=search_endpoint,
                                credential=AzureKeyCredential(search_key)
                            )
                            indexer_client.run_indexer(indexer_name)
                            st.success("✅ 동기화 완료! 잠시 후 반영됩니다.")

                    # 인덱서 재실행 중 오류 발생시        
                    except Exception as e:
                        st.warning(f"⚠️ 인덱서 재실행 실패: {e}")
                # 파일 업로드 실패 시
                if fail:
                    st.warning(f"⚠️ 업로드 실패: {fail}개")

            except Exception as e:
                st.error(f"업로드 중 오류: {e}")