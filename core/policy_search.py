# core/policy_search.py
from __future__ import annotations

import os
from typing import List, Dict, Any, Optional

# pip install azure-search-documents
from azure.core.credentials import AzureKeyCredential
from azure.search.documents import SearchClient
from azure.search.documents.models import QueryType


class PolicySearch:
    """
    Azure Cognitive Search(=Azure AI Search)에서 정책 근거 스니펫을 조회하는 경량 헬퍼.

    환경변수(필수):
      - AZURE_SEARCH_ENDPOINT  : https://<service>.search.windows.net
      - AZURE_SEARCH_KEY       : admin/query key
      - AZURE_SEARCH_INDEX     : 인덱스명 (예: policy-index)

    환경변수(선택):
      - AZURE_SEARCH_SEMANTIC_CONFIG : 세맨틱 구성 이름(있을 때만 사용)
      - AZURE_SEARCH_SEARCH_FIELDS   : 검색 필드(콤마분리, 기본: content,title)
      - AZURE_SEARCH_FILTER          : 고정 filter OData 식 (예: "securityLevel eq 'internal'")

    인덱스 스키마 가정(확실하지 않음: 조직별 상이):
      - content(Text)  : 본문(조각) 저장
      - title(Edm.String) : 문서/섹션 제목
      - version(Edm.String) : 문서 버전
      - source(Edm.String)  : 원본 파일명/경로
      - chunk_id(Edm.String): 조각 ID
    """

    def __init__(
        self,
        endpoint: Optional[str] = None,
        key: Optional[str] = None,
        index_name: Optional[str] = None,
        semantic_config: Optional[str] = None,
        search_fields: Optional[List[str]] = None,
        fixed_filter: Optional[str] = None,
    ) -> None:
        endpoint = endpoint or os.getenv("AZURE_SEARCH_ENDPOINT")
        key = key or os.getenv("AZURE_SEARCH_KEY")
        index_name = index_name or os.getenv("AZURE_SEARCH_INDEX")
        semantic_config = semantic_config or os.getenv("AZURE_SEARCH_SEMANTIC_CONFIG", "").strip() or None
        fixed_filter = fixed_filter or os.getenv("AZURE_SEARCH_FILTER", "").strip() or None

        if not endpoint or not key or not index_name:
            raise RuntimeError("Azure Search 환경변수(AZURE_SEARCH_ENDPOINT/KEY/INDEX)가 필요합니다.")

        self.client = SearchClient(endpoint=endpoint, index_name=index_name, credential=AzureKeyCredential(key))
        self.semantic_config = semantic_config
        self.search_fields = search_fields or (os.getenv("AZURE_SEARCH_SEARCH_FIELDS") or "content,title").split(",")
        self.fixed_filter = fixed_filter

    def search_snippets(
        self,
        query: str,
        top_k: int = 3,
        *,
        filter_expr: Optional[str] = None,
        use_semantic_if_available: bool = True,
        highlight: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        정책 근거 스니펫 조회.

        반환: [{title, snippet, score, version, source, chunk_id}, ...]
        """
        if not query or not query.strip():
            return []

        # 기본 옵션(키워드 모드)
        search_kwargs: Dict[str, Any] = {
            "top": top_k,
            "query_type": QueryType.SIMPLE,
            "search_fields": self.search_fields,
        }

        # 필터(고정 + 호출시 전달) 결합
        filt = self.fixed_filter
        if filter_expr:
            filt = f"({filt}) and ({filter_expr})" if filt else filter_expr
        if filt:
            search_kwargs["filter"] = filt

        # 하이라이트/캡션 옵션
        if highlight:
            # 하이라이트 필드(우선 content)
            search_kwargs["highlight_fields"] = ["content"]
            search_kwargs["highlight_pre_tag"] = "<em>"
            search_kwargs["highlight_post_tag"] = "</em>"

        # 세맨틱 검색 옵션(있을 때만)
        if use_semantic_if_available and self.semantic_config:
            search_kwargs["query_type"] = QueryType.SEMANTIC
            search_kwargs["semantic_configuration_name"] = self.semantic_config
            # extractive summaries (captions)
            search_kwargs["captions"] = "extractive"
            search_kwargs["answers"] = "extractive"  # 있으면 요약 답변도 반환

        results: List[Dict[str, Any]] = []
        try:
            resp = self.client.search(query, **search_kwargs)
            for doc in resp:
                item = self._to_snippet(doc, highlight=highlight)
                results.append(item)
        except Exception as e:
            # 운영 시 로깅 권장
            return [{"error": f"Azure Search 검색 실패: {e}"}]

        return results

    def _to_snippet(self, doc: Any, highlight: bool = True) -> Dict[str, Any]:
        """
        SDK SearchResult -> 깔끔한 dict 변환
        """
        # document fields
        _doc = doc if isinstance(doc, dict) else doc
        source = _doc.get("source") if hasattr(_doc, "get") else getattr(_doc, "source", None)
        title = _doc.get("title") if hasattr(_doc, "get") else getattr(_doc, "title", None)
        version = _doc.get("version") if hasattr(_doc, "get") else getattr(_doc, "version", None)
        chunk_id = _doc.get("chunk_id") if hasattr(_doc, "get") else getattr(_doc, "chunk_id", None)
        content = _doc.get("content") if hasattr(_doc, "get") else getattr(_doc, "content", None)

        # score
        score = getattr(doc, "@search.score", None) or getattr(doc, "score", None)
        if score is None and hasattr(doc, "score"):
            score = doc.score  # fallback

        # highlight / captions
        snippet = None
        if highlight:
            hl = getattr(doc, "@search.highlights", None) or getattr(doc, "highlights", None)
            if hl and isinstance(hl, dict):
                # content 필드 하이라이트가 있으면 우선 사용
                snippets = hl.get("content") or []
                if snippets:
                    snippet = " … ".join(snippets[:2])

        if snippet is None:
            # 세맨틱 캡션이 있으면 사용
            caps = getattr(doc, "@search.captions", None)
            if caps and isinstance(caps, list) and len(caps) > 0:
                # captions: [ { text: "...", highlights: [...] }, ... ]
                cap_text = caps[0].get("text")
                if cap_text:
                    snippet = cap_text

        # 아무 것도 없으면 content 앞부분 컷
        if snippet is None and content:
            snippet = (content[:300] + "…") if len(content) > 300 else content

        return {
            "title": title or source or "(untitled)",
            "snippet": snippet or "",
            "score": float(score) if score is not None else None,
            "version": version,
            "source": source,
            "chunk_id": chunk_id,
        }


# ---- 모듈 레벨 헬퍼 ----

def search_snippets(query: str, top_k: int = 3, **kwargs) -> List[Dict[str, Any]]:
    """
    간단 헬퍼: 환경변수 기반으로 PolicySearch 생성 후 검색.
    사용 예) from core.policy_search import search_snippets
    """
    ps = PolicySearch()
    return ps.search_snippets(query, top_k=top_k, **kwargs)
