# core/policy_search.py
from __future__ import annotations

import os
from typing import List, Dict, Any, Optional

from azure.core.credentials import AzureKeyCredential
from azure.search.documents import SearchClient
from azure.search.documents.models import QueryType

# .env 로딩
from dotenv import load_dotenv
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "config", ".env"))

class PolicySearch:
    """Azure Cognitive Search에서 정책 근거 스니펫을 조회하는 경량 헬퍼."""

    def __init__(
        self,
        endpoint: Optional[str] = None,
        key: Optional[str] = None,
        index_name: Optional[str] = None,
        semantic_config: Optional[str] = None,
        search_fields: Optional[List[str]] = None,
        fixed_filter: Optional[str] = None,
    ) -> None:
        # 환경변수에서 직접 가져오기 (간단하게)
        endpoint = endpoint or os.getenv("AZURE_SEARCH_ENDPOINT")
        key = key or os.getenv("AZURE_SEARCH_KEY")
        index_name = index_name or os.getenv("AZURE_SEARCH_INDEX")

        if not endpoint or not key or not index_name:
            raise RuntimeError("Azure Search 환경변수(AZURE_SEARCH_ENDPOINT/KEY/INDEX)가 필요합니다.")

        self.semantic_config = semantic_config or os.getenv("AZURE_SEARCH_SEMANTIC_CONFIG")
        self.fixed_filter = fixed_filter or os.getenv("AZURE_SEARCH_FILTER")
        
        fields = search_fields or os.getenv("AZURE_SEARCH_SEARCH_FIELDS", "content,title")
        self.search_fields = fields.split(",") if isinstance(fields, str) else fields

        self.client = SearchClient(
            endpoint=endpoint, 
            index_name=index_name, 
            credential=AzureKeyCredential(key)
        )

    def search_snippets(
        self,
        query: str,
        top_k: int = 3,
        *,
        filter_expr: Optional[str] = None,
        use_semantic_if_available: bool = True,
        highlight: bool = True,
    ) -> List[Dict[str, Any]]:
        if not query or not query.strip():
            return []

        search_kwargs: Dict[str, Any] = {
            "top": top_k,
            "search_fields": self.search_fields,
        }

        # 필터
        filt = self.fixed_filter
        if filter_expr:
            filt = f"({filt}) and ({filter_expr})" if filt else filter_expr
        if filt:
            search_kwargs["filter"] = filt

        # 세맨틱 검색
        if use_semantic_if_available and self.semantic_config:
            search_kwargs["query_type"] = QueryType.SEMANTIC
            search_kwargs["semantic_configuration_name"] = self.semantic_config
            search_kwargs["query_caption"] = "extractive"  # ← 문자열로 전달
        else:
            # 일반 검색
            if highlight:
                search_kwargs["highlight_fields"] = "content"
                search_kwargs["highlight_pre_tag"] = "<em>"
                search_kwargs["highlight_post_tag"] = "</em>"

        results: List[Dict[str, Any]] = []
        try:
            resp = self.client.search(query, **search_kwargs)
            for doc in resp:
                results.append(self._to_snippet(doc, highlight=highlight))
        except Exception as e:
            print(f"[ERROR] Azure Search 실패: {e}")
            return [{"error": f"Azure Search 검색 실패: {e}"}]

        return results

    def _to_snippet(self, doc: Any, highlight: bool = True) -> Dict[str, Any]:
        """SDK SearchResult -> dict 변환"""
        getter = doc.get if hasattr(doc, "get") else lambda k, default=None: getattr(doc, k, default)

        source = getter("source") or getter("title") or "정책문서"
        title = getter("title") or source
        page = getter("page") or 1
        content = getter("content")
        doc_id = getter("id")
        score = getattr(doc, "@search.score", None)

        # Caption 우선 (세맨틱 검색)
        snippet = None
        
        captions = getattr(doc, "@search.captions", None)
        if captions and isinstance(captions, list) and len(captions) > 0:
            cap = captions[0]
            if isinstance(cap, dict):
                snippet = cap.get("highlights") or cap.get("text", "")
            print(f"[DEBUG] Caption 사용: {snippet[:100] if snippet else 'N/A'}")
        
        # Highlight (일반 검색)
        if not snippet and highlight:
            highlights = getattr(doc, "@search.highlights", None)
            if isinstance(highlights, dict):
                content_hl = highlights.get("content", [])
                if content_hl:
                    snippet = " … ".join(content_hl[:2])
                    print(f"[DEBUG] Highlight 사용: {snippet[:100]}")
        
        # Content fallback
        if not snippet and content:
            snippet = (content[:150] + "…") if len(content) > 150 else content
            print(f"[DEBUG] Content fallback 사용")

        return {
            "id": doc_id,
            "title": title,
            "snippet": snippet or "",
            "score": float(score) if score is not None else None,
            "version": getter("version"),
            "source": source,
            "page": page,
            "chunk_id": getter("chunk_id"),
            "content": content,
        }


def search_snippets(query: str, top_k: int = 3, **kwargs) -> List[Dict[str, Any]]:
    """환경변수 기반 간단 헬퍼"""
    ps = PolicySearch()
    return ps.search_snippets(query, top_k=top_k, **kwargs)