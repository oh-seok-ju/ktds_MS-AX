# core/loader.py
from __future__ import annotations

import os
import io
import csv
import json
from typing import Dict, Any, List, Optional

import yaml
from azure.storage.blob import BlobServiceClient
from azure.core.credentials import AzureNamedKeyCredential

from dotenv import load_dotenv
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "config", ".env"))



try:
    from azure.identity import DefaultAzureCredential  # type: ignore
    HAS_AZURE_IDENTITY = True
except Exception:
    HAS_AZURE_IDENTITY = False


class RulesLoader:
    """
    Azure Blob Storage에 저장된 rules 디렉터리를 읽어
    단일 ruleset(dict)으로 병합하는 간단한 로더 (MVP 용).

    기대 Blob 경로 구조 (prefix=base_path, 기본값 'rules/'):
      rules/
        version.json
        scoring.json
        masks.yml
        categories/*.yml
        keywords/*.csv    # 선택
        patterns/*        # 선택(이번 버전 미사용)

    반환 형태:
    {
      "version": "1.0.0",
      "locale": ["ko-KR","en-US"],
      "categories": [...],      # 각 카테고리 YAML 병합 결과
      "scoring": {...},         # scoring.json
      "_etag_map": {...}        # 파일별 ETag(옵션, 캐시/디버그용)
    }
    """


    def __init__(
        self,
        account_url: Optional[str] = None,
        container: Optional[str] = None,
        base_path: str = "rules/",
    ):
        
        self.base_path = base_path.rstrip("/") + "/"

        # 컨테이너 이름
        self.container = container or os.getenv("AZURE_BLOB_CONTAINER", "secureassist")

        # --- ✅ 핵심: Account Name + Key 인증 전용 ---
        acct_name = os.getenv("AZURE_STORAGE_ACCOUNT_NAME")
        acct_key  = os.getenv("AZURE_STORAGE_ACCOUNT_KEY")

        if not (acct_name and acct_key):
            raise RuntimeError("Azure에 연결할 수 있는 환경변수가 필요합니다.")

        # Account URL 자동 구성 (직접 override 가능)
        account_url = account_url or f"https://{acct_name}.blob.core.windows.net"

        # 인증정보 객체
        cred = AzureNamedKeyCredential(acct_name, acct_key)

        # ✅ BlobServiceClient 생성
        self._bsc = BlobServiceClient(account_url=account_url, credential=cred)
        self._cc = self._bsc.get_container_client(self.container)

    # ------------------------------
    # 내부 유틸
    # (1) app.py 실행 → loader.py가 Azure Blob에서 "룰셋" 불러오기
    # (2) 룰셋이 메모리에 로드됨
    # (3) 사용자가 text_area에 입력
    # (4) detect()가 그 룰셋을 기준으로 사용자 입력을 검사
    # ------------------------------
    # Blob에 올라가 있는 특정 파일 1개를 불러서 문자열로 읽어옵니다.
    def _read_text(self, blob_name: str) -> str:
        bc = self._cc.get_blob_client(blob_name)
        return bc.download_blob().readall().decode("utf-8")

    # 해당 Blob 파일의 ETag(파일 변경판 ID)를 얻습니다.
    def _get_etag(self, blob_name: str) -> Optional[str]:
        try:
            bc = self._cc.get_blob_client(blob_name)
            return bc.get_blob_properties().etag
        except Exception:
            return None
    # 해당 경로(prefix)에 있는 Blob 파일 목록을 얻습니다.
    def _list(self, prefix: str) -> List[str]:
        return [b.name for b in self._cc.list_blobs(name_starts_with=prefix)]

    # ------------------------------
    # 공개 API
    # ------------------------------
    def load(self) -> Dict[str, Any]:
        etags: Dict[str, Optional[str]] = {}
        bp = self.base_path

        # 1) version.json (필수)
        version_path = f"{bp}version.json"
        version = json.loads(self._read_text(version_path))
        etags[version_path] = self._get_etag(version_path)

        # 2) scoring.json (필수)
        scoring_path = f"{bp}scoring.json"
        scoring = json.loads(self._read_text(scoring_path))
        etags[scoring_path] = self._get_etag(scoring_path)

        # 3) masks.yml (필수)
        masks_path = f"{bp}masks.yml"
        masks = yaml.safe_load(self._read_text(masks_path)) or {}
        mask_templates = (masks.get("templates") or {}) if isinstance(masks, dict) else {}
        etags[masks_path] = self._get_etag(masks_path)

        # 4) categories/*.yml (필수: 하나 이상)
        categories: List[Dict[str, Any]] = []
        cat_prefix = f"{bp}categories/"
        cat_files = [n for n in self._list(cat_prefix) if n.endswith((".yml", ".yaml"))]
        if not cat_files:
            raise RuntimeError(f"카테고리 파일이 없습니다: {cat_prefix}")

        for name in sorted(cat_files):
            data = yaml.safe_load(self._read_text(name)) or {}
            # mask_ref → 실제 템플릿 주입
            mask_ref = data.get("mask_ref")
            if mask_ref and mask_ref in mask_templates:
                data["mask"] = {"strategy": "template", "template": mask_templates[mask_ref]}
            etags[name] = self._get_etag(name)
            categories.append(data)

        # 5) keywords/*.csv (선택) → 예시: confidential.internal_terms에 병합
        kw_prefix = f"{bp}keywords/"
        kw_files = [n for n in self._list(kw_prefix) if n.endswith(".csv")]
        kw_ko: Dict[str, List[str]] = {}
        kw_en: Dict[str, List[str]] = {}

        for name in sorted(kw_files):
            text = self._read_text(name)
            etags[name] = self._get_etag(name)
            rows = list(csv.DictReader(io.StringIO(text)))
            # 파일명으로 언어 추정 (.ko., .en.)
            lang = "ko" if ".ko." in name else ("en" if ".en." in name else "ko")
            dest = kw_ko if lang == "ko" else kw_en
            # 간단: confidential.internal_terms에만 합치는 MVP (필요시 매핑 정책 확장)
            dest.setdefault("confidential.internal_terms", []).extend([r["keyword"] for r in rows if "keyword" in r])

        for c in categories:
            if c.get("id") == "confidential.internal_terms":
                ks = c.setdefault("keywords", {})
                if kw_ko.get(c["id"]):
                    ks["denylist_kr"] = sorted(set((ks.get("denylist_kr") or []) + kw_ko[c["id"]]))
                if kw_en.get(c["id"]):
                    ks["denylist_en"] = sorted(set((ks.get("denylist_en") or []) + kw_en[c["id"]]))

        # 최종 ruleset
        rules: Dict[str, Any] = {
            "version": version.get("rules_version", "0"),
            "locale": version.get("locale", ["ko-KR", "en-US"]),
            "categories": categories,
            "scoring": scoring,
            "_etag_map": etags,  # 캐시/디버그용 (원치 않으면 제거해도 됨)
        }
        return rules


# ------------------------------
# 모듈 레벨 헬퍼 (Streamlit에서 바로 쓰기 편하게)
# ------------------------------
def load_rules_from_blob(
    account_url: Optional[str] = None,
    container: Optional[str] = None,
    base_path: str = None,

) -> Dict[str, Any]:
    """
    간단 헬퍼: 환경변수와 인자를 조합해 RulesLoader로 로드.
    """
    loader = RulesLoader(
        account_url=account_url,
        container=container,
        base_path=base_path or os.getenv("RULES_BASE_PATH", "rules/"),
    )
    return loader.load()