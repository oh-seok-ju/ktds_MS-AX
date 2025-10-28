해당 경로에 .env 파일안에 아래 키가 있어야합니다.

# -------------------------------
# [RULES용 Azure Blob Storage 설정]
# -------------------------------

AZURE_STORAGE_ACCOUNT_NAME=" "
AZURE_STORAGE_ACCOUNT_KEY=" "
AZURE_BLOB_ACCOUNT_URL="https://????.blob.core.windows.net"
AZURE_BLOB_CONTAINER=" "
RULES_BASE_PATH="rules/"   # rules 디렉토리 Prefix (기본값이라 생략 가능)


# -------------------------------
# [Azure OpenAI 설정 - 2차 LLM 검사]
# -------------------------------
# (없으면 suggest_llm.py는 자동 우회함)
AZURE_OPENAI_ENDPOINT="https://<YOUR_OPENAI_RESOURCE>.openai.azure.com"
AZURE_OPENAI_KEY=""
AZURE_OPENAI_DEPLOYMENT="gpt-4o-mini"   # 또는 gpt-4o, gpt-35-turbo 등
AZURE_OPENAI_API_VERSION="2024-02-15-preview"

# -------------------------------
# [Azure AI Search (정책 근거 RAG)]
# -------------------------------
# (없으면 policy_search 호출은 자동 우회함)
AZURE_SEARCH_ENDPOINT="https://<YOUR_SEARCH_SERVICE>.search.windows.net"
AZURE_SEARCH_KEY=""
AZURE_SEARCH_INDEX="policy-index"  # 인덱스명
