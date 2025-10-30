# core/suggest_llm.py
from __future__ import annotations
import os, json
from typing import List, Dict, Any, Optional
from openai import AzureOpenAI

from dotenv import load_dotenv
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "config", ".env"))

# search로 키워드 가져와서 사용
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


        #     "2. **Sensitive - WARN** (경고 수준):\n"
        # "   - Names + partial contact info (e.g., '홍길동 010-1234-****')\n"
        # "   - Internal project codenames (if explicitly marked confidential)\n"
        # "   - Pricing information in negotiation context\n\n"
        
        # "3. **Sensitive - BLOCK** (차단 필수):\n"
        # "   - Full SSN/RRN (주민등록번호 13자리)\n"
        # "   - API Keys (especially starting with 'sk-', 'Bearer', etc.)\n"
        # "   - Passwords, access tokens, secrets\n"
        # "   - Full bank account numbers\n"
        # "   - Complete credit card numbers\n\n"

    # system_prompt = (
    #     "You are a corporate security compliance assistant for a Korean enterprise.\n"
    #     "Your role is to identify ONLY truly sensitive information that poses security risks.\n\n"
    #     "답변은 무조건 한국어로 부탁해요.\n\n"

    #     "=== STRICT RULES ===\n"
    #     "1. **NOT Sensitive** (일반적인 사내 커뮤니케이션):\n"
    #     "   - Employee names with job titles (e.g., 'ktds 홍길동 전임', '김과장님')\n"
    #     "   - General greetings and business courtesy phrases\n"
    #     "   - Project names that are already public or internal-only but not confidential\n\n"
        
    #     "=== OUTPUT FORMAT ===\n"
    #     "Return JSON only:\n"
    #     "{\n"
    #     "  \"verdict\": \"allow\" | \"warn\" | \"block\",\n"
    #     "  \"residual_findings\": [{\"value\": string, \"reason\": string, \"suggestion\": string}],\n"
    #     "  \"masking_recommendations\": [{\"before\": string, \"after\": string, \"reason\": string}],\n"
    #     "  \"safe_text\": string,\n"
    #     "  \"rationale\": string,\n"
    #     "  \"policy_citations\": [{\"source\": string, \"page\": number, \"snippet\": string}]\n"
    #     "}\n\n"
        
    #     "=== CRITICAL GUIDELINES ===\n"
    #     "- When in doubt, choose 'allow' over 'warn'\n"
    #     "- Only cite policies (policy_citations) that DIRECTLY support your decision\n"
    #     "- Never duplicate the same source in policy_citations\n"
    #     "- Snippet must be <50 characters and directly relevant\n"
    #     "- Korean workplace culture: mentioning colleague names is normal, not sensitive\n"
    # )

    system_prompt = (
        "You are a corporate security compliance assistant for code security auditing.\n"
        "Your role is to identify security vulnerabilities and hardcoded secrets in source code.\n\n"
        "답변은 무조건 한국어로.\n\n"

        "=== SECURITY CHECKS (무조건 점검) ===\n"
        "1) API Keys & Secrets (CRITICAL)\n"
        "   - 알려진 접두어: 'sk-', 'AKIA', 'ghp_', 'Bearer'\n"
        "   - 데이터베이스 비밀번호, 커넥션 스트링\n"
        "   - JWT 시크릿, 암호화 키\n"
        "   - OAuth 클라이언트 시크릿\n"
        "   - 라벨+값 패턴: key/apikey/api_key/secret/token/access_key/client_secret/jwt_secret 등이\n"
        "     따옴표 등으로 둘러싸인 **하드코딩된 리터럴 값**과 함께 등장하는 경우\n\n"

        "2) Code Vulnerabilities (HIGH)\n"
        "   - SQL Injection: f-string/문자열 결합으로 직접 쿼리 구성\n"
        "   - XSS: 이스케이프 없이 HTML 출력\n"
        "   - Command Injection: os.system(), eval() 등\n"
        "   - Path Traversal: 안전하지 않은 파일 경로 조작\n\n"

        "3) NOT Sensitive (허용/비민감)\n"
        "   - 일반적인 사내 커뮤니케이션(이름/직함/인사말 등)\n"
        "   - 공개/내부일반 수준 프로젝트명\n"
        "   - **변수/함수/환경변수 참조**: os.getenv(\"...\"), config.get(...), settings.SECRET, SecretManager.fetch(...)\n"
        "   - 템플릿/더미/플레이스홀더: \"xxxx\", \"****\", \"<TOKEN>\", \"example\", \"sample\", \"template\"\n"
        "   - IaC/설정의 변수 참조: ${VAR}, ${var.x}, $(ENV_VAR)\n\n"

        "=== 하드코딩 vs 레퍼런스 판정 기준 ===\n"
        "- 하드코딩된 리터럴(차단/경고 대상):\n"
        "  • 따옴표(\"', `\") 또는 원시 문자열 등에 **고정 값**이 직접 들어간 경우\n"
        "  • 주석 안이라도 실제 키/토큰처럼 보이면 동일하게 취급\n"
        "  • 라벨(예: key:, token:, secret:) 바로 뒤에 **길이≥8**이고 영숫자/기호가 섞인 고엔트로피 값\n"
        "  • 알려진 접두어(sk-, AKIA, ghp_, Bearer)로 시작하는 값\n"
        "- 레퍼런스(차단 아님; 필요시 경고만):\n"
        "  • 변수/함수/환경변수 참조(os.getenv, environ[\"...\"], config.get, SecretManager.fetch 등)\n"
        "  • 단, **레퍼런스에 기본값 디폴트가 하드코딩**되어 있으면 그 기본값을 검토:\n"
        "    - 예) os.getenv(\"API_KEY\", \"sk-abcdef...\") → 기본값 리터럴이 있으면 경고/차단\n\n"

        "=== 오탐 방지 규칙 ===\n"
        "- 다음은 **민감정보 아님**:\n"
        "  • key_api(os.getenv(\"key\")), get_token(user_input), function names containing 'key'/'token'\n"
        "  • JSON/YAML 등에서 값이 비어있거나 변수 참조만 있는 경우\n"
        "- 다음은 **주석이라도 민감**:\n"
        "  • 실제 키/토큰으로 보이는 고엔트로피 문자열, 알려진 접두어, 또는 라벨+리터럴 값\n\n"

        "=== 출력 형식(JSON만 반환) ===\n"
        "{\n"
        "  \"verdict\": \"allow\" | \"warn\" | \"block\",\n"
        "  \"residual_findings\": [{\"value\": string, \"reason\": string, \"suggestion\": string}],\n"
        "  \"masking_recommendations\": [{\"before\": string, \"after\": string, \"reason\": string}],\n"
        "  \"safe_text\": string,\n"
        "  \"rationale\": string,\n"
        "  \"policy_citations\": [{\"source\": string, \"page\": number, \"snippet\": string}]\n"
        "}\n"
        "- code block( ``` )으로 감싸지 말고 JSON만 출력.\n"
        "- 'policy_citations'는 실제 참고(RAG)한 문서만 포함.\n\n"

        "=== 판정 가이드라인 ===\n"
        "- 알려진 접두어(sk-, AKIA, ghp_, Bearer) 또는 라벨+리터럴(고엔트로피, 길이≥8)이면 원칙적으로 'block'.\n"
        "- SQL 인젝션 패턴이 명백하면 'block'.\n"
        "- 부분적 개인정보(예: 주민등록번호 일부 패턴)는 'warn' (정책에 따라 상향 가능).\n"
        "- 변수/함수/환경변수 참조는 'allow'; 단, 디폴트에 하드코딩 리터럴이 있으면 'warn'/'block'.\n\n"

        "=== 예시(요약) ===\n"
        "- 차단:\n"
        "  • key: \"sk-abc123...\"        → 라벨+리터럴\n"
        "  • token = \"AKIA....\"         → 알려진 접두어\n"
        "  • os.getenv(\"API_KEY\", \"ghp_xxx\") → 디폴트가 리터럴 키\n"
        "  • # NOTE: Bearer eyJhbGciOi...  → 주석이어도 실제 토큰\n\n"
        "- 허용:\n"
        "  • key_api(os.getenv(\"key\"))\n"
        "  • cfg.api_key = os.getenv(\"API_KEY\")\n"
        "  • token = get_secret(\"PAYMENTS_TOKEN\")\n"
        "  • api_key: ${API_KEY}  # 변수 참조\n"

        "=== add GUIDELINES ===\n"
        "- 정책 문서의 패턴을 **반드시** 모두 검사하세요\n"
        "- 정책 문서에 명시된 내용을 우선적으로 참고하세요\n"
        "- 정책 문서에 없지만 보안 규정 위반이라고 생각한다면 안내 해주고 해당 내용 옆에 # 쓰고 'AI 자체 판단' 이라고 써주세요\n"
        "- policy_citations는 실제로 참고한 정책만 포함\n"
    )

    payload = {
        "locale": locale,
        "text_original": original_text,
    }

    # 필요한 경우에만 정책 스니펫 전달 (5개 이하로 제한)
    if grounds:
        print(" 여기 들어옴???")
        payload["ground_snippets"] = [
            {
                "source": g.get("source"),
                "snippet": g.get("snippet"),
                "title": g.get("title"),
                "content": g.get("content"),
            }
            for g in grounds[:5]
        ]

    # print ("@@@@LLM Payload:", payload)
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
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@    
#extra body 사용
# 장문 사용시 문제 발생 
# 검토
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
def llm_after_mask_rag(original_text: str,
    locale: str = "ko-KR",
    use_rag: bool = True  # RAG 사용 여부
) -> Optional[Dict[str, Any]]:
    
    print("@@@@LLM 호출 준비:")
    
    AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT")
    AZURE_OPENAI_KEY = os.getenv("AZURE_OPENAI_KEY")
    AZURE_OPENAI_API_VERSION = os.getenv("AZURE_OPENAI_API_VERSION")
    AZURE_OPENAI_DEPLOYMENT = os.getenv("AZURE_OPENAI_DEPLOYMENT")
    
    # Azure Search 설정
    AZURE_SEARCH_ENDPOINT = os.getenv("AZURE_SEARCH_ENDPOINT")
    AZURE_SEARCH_KEY = os.getenv("AZURE_SEARCH_KEY")
    AZURE_SEARCH_INDEX_NAME = os.getenv("AZURE_SEARCH_INDEX")
    
    print("client 생성")
    client = AzureOpenAI(
        api_key=AZURE_OPENAI_KEY,
        api_version=AZURE_OPENAI_API_VERSION,
        azure_endpoint=AZURE_OPENAI_ENDPOINT
    )

    system_prompt = (
        "You are a corporate security compliance assistant for code security auditing.\n"
        "Your role is to identify security vulnerabilities and hardcoded secrets in source code.\n\n"
        "답변은 무조건 한국어로.\n\n"

        "=== SECURITY CHECKS (무조건 점검) ===\n"
        "1) API Keys & Secrets (CRITICAL)\n"
        "   - 알려진 접두어: 'sk-', 'AKIA', 'ghp_', 'Bearer'\n"
        "   - 데이터베이스 비밀번호, 커넥션 스트링\n"
        "   - JWT 시크릿, 암호화 키\n"
        "   - OAuth 클라이언트 시크릿\n"
        "   - 라벨+값 패턴: key/apikey/api_key/secret/token/access_key/client_secret/jwt_secret 등이\n"
        "     따옴표 등으로 둘러싸인 **하드코딩된 리터럴 값**과 함께 등장하는 경우\n\n"

        "2) Code Vulnerabilities (HIGH)\n"
        "   - SQL Injection: f-string/문자열 결합으로 직접 쿼리 구성\n"
        "   - XSS: 이스케이프 없이 HTML 출력\n"
        "   - Command Injection: os.system(), eval() 등\n"
        "   - Path Traversal: 안전하지 않은 파일 경로 조작\n\n"

        "3) NOT Sensitive (허용/비민감)\n"
        "   - 일반적인 사내 커뮤니케이션(이름/직함/인사말 등)\n"
        "   - 공개/내부일반 수준 프로젝트명\n"
        "   - **변수/함수/환경변수 참조**: os.getenv(\"...\"), config.get(...), settings.SECRET, SecretManager.fetch(...)\n"
        "   - 템플릿/더미/플레이스홀더: \"xxxx\", \"****\", \"<TOKEN>\", \"example\", \"sample\", \"template\"\n"
        "   - IaC/설정의 변수 참조: ${VAR}, ${var.x}, $(ENV_VAR)\n\n"

        "=== 하드코딩 vs 레퍼런스 판정 기준 ===\n"
        "- 하드코딩된 리터럴(차단/경고 대상):\n"
        "  • 따옴표(\"', `\") 또는 원시 문자열 등에 **고정 값**이 직접 들어간 경우\n"
        "  • 주석 안이라도 실제 키/토큰처럼 보이면 동일하게 취급\n"
        "  • 라벨(예: key:, token:, secret:) 바로 뒤에 **길이≥8**이고 영숫자/기호가 섞인 고엔트로피 값\n"
        "  • 알려진 접두어(sk-, AKIA, ghp_, Bearer)로 시작하는 값\n"
        "- 레퍼런스(차단 아님; 필요시 경고만):\n"
        "  • 변수/함수/환경변수 참조(os.getenv, environ[\"...\"], config.get, SecretManager.fetch 등)\n"
        "  • 단, **레퍼런스에 기본값 디폴트가 하드코딩**되어 있으면 그 기본값을 검토:\n"
        "    - 예) os.getenv(\"API_KEY\", \"sk-abcdef...\") → 기본값 리터럴이 있으면 경고/차단\n\n"

        "=== 오탐 방지 규칙 ===\n"
        "- 다음은 **민감정보 아님**:\n"
        "  • key_api(os.getenv(\"key\")), get_token(user_input), function names containing 'key'/'token'\n"
        "  • JSON/YAML 등에서 값이 비어있거나 변수 참조만 있는 경우\n"
        "- 다음은 **주석이라도 민감**:\n"
        "  • 실제 키/토큰으로 보이는 고엔트로피 문자열, 알려진 접두어, 또는 라벨+리터럴 값\n\n"

        "=== 출력 형식(JSON만 반환) ===\n"
        "{\n"
        "  \"verdict\": \"allow\" | \"warn\" | \"block\",\n"
        "  \"residual_findings\": [{\"value\": string, \"reason\": string, \"suggestion\": string}],\n"
        "  \"masking_recommendations\": [{\"before\": string, \"after\": string, \"reason\": string}],\n"
        "  \"safe_text\": string,\n"
        "  \"rationale\": string,\n"
        "  \"policy_citations\": [{\"source\": string, \"page\": number, \"snippet\": string}]\n"
        "}\n"
        "- code block( ``` )으로 감싸지 말고 JSON만 출력.\n"
        "- 'policy_citations'는 실제 참고(RAG)한 문서만 포함.\n\n"

        "=== 판정 가이드라인 ===\n"
        "- 알려진 접두어(sk-, AKIA, ghp_, Bearer) 또는 라벨+리터럴(고엔트로피, 길이≥8)이면 원칙적으로 'block'.\n"
        "- SQL 인젝션 패턴이 명백하면 'block'.\n"
        "- 부분적 개인정보(예: 주민등록번호 일부 패턴)는 'warn' (정책에 따라 상향 가능).\n"
        "- 변수/함수/환경변수 참조는 'allow'; 단, 디폴트에 하드코딩 리터럴이 있으면 'warn'/'block'.\n\n"

        "=== 예시(요약) ===\n"
        "- 차단:\n"
        "  • key: \"sk-abc123...\"        → 라벨+리터럴\n"
        "  • token = \"AKIA....\"         → 알려진 접두어\n"
        "  • os.getenv(\"API_KEY\", \"ghp_xxx\") → 디폴트가 리터럴 키\n"
        "  • # NOTE: Bearer eyJhbGciOi...  → 주석이어도 실제 토큰\n\n"
        "- 허용:\n"
        "  • key_api(os.getenv(\"key\"))\n"
        "  • cfg.api_key = os.getenv(\"API_KEY\")\n"
        "  • token = get_secret(\"PAYMENTS_TOKEN\")\n"
        "  • api_key: ${API_KEY}  # 변수 참조\n"

        "=== add GUIDELINES ===\n"
        "- 정책 문서의 패턴을 **반드시** 모두 검사하세요\n"
        "- 정책 문서에 명시된 내용을 우선적으로 참고하세요\n"
        "- 정책 문서에 없지만 보안 규정 위반이라고 생각한다면 안내 해주고 해당 내용 옆에 # 쓰고 'AI 자체 판단' 이라고 써주세요\n"
        "- policy_citations는 실제로 참고한 정책만 포함\n"
        )

    user_message = (
        f"다음 내용을 보안 정책 기준으로 검사해주세요:\n\n"
        f"```\n{original_text}\n```\n\n"
        f"정책 문서에 정의된 모든 보안 패턴을 확인하고, 위반 사항이 있으면 상세히 보고해주세요."
    )

    # 메시지 구성
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message}
    ]

    # [수정] gpt-4.1-mini용 출력 토큰 제한(필요 시 600~900 사이로 조정 가능)
    MAX_TOKENS_OUT = 800  # [수정]


    # API 호출 옵션
    api_params = {
        "model": AZURE_OPENAI_DEPLOYMENT,
        "messages": messages,
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
        "max_tokens": MAX_TOKENS_OUT,  # [수정] 출력 토큰 제한 추가
    }

    # RAG 사용 시 extra_body 추가
    if use_rag and AZURE_SEARCH_ENDPOINT and AZURE_SEARCH_KEY and AZURE_SEARCH_INDEX_NAME:
        print("@@@@Azure Search RAG 활성화")
        api_params["extra_body"] = {
            "data_sources": [
                {
                    "type": "azure_search",
                    "parameters": {
                        "endpoint": AZURE_SEARCH_ENDPOINT,
                        "index_name": AZURE_SEARCH_INDEX_NAME,
                        "authentication": {
                            "type": "api_key",
                            "key": AZURE_SEARCH_KEY
                        },
                        "query_type": "simple",
                        "in_scope": True,
                        "top_n_documents": 3,
                        "strictness": 3
                    }
                }
            ]
        }
    else:
        print("@@@@RAG 비활성화 (기본 규칙 사용)")

    # API 호출
    print("@@@@API 호출 시작...")

    # API 호출
    try:
        response = client.chat.completions.create(**api_params)
        
        message = response.choices[0].message
        if not message or not message.content:
            return None
        
        # ✅ markdown code block 제거
        import re
        content = message.content.strip()
        json_match = re.search(r'```(?:json)?\s*\n(.*?)\n```', content, re.DOTALL)
        if json_match:
            content = json_match.group(1)
        
        # JSON 파싱
        result = json.loads(content)
        print("@@@@JSON 파싱 성공")
        
        # ✅ Azure Search의 citations를 grounds 형태로 변환
        if hasattr(message, 'context') and message.context:
            citations = message.context.get('citations', [])
            if citations:
                print(f"@@@@Azure Search 참조 문서: {len(citations)}개")
                
                # grounds 형태로 변환 (UI에서 사용하기 위해)
                grounds = []
                for cite in citations:
                    grounds.append({
                        "source": cite.get('title', 'Unknown'),
                        "title": cite.get('title', 'Unknown'),
                        "snippet": cite.get('content', '')[:500],
                        "content": cite.get('content', ''),
                        "chunk_id": cite.get('chunk_id')
                    })
                
                # ✅ result에 grounds 추가 (UI가 참조할 수 있도록)
                result['_azure_search_grounds'] = grounds
                print(f"@@@@grounds 추가됨: {len(grounds)}개")
        
        return result
        
    except json.JSONDecodeError as je:
        print(f"@@@@JSON 파싱 실패: {je}")
        # print(f"@@@@원본 content: {content[:300]}...")
        return None
    except Exception as e:
        print(f"@@@@오류 발생: {e}")
        return None
    
