# core/detector.py
from __future__ import annotations
import re
from typing import Dict, Any, List
from typing import Tuple, Set

# --- 내부 유틸 ---
def _compile(pattern: str) -> re.Pattern:
    # NOTE: YAML에서 (?i) 같은 inline flag를 쓰면 re가 처리합니다.
    return re.compile(pattern)

def _apply_template(val: str, tmpl: str, groups: Dict[str, str]) -> str:
    out = tmpl
    for k, v in (groups or {}).items():
        out = out.replace(f"{{{{{k}}}}}", v)
    return out

def _groups_for(cat_id: str, value: str, m: re.Match) -> Dict[str, str]:
    g: Dict[str, str] = {"last4": value[-4:]}
    if cat_id == "pii.identity.rrn":
        # rrn 정규식이 (yy)(mm)(dd) 그룹을 가진다고 가정
        try:
            g.update({"yy": m.group(1), "mm": m.group(2), "dd": m.group(3)})
        except Exception:
            pass
    if cat_id == "pii.email":
        if "@" in value:
            try:
                user, domain = value.split("@", 1)
                # 해시는 LLM 없이 간단 치환: UI에서 해시 원하면 별도 처리
                g.update({"user_hash": "******", "domain": domain})
            except Exception:
                pass
    if cat_id == "network.ip":
        parts = value.split(".")
        if len(parts) == 4:
            g.update({"oct1": parts[0], "oct2": parts[1]})
    return g

# --- 공개 API ---
def detect(text: str, rules: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    rules(dict) 기반으로 키워드/정규식 탐지 결과를 반환
    hit: {id, type(keyword|regex), value, severity, action[], pattern_id?, groups?}
    """
    hits: List[Dict[str, Any]] = []
    cats = rules.get("categories", []) or []

    for cat in cats:
        cat_id = cat.get("id")
        severity = cat.get("severity", "low")
        action = cat.get("action", [])

        # 1) 키워드 (denylist_kr/en)
        kws = (cat.get("keywords") or {})
        for kw in (kws.get("denylist_kr") or []):
            if kw and kw in text:
                hits.append({
                    "id": cat_id, "type": "keyword", "value": kw,
                    "severity": severity, "action": action
                })
        for kw in (kws.get("denylist_en") or []):
            if kw and kw.lower() in text.lower():
                hits.append({
                    "id": cat_id, "type": "keyword", "value": kw,
                    "severity": severity, "action": action
                })

        # 2) 정규식
        for p in (cat.get("patterns") or []):
            if p.get("type") != "regex":
                continue
            pat = p.get("pattern")
            if not pat:
                continue
            try:
                rx = _compile(pat)
                for m in rx.finditer(text):
                    val = m.group(0)
                    groups = _groups_for(cat_id, val, m)
                    hits.append({
                        "id": cat_id, "type": "regex", "pattern_id": p.get("id"),
                        "value": val, "severity": severity, "action": action,
                        "groups": groups
                    })
            except re.error:
                # 잘못된 정규식은 스킵 (운영 시 로그 권장)
                continue

    return hits

def score(hits: List[Dict[str, Any]], rules: Dict[str, Any]) -> int:
    w = (rules.get("scoring") or {}).get("weights", {})
    return sum(w.get(h.get("severity", "low"), 0) for h in hits)

## 마스크 부분
def mask_text(text: str, hit: Dict[str, Any], rules: Dict[str, Any]) -> str:
    """
    해당 hit의 value를 rules의 mask.template로 치환
    """
    template = None
    for c in rules.get("categories", []):
        if c.get("id") == hit.get("id"):
            template = (c.get("mask") or {}).get("template")
            break
    if not template:
        return text
    masked = _apply_template(hit["value"], template, hit.get("groups") or {})
    return text.replace(hit["value"], masked)

# def auto_mask(text: str, hits: List[Dict[str, Any]], rules: Dict[str, Any]) -> str:
#     """
#     mask 또는 block 액션이 있는 항목만 템플릿 적용
#     긴 값부터 치환하여 중첩 교란 최소화
#     """
#     out = text
#     # 길이 내림차순
#     for h in sorted(hits, key=lambda x: len(x.get("value", "")), reverse=True):
#         actions = h.get("action") or []
#         if any(a in ("mask", "block") for a in actions):
#             out = mask_text(out, h, rules)
#     return out

## 비 마스크 부분
def mask_value(value: str, hit: Dict[str, Any], rules: Dict[str, Any]) -> str:
    """
    단일 값(value)에 대해 해당 hit의 마스킹 템플릿을 적용한 결과를 반환.
    auto_mask를 value 범위(0..len)로 한정해 재사용.
    """
    if not value:
        return value
    h2 = dict(hit)
    h2["span"] = [0, len(value)]
    return auto_mask(value, [h2], rules)

def auto_mask_pairs(text: str, hits: List[Dict[str, Any]], rules: Dict[str, Any]) -> List[Tuple[str, str]]:
    """
    mask 대상 hit들만 받아, (before, after) 쌍 리스트를 만든다.
    - hit.value가 없으면 span으로 원문에서 추출 시도
    - (value, id, pattern_id) 중복은 1회만 포함
    """
    pairs: List[Tuple[str, str]] = []
    seen: Set[Tuple[str, Any, Any]] = set()

    # mask 액션만 대상으로
    maskables = []
    for h in hits:
        acts = set((h.get("action") or []))
        if "mask" in acts or "block" in acts:
            maskables.append(h)

    for h in maskables:
        v = h.get("value")
        if not v:
            span = h.get("span")
            if isinstance(span, (list, tuple)) and len(span) == 2 and all(isinstance(x, int) for x in span):
                v = text[span[0]:span[1]]
        if not v:
            continue

        key = (v, h.get("id"), h.get("pattern_id"))
        if key in seen:
            continue
        seen.add(key)

        after = mask_value(v, h, rules)
        if after != v:  # 실제 변화가 있을 때만
            pairs.append((v, after))

    return pairs

## llm 결과 정규화
# def ai_mask_pairs(llm_result: Dict[str, Any]) -> list[tuple[str, str]]:
#     items = llm_result.get("masking_recommendations") or []
#     pairs: List[Tuple[str, str]] = []
#     for x in items:
#         if isinstance(x, dict):
#             b = x.get("before") or x.get("value") or x.get("text")
#             a = x.get("after")  or x.get("masked") or x.get("suggested")
#             if b and a:
#                 pairs.append((b, a))
#     return pairs

def ai_warn_items(llm_result: Dict[str, Any]) -> list[tuple[str, str]]:
    items = llm_result.get("residual_findings") or []
    out: List[Tuple[str, str]] = []
    for x in items:
        if isinstance(x, dict):
            v = x.get("value") or x.get("text")
            s = x.get("suggestion") or x.get("suggestion_kr") or x.get("suggestion_en") or "⚠️ 삭제 권장"
        else:
            v = str(x); s = "⚠️ 삭제 권장"
        if v:
            out.append((v, s))
    return out
