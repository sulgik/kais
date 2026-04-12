"""
KAIS MCP Server — NIS AI보안 가이드북 지식그래프를 MCP 프로토콜로 제공
"""
import json
from mcp.server.fastmcp import FastMCP
from knowledge_graph import SecurityKnowledgeGraph

mcp = FastMCP(
    "kais",
    instructions=(
        "KAIS는 국가정보원(NIS) AI보안 가이드북(2025.12) 기반 지식그래프입니다. "
        "공공기관 AI시스템 도입·운영 시 보안위협(T01~T15)과 보안대책(M01~M30, A-M, P-M)을 조회할 수 있습니다. "
        "MITRE ATLAS(AI 보안 프레임워크)와 OWASP LLM Top 10과의 교차 매핑도 제공합니다. "
        "답변 시 위협번호(T##), 대책번호(M##), ATLAS 기법(AML.T####)을 인용하세요."
    ),
)

kg = SecurityKnowledgeGraph()


# --- Tools ---

@mcp.tool()
def query_by_context(
    build_type: str | None = None,
    ai_type: str | None = None,
    lifecycle: str | None = None,
) -> dict:
    """구축유형·AI유형·수명주기 기반으로 관련 보안위협과 대책을 조회합니다.

    Args:
        build_type: 구축 유형 (내부망 전용 | 외부망 연계 | 대민서비스 | 상용 AI서비스)
        ai_type: AI 유형 (생성형 AI | 에이전틱 AI | 피지컬 AI)
        lifecycle: 수명주기 (데이터 수집 | AI 학습 | AI시스템 구축 | AI시스템 운영 | AI시스템 폐기)
    """
    return kg.query_by_context(
        build_type=build_type,
        ai_type=ai_type,
        lifecycle=lifecycle,
    )


@mcp.tool()
def get_threat(threat_id: str) -> dict:
    """위협 ID(T01~T15)로 보안위협 상세 정보를 조회합니다.

    Args:
        threat_id: 위협 ID (예: T01, T15)
    """
    t = kg.get_threat(threat_id)
    if not t:
        return {"error": f"위협 '{threat_id}'을(를) 찾을 수 없습니다."}
    measures = kg.get_measures_for_threat(threat_id)
    owasp = kg.get_owasp_for_threat(threat_id)
    return {
        **t,
        "related_measures": [{"id": m["id"], "name": m["name"]} for m in measures],
        "related_owasp": [{"id": o["id"], "name": o["name"]} for o in owasp],
    }


@mcp.tool()
def get_measure(measure_id: str) -> dict:
    """대책 ID(M01~M30, A-M01~, P-M01~)로 보안대책 상세 정보를 조회합니다.

    Args:
        measure_id: 대책 ID (예: M01, A-M03, P-M05)
    """
    m = kg.get_measure(measure_id)
    if not m:
        return {"error": f"대책 '{measure_id}'을(를) 찾을 수 없습니다."}
    threats = kg.get_threats_for_measure(measure_id)
    return {
        **m,
        "related_threats": [{"id": t["id"], "name": t["name"]} for t in threats],
    }


@mcp.tool()
def search_threats(keyword: str) -> list[dict]:
    """키워드로 보안위협을 검색합니다. 이름, 정의, 위협 설명, 사례에서 검색합니다.

    Args:
        keyword: 검색어 (예: 데이터, 프롬프트, 모델)
    """
    keyword_lower = keyword.lower()
    results = []
    for t in kg.threats:
        searchable = " ".join([
            t["name"], t["definition"], t["risk"],
            *t.get("examples", []),
        ]).lower()
        if keyword_lower in searchable:
            results.append({"id": t["id"], "name": t["name"], "definition": t["definition"]})
    return results


@mcp.tool()
def search_measures(keyword: str) -> list[dict]:
    """키워드로 보안대책을 검색합니다. 이름, 설명, 세부항목, 체크리스트에서 검색합니다.

    Args:
        keyword: 검색어 (예: 암호화, 접근통제, 로깅)
    """
    keyword_lower = keyword.lower()
    results = []
    for m in kg.measures:
        searchable = " ".join([
            m["name"], m["description"],
            *m.get("details", []),
            m.get("checklist", ""),
        ]).lower()
        if keyword_lower in searchable:
            results.append({"id": m["id"], "name": m["name"], "description": m["description"]})
    return results


@mcp.tool()
def list_incidents() -> list[dict]:
    """NIS AI보안 가이드북에 수록된 AI 보안 사고 사례를 조회합니다."""
    return kg.incidents


@mcp.tool()
def get_owasp_mapping(owasp_id: str) -> dict:
    """OWASP LLM Top 10 항목과 NIS 가이드북 위협·대책의 매핑을 조회합니다.

    Args:
        owasp_id: OWASP ID (예: LLM01, LLM10)
    """
    owasp = kg.get_owasp(owasp_id)
    if not owasp:
        return {"error": f"OWASP '{owasp_id}'을(를) 찾을 수 없습니다."}
    nis = kg.get_nis_for_owasp(owasp_id)
    return {
        "owasp": owasp,
        "nis_threats": nis["threats"],
        "nis_measures": nis["measures"],
    }


@mcp.tool()
def summary() -> dict:
    """지식그래프 전체 통계를 반환합니다."""
    return kg.summary()


# --- ATLAS Tools ---

@mcp.tool()
def get_atlas_technique(technique_id: str) -> dict:
    """MITRE ATLAS 기법 상세 정보 및 NIS/OWASP 매핑을 조회합니다.

    Args:
        technique_id: ATLAS 기법 ID (예: AML.T0051, AML.T0020)
    """
    tech = kg.get_atlas_technique(technique_id)
    if not tech:
        return {"error": f"ATLAS 기법 '{technique_id}'을(를) 찾을 수 없습니다."}
    mapping = kg.get_atlas_mapping(technique_id) or {}
    threats = kg.get_threats_for_atlas(technique_id)
    return {
        **tech,
        "nis_threats": [{"id": t["id"], "name": t["name"]} for t in threats],
        "nis_measures": mapping.get("measure_ids", []),
        "owasp_ids": mapping.get("owasp_ids", []),
        "confidence": mapping.get("confidence", ""),
        "rationale": mapping.get("rationale", ""),
    }


@mcp.tool()
def search_atlas(keyword: str) -> list[dict]:
    """키워드로 MITRE ATLAS 기법을 검색합니다.

    Args:
        keyword: 검색어 (예: prompt injection, 학습데이터, backdoor)
    """
    results = kg.search_atlas(keyword)
    return [{"id": t["id"], "name": t["name"], "name_ko": t["name_ko"]} for t in results]


@mcp.tool()
def get_cross_framework_mapping(item_id: str) -> dict:
    """NIS/ATLAS/OWASP 중 하나의 ID로 세 프레임워크의 교차 매핑을 조회합니다.

    Args:
        item_id: 항목 ID (예: T08, AML.T0051, LLM01)
    """
    result = kg.get_cross_framework(item_id)
    if not result["framework"]:
        return {"error": f"'{item_id}'을(를) 어떤 프레임워크에서도 찾을 수 없습니다."}
    return {
        "id": result["id"],
        "framework": result["framework"],
        "item": result["item"],
        "nis_threats": [{"id": t["id"], "name": t["name"]} for t in result.get("nis_threats", [])],
        "nis_measures": [{"id": m["id"], "name": m["name"]} for m in result.get("nis_measures", [])],
        "owasp": [{"id": o["id"], "name": o.get("name", "")} for o in result.get("owasp", [])],
        "atlas": [{"id": a["id"], "name": a["name"], "name_ko": a["name_ko"]} for a in result.get("atlas", [])],
    }


# --- Resources ---

@mcp.resource("kais://threats")
def all_threats() -> str:
    """전체 보안위협 목록 (T01~T15)"""
    return json.dumps(kg.threats, ensure_ascii=False, indent=2)


@mcp.resource("kais://measures")
def all_measures() -> str:
    """전체 보안대책 목록 (M01~M30, A-M, P-M)"""
    return json.dumps(kg.measures, ensure_ascii=False, indent=2)


@mcp.resource("kais://incidents")
def all_incidents() -> str:
    """AI 보안 사고 사례"""
    return json.dumps(kg.incidents, ensure_ascii=False, indent=2)


@mcp.resource("kais://owasp")
def all_owasp() -> str:
    """OWASP LLM Top 10 + NIS 매핑"""
    return json.dumps(kg.owasp, ensure_ascii=False, indent=2)


@mcp.resource("kais://atlas")
def all_atlas() -> str:
    """MITRE ATLAS 전술·기법 전체 데이터"""
    return json.dumps({
        "tactics": kg.atlas_tactics,
        "techniques": kg.atlas_techniques,
        "mitigations": kg.atlas_mitigations,
    }, ensure_ascii=False, indent=2)


@mcp.resource("kais://trinity-mapping")
def trinity_mapping() -> str:
    """NIS-ATLAS-OWASP 3자 교차매핑"""
    return json.dumps(kg._atlas_mapping, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    mcp.run()
