"""
AI Security Advisor - Claude API integration for natural language synthesis
"""
import json
import anthropic
from knowledge_graph import SecurityKnowledgeGraph


SYSTEM_PROMPT = '''당신은 국가정보원(NIS) AI보안 가이드북에 기반한 AI 보안 어드바이저입니다.

역할:
- 공공기관 담당자가 AI시스템을 안전하게 도입·운영하도록 돕습니다
- 질문에 대해 NIS 가이드북의 보안위협과 보안대책을 근거로 답변합니다
- 답변에는 반드시 관련 위협번호(T01~T15)와 대책번호(M01~M30, A-M, P-M)를 인용합니다

형식:
- 한국어로 답변합니다
- 구체적이고 실무적인 조언을 제공합니다
- 체크리스트 형태로 정리하여 바로 활용할 수 있게 합니다
'''


def build_context(kg: SecurityKnowledgeGraph, query_result: dict) -> str:
    '''Build context string from knowledge graph query result for LLM.'''
    parts = []

    if query_result.get("context"):
        ctx = query_result["context"]
        parts.append(f"[쿼리 컨텍스트] 구축유형: {ctx.get('build_type', '미지정')}, AI유형: {ctx.get('ai_type', '미지정')}, 수명주기: {ctx.get('lifecycle', '미지정')}")

    threats = query_result.get("threats", [])
    if threats:
        parts.append("\n## 관련 보안위협")
        for t in threats:
            parts.append(f"\n### {t['id']} {t['name']}")
            parts.append(f"정의: {t['definition']}")
            parts.append(f"위협: {t['risk']}")
            if t.get("examples"):
                parts.append(f"사례: {'; '.join(t['examples'])}")
            if t.get("lifecycles"):
                parts.append(f"해당 수명주기: {', '.join(t['lifecycles'])}")

    measures = query_result.get("measures", [])
    if measures:
        parts.append("\n## 관련 보안대책")
        for m in measures:
            parts.append(f"\n### {m['id']} {m['name']}")
            parts.append(f"{m['description']}")
            if m.get("details"):
                for d in m["details"]:
                    parts.append(f"  - {d}")
            if m.get("checklist"):
                parts.append(f"체크리스트: {m['checklist']}")

    return "\n".join(parts)


def advise(
    user_query: str,
    kg: SecurityKnowledgeGraph,
    build_type: str | None = None,
    ai_type: str | None = None,
    lifecycle: str | None = None,
    api_key: str | None = None,
) -> str:
    '''
    Given a user query and optional context filters,
    query the knowledge graph and synthesize an answer via Claude.
    '''
    query_result = kg.query_by_context(
        build_type=build_type,
        ai_type=ai_type,
        lifecycle=lifecycle,
    )

    context = build_context(kg, query_result)

    client = anthropic.Anthropic(api_key=api_key)

    user_message = f'''다음은 NIS AI보안 가이드북에서 추출한 관련 보안위협과 보안대책입니다:

{context}

---

사용자 질문: {user_query}

위 자료를 근거로 답변해주세요. 반드시 위협번호(T##)와 대책번호(M##)를 인용하세요.'''

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )

    return response.content[0].text


if __name__ == "__main__":
    import os
    kg = SecurityKnowledgeGraph()
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Set ANTHROPIC_API_KEY environment variable")
        exit(1)

    result = advise(
        user_query="우리 기관에서 생성형 AI 챗봇을 대민서비스로 도입하려고 합니다. 가장 주의해야 할 보안위협과 대책은?",
        kg=kg,
        build_type="대민서비스",
        ai_type="생성형 AI",
        api_key=api_key,
    )
    print(result)
