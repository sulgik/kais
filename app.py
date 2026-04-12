"""
KAIS - K-AI Security Advisor
Streamlit Web UI
"""
import json
import re
from datetime import datetime
from pathlib import Path
import streamlit as st
from knowledge_graph import SecurityKnowledgeGraph

KAIS_VERSION = "0.1.0"
KAIS_DATA_SOURCE = "NIS AI보안 가이드북 (2025.12)"

st.set_page_config(
    page_title="KAIS - 국가·공공기관 AI보안 어드바이저",
    page_icon="🛡️",
    layout="wide",
)

# --- Init ---
@st.cache_resource
def load_kg():
    return SecurityKnowledgeGraph()

def load_image_index():
    index_path = Path(__file__).parent / "data" / "images" / "index.json"
    if index_path.exists():
        return json.loads(index_path.read_text(encoding="utf-8"))
    return {}

kg = load_kg()
image_index = load_image_index()
IMAGE_DIR = Path(__file__).parent / "data" / "images"

# Load incidents directly (not via cached kg to avoid stale cache issues)
_incidents_path = Path(__file__).parent / "data" / "incidents.json"
incidents = json.loads(_incidents_path.read_text(encoding="utf-8")) if _incidents_path.exists() else []

# Load OWASP data directly
_owasp_path = Path(__file__).parent / "data" / "owasp_llm.json"
owasp_items = json.loads(_owasp_path.read_text(encoding="utf-8")) if _owasp_path.exists() else []
_owasp_map_path = Path(__file__).parent / "data" / "owasp_nis_mapping.json"
owasp_mapping = json.loads(_owasp_map_path.read_text(encoding="utf-8")) if _owasp_map_path.exists() else []
owasp_map_by_id = {m["owasp_id"]: m for m in owasp_mapping}


# --- Badge helpers ---
def _t_badge(tid: str) -> str:
    return f'<span style="background:#ed1c24;color:#fff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:0.85em;white-space:nowrap;">{tid}</span>'

def _m_badge(mid: str) -> str:
    return f'<span style="background:#2f55a5;color:#fff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:0.85em;white-space:nowrap;">{mid}</span>'

def _owasp_badge(oid: str) -> str:
    return f'<span style="background:#f58220;color:#fff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:0.85em;white-space:nowrap;">{oid}</span>'

_BADGE_PATTERN = re.compile(r'\b(LLM\d{2}|T\d{2}|M\d{2}|A-M\d{2}|P-M\d{2})\b')

def badged(text: str) -> str:
    '''Replace all LLM##, T##, M##, A-M##, P-M## in text with colored HTML badges.'''
    def _repl(m):
        token = m.group(1)
        if token.startswith("T"):
            return _t_badge(token)
        if token.startswith("LLM"):
            return _owasp_badge(token)
        return _m_badge(token)
    return _BADGE_PATTERN.sub(_repl, text)

def bmd(text: str):
    '''st.markdown with badge support.'''
    st.markdown(badged(text), unsafe_allow_html=True)


def show_threat_image(threat_id: str):
    if threat_id in image_index:
        img_path = IMAGE_DIR / image_index[threat_id]
        if img_path.exists():
            st.image(str(img_path), use_container_width=True)


# --- Sidebar ---
with st.sidebar:
    st.title("⚙️ 설정")

    stats = kg.summary()
    st.caption(f"📊 지식 그래프: {stats['total_threats']}개 위협 · {stats['total_measures']}개 대책 · {stats['total_links']}개 연결")

    st.divider()
    st.markdown("📄 **관련 문서**")
    st.markdown("- [NIS AI보안 가이드북 (2025.12)](https://www.nis.go.kr)")
    st.markdown("- [OWASP Top 10 for LLM](https://genai.owasp.org/)")
    st.markdown("- [NIST AI RMF](https://www.nist.gov/artificial-intelligence)")
    st.markdown("- [MITRE ATLAS](https://atlas.mitre.org/)")

    st.divider()
    st.caption("Made by [sulgik@gmail.com](mailto:sulgik@gmail.com)")


# --- Main area ---
st.markdown("""
<div style="padding: 8px 0 4px 0;">
  <div style="font-size:2rem; font-weight:800; letter-spacing:-1px; color:#1a1a2e; line-height:1.1;">
    국가·공공기관 AI보안 어드바이저
  </div>
  <div style="font-size:1.25rem; font-weight:400; color:#2f55a5; letter-spacing:1px; margin-top:4px;">
    KAIS &mdash; K-AI Security Advisor
  </div>
  <div style="font-size:0.85rem; color:#888; margin-top:6px;">
    NIS AI보안 가이드북(2025.12) 기반 &nbsp;·&nbsp; 안전한 AI시스템 도입·활용을 위한 보안 안내 시스템
  </div>
</div>
""", unsafe_allow_html=True)

st.warning(
    "**⚠️ 실험적 서비스 (Experimental)** — 연구·교육 목적의 비공식 서비스이며 국가정보원(NIS)과 무관합니다. "
    "NIS AI보안 가이드북(2025.12) 기반으로 생성되며 공식 보안 검토를 대체하지 않습니다.",
    icon="⚠️",
)

# --- Tabs ---
tab_home, tab_explorer, tab_owasp, tab_incidents, tab_checklist, tab_mcp = st.tabs(
    ["홈", "🔍 지식 탐색", "🌐 OWASP LLM Top 10", "🔥 사고 사례", "✅ 체크리스트", "🔌 MCP 연결"]
)

# --- Tab 0: Home ---
with tab_home:
    stats = kg.summary()

    # 소개 헤더
    st.markdown("""
<div style="background:linear-gradient(135deg,#1a1a2e 0%,#2f55a5 100%);
            border-radius:12px; padding:32px 36px; color:#fff; margin-bottom:24px;">
  <div style="font-size:1.5rem; font-weight:700; margin-bottom:8px;">
    국가·공공기관을 위한 AI보안 지식 플랫폼
  </div>
  <div style="font-size:0.95rem; opacity:0.88; line-height:1.8;">
    국가정보원(NIS) AI보안 가이드북을 기반으로 보안위협·대책·사고사례를 체계화한 지식그래프입니다.<br>
    OWASP LLM Top 10, NIST AI RMF, MITRE ATLAS 등 국제 기준과 교차 매핑하여 실무에 바로 활용할 수 있습니다.
  </div>
</div>
""", unsafe_allow_html=True)

    # 통계 카드
    c1, c2, c3, c4 = st.columns(4)
    for col, label, value, color in [
        (c1, "보안위협", f"{stats['total_threats']}개", "#ed1c24"),
        (c2, "보안대책", f"{stats['total_measures']}개", "#2f55a5"),
        (c3, "사고 사례", f"{len(incidents)}건", "#f58220"),
        (c4, "위협↔대책 연결", f"{stats['total_links']}개", "#2a9d8f"),
    ]:
        col.markdown(f"""
<div style="border:1px solid #e0e4f0; border-top:4px solid {color};
            border-radius:8px; padding:16px 20px; text-align:center;">
  <div style="font-size:1.6rem; font-weight:800; color:{color};">{value}</div>
  <div style="font-size:0.8rem; color:#666; margin-top:2px;">{label}</div>
</div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    col_nis, col_owasp = st.columns(2)

    with col_nis:
        st.markdown("""
#### NIS AI보안 가이드북 (2025.12)

국가정보원이 발간한 **국가·공공기관 AI시스템 보안 가이드북**으로,
생성형 AI·에이전틱 AI·피지컬 AI를 아우르는 AI 수명주기 전 단계의
보안위협과 대책을 체계적으로 정리한 국내 최초의 공공 AI보안 기준입니다.

**주요 구성**
- **보안위협 T01~T15**: 학습데이터 오염, 프롬프트 인젝션, 공급망 공격 등 15개 위협 유형
- **보안대책 M01~M30**: 공통·에이전틱(A-M)·피지컬(P-M) 영역별 대책
- **구축유형별 중점 대책**: 내부망 전용 / 외부망 연계 / 대민서비스 / 상용 AI서비스
- **수명주기**: 데이터 수집 → 학습 → 구축 → 운영 → 폐기 전 단계 커버
""")
        st.link_button("가이드북 원문 (NIS)", "https://www.nis.go.kr", use_container_width=True)

    with col_owasp:
        st.markdown("""
#### OWASP Top 10 for LLM Applications (2025)

**OWASP(Open Worldwide Application Security Project)**가 선정한
LLM 애플리케이션 10대 취약점으로, 전 세계 AI 보안의 사실상 표준입니다.

**10대 취약점 요약**
- **LLM01** 프롬프트 인젝션 &nbsp;·&nbsp; **LLM02** 민감 정보 노출
- **LLM03** 공급망 취약점 &nbsp;·&nbsp; **LLM04** 데이터·모델 오염
- **LLM05** 부적절한 출력 처리 &nbsp;·&nbsp; **LLM06** 과도한 권한 위임
- **LLM07** 시스템 프롬프트 유출 &nbsp;·&nbsp; **LLM08** 벡터·임베딩 취약점
- **LLM09** 허위 정보 생성 &nbsp;·&nbsp; **LLM10** 무제한 리소스 소비

NIS 가이드북의 위협·대책과 **양방향 교차 매핑**을 제공합니다.
""")
        st.link_button("OWASP LLM Top 10 원문", "https://genai.owasp.org/", use_container_width=True)

    st.divider()

    # 메뉴 안내
    st.markdown("#### 메뉴 안내")
    g1, g2, g3, g4, g5 = st.columns(5)
    for col, icon, name, desc in [
        (g1, "🔍", "지식 탐색",   "위협·대책 전체 목록과 상세 내용, 상호 연결 관계 탐색"),
        (g2, "🌐", "OWASP",       "LLM Top 10 항목과 NIS 가이드북 교차 매핑"),
        (g3, "🔥", "사고 사례",   "실제 발생한 AI 보안 사고 16건 상세 분석"),
        (g4, "✅", "체크리스트",  "구축유형·AI유형 선택 → 맞춤 체크리스트 HTML 생성"),
        (g5, "🔌", "MCP 연결",    "Claude와 연결해 자연어로 AI보안 질문"),
    ]:
        col.markdown(f"""
<div style="border:1px solid #e8eaf0; border-radius:8px; padding:14px 12px; height:110px;">
  <div style="font-size:1.4rem;">{icon}</div>
  <div style="font-weight:700; font-size:0.85rem; margin:4px 0 4px;">{name}</div>
  <div style="font-size:0.75rem; color:#666; line-height:1.4;">{desc}</div>
</div>""", unsafe_allow_html=True)

# --- Tab 1: Knowledge Explorer ---
with tab_explorer:
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("보안위협 (T01~T15)")
        for t in kg.threats:
            with st.expander(f"**{t['id']}** {t['name']}"):
                bmd(f"{t['id']} **{t['name']}**")
                show_threat_image(t["id"])
                bmd(f"**정의:** {t['definition']}")
                bmd(f"**위협:** {t['risk']}")
                if t.get("examples"):
                    st.markdown("**사례:**")
                    for ex in t["examples"]:
                        bmd(f"- {ex}")
                if t.get("lifecycles"):
                    st.markdown(f"**수명주기:** {', '.join(t['lifecycles'])}")
                related_measures = kg.get_measures_for_threat(t["id"])
                if related_measures:
                    badges = " ".join(_m_badge(m["id"]) for m in related_measures)
                    st.markdown(f"**대응 대책:** {badges}", unsafe_allow_html=True)
                # OWASP cross-reference
                related_owasp = [o for o in owasp_mapping if t["id"] in o.get("threat_ids", [])]
                if related_owasp:
                    badges = " ".join(_owasp_badge(o["owasp_id"]) for o in related_owasp)
                    st.markdown(f"**OWASP 연결:** {badges}", unsafe_allow_html=True)

    with col2:
        st.subheader("보안대책 (M01~M30)")
        measure_filter = st.radio(
            "필터", ["공통 (M)", "에이전틱 (A-M)", "피지컬 (P-M)"],
            horizontal=True, key="measure_filter"
        )
        filter_map = {"공통 (M)": None, "에이전틱 (A-M)": "에이전틱 AI", "피지컬 (P-M)": "피지컬 AI"}
        filtered_measures = kg.get_measures_by_ai_type(filter_map[measure_filter])

        for m in filtered_measures:
            with st.expander(f"**{m['id']}** {m['name']}"):
                bmd(f"{m['id']} **{m['name']}**")
                bmd(m["description"])
                if m.get("details"):
                    for d in m["details"]:
                        bmd(f"- {d}")
                if m.get("checklist"):
                    st.info(f"📋 {m['checklist']}")
                related_threats = kg.get_threats_for_measure(m["id"])
                if related_threats:
                    badges = " ".join(_t_badge(t["id"]) for t in related_threats)
                    st.markdown(f"**대응 위협:** {badges}", unsafe_allow_html=True)

# --- Tab 2: OWASP LLM Top 10 ---
with tab_owasp:
    st.subheader("OWASP Top 10 for LLM Applications (2025)")
    st.caption("각 항목과 NIS AI보안 가이드북의 대응 위협·대책을 교차 매핑합니다.")

    for o in owasp_items:
        mapping = owasp_map_by_id.get(o["id"], {})
        with st.expander(f"**{o['id']}** {o['name']} — {o['name_ko']}"):
            st.markdown(f"{_owasp_badge(o['id'])} **{o['name']}** ({o['name_ko']})", unsafe_allow_html=True)
            st.markdown(o["description"])
            if o.get("examples"):
                st.markdown("**공격 시나리오:**")
                for ex in o["examples"]:
                    st.markdown(f"- {ex}")

            st.divider()
            st.markdown("##### NIS 가이드북 매핑")

            # 매핑된 위협
            threat_ids = mapping.get("threat_ids", [])
            if threat_ids:
                badges = " ".join(_t_badge(tid) for tid in threat_ids)
                st.markdown(f"**대응 위협:** {badges}", unsafe_allow_html=True)
                for tid in threat_ids:
                    t = kg.get_threat(tid)
                    if t:
                        st.markdown(f"- {_t_badge(tid)} {t['name']}: {t['definition']}", unsafe_allow_html=True)

            # 매핑된 대책
            measure_ids = mapping.get("measure_ids", [])
            if measure_ids:
                badges = " ".join(_m_badge(mid) for mid in measure_ids)
                st.markdown(f"**대응 대책:** {badges}", unsafe_allow_html=True)

# --- Tab 3: Incidents ---
with tab_incidents:
    st.subheader("AI 보안 사고 사례")
    st.caption("NIS AI보안 가이드북에 수록된 실제 사고/공격 사례")

    if incidents:
        for inc in incidents:
            threat_ids = inc.get("threat_ids", [])
            year = inc.get("year", "")
            year_str = f" ({year})" if year else ""
            with st.expander(f"**{inc['id']}** {inc['title']}{year_str}"):
                # 관련 위협 배지
                if threat_ids:
                    badges = " ".join(_t_badge(tid) for tid in threat_ids)
                    st.markdown(f"**관련 위협:** {badges}", unsafe_allow_html=True)
                bmd(inc["description"])
                if inc.get("source"):
                    st.caption(f"출처: {inc['source']}")
                # 사고 관련 이미지
                img_key = inc.get("image")
                if img_key and img_key in image_index:
                    img_path = IMAGE_DIR / image_index[img_key]
                    if img_path.exists():
                        st.image(str(img_path), use_container_width=True)
    else:
        st.info("사고 사례 데이터가 없습니다.")

def _generate_checklist_html(cl_build: str, cl_ai: str, result: dict) -> str:
    """Generate a standalone HTML checklist page."""
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")

    threat_rows = ""
    for t in result["threats"]:
        threat_rows += f"""
        <tr>
          <td><span class="badge badge-threat">{t['id']}</span></td>
          <td><strong>{t['name']}</strong></td>
          <td>{t.get('risk', '')}</td>
        </tr>"""

    checklist_rows = ""
    for i, m in enumerate(result["measures"], 1):
        label = m.get("checklist") or m["name"]
        checklist_rows += f"""
        <tr>
          <td class="check-cell"><input type="checkbox" id="chk_{m['id']}"></td>
          <td><label for="chk_{m['id']}"><span class="badge badge-measure">{m['id']}</span></label></td>
          <td><label for="chk_{m['id']}">{label}</label></td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>KAIS 체크리스트 — {cl_build} + {cl_ai}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Malgun Gothic', 'Apple SD Gothic Neo', sans-serif;
    font-size: 14px;
    background: #f5f7fa;
    color: #1a1a2e;
    padding: 24px;
  }}
  .page {{
    max-width: 900px;
    margin: 0 auto;
    background: #fff;
    border: 2px solid #2f55a5;
    border-radius: 10px;
    padding: 32px 36px;
  }}
  /* Header */
  .header {{
    border-bottom: 3px solid #2f55a5;
    padding-bottom: 16px;
    margin-bottom: 20px;
  }}
  .header h1 {{
    font-size: 22px;
    color: #2f55a5;
    letter-spacing: -0.5px;
  }}
  .header h2 {{
    font-size: 15px;
    font-weight: normal;
    color: #555;
    margin-top: 4px;
  }}
  /* Meta grid */
  .meta-grid {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 10px;
    background: #f0f4ff;
    border: 1px solid #c5d3f5;
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 20px;
  }}
  .meta-item label {{ font-size: 11px; color: #777; display: block; margin-bottom: 2px; }}
  .meta-item span  {{ font-size: 14px; font-weight: bold; color: #1a1a2e; }}
  /* Warning */
  .warning {{
    background: #fff8e1;
    border-left: 4px solid #f0a500;
    border-radius: 4px;
    padding: 10px 14px;
    font-size: 12px;
    color: #7a5c00;
    margin-bottom: 24px;
    line-height: 1.6;
  }}
  /* Section titles */
  h3 {{
    font-size: 15px;
    color: #2f55a5;
    margin: 20px 0 10px;
    padding-left: 8px;
    border-left: 4px solid #2f55a5;
  }}
  /* Tables */
  table {{
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 8px;
    font-size: 13px;
  }}
  th {{
    background: #2f55a5;
    color: #fff;
    padding: 8px 10px;
    text-align: left;
    font-size: 12px;
  }}
  td {{
    padding: 8px 10px;
    border-bottom: 1px solid #e8eaf0;
    vertical-align: top;
    line-height: 1.5;
  }}
  tr:hover td {{ background: #f5f7ff; }}
  .check-cell {{ width: 32px; text-align: center; }}
  input[type="checkbox"] {{ width: 16px; height: 16px; cursor: pointer; accent-color: #2f55a5; }}
  /* Badges */
  .badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-weight: bold;
    font-size: 12px;
    white-space: nowrap;
  }}
  .badge-threat  {{ background: #ed1c24; color: #fff; }}
  .badge-measure {{ background: #2f55a5; color: #fff; }}
  /* Footer */
  .footer {{
    margin-top: 28px;
    padding-top: 14px;
    border-top: 1px solid #ddd;
    font-size: 11px;
    color: #999;
    display: flex;
    justify-content: space-between;
  }}
  .sources {{ font-size: 11px; color: #777; margin-top: 6px; line-height: 1.7; }}
  @media print {{
    body {{ background: white; padding: 0; }}
    .page {{ border: 1px solid #aaa; padding: 20px; }}
    tr:hover td {{ background: none; }}
  }}
</style>
</head>
<body>
<div class="page">

  <div class="header">
    <h1>🛡️ KAIS — AI보안 체크리스트</h1>
    <h2>국가·공공기관 AI보안 어드바이저 · K-AI Security Advisor</h2>
  </div>

  <div class="meta-grid">
    <div class="meta-item">
      <label>구축 유형</label>
      <span>{cl_build}</span>
    </div>
    <div class="meta-item">
      <label>AI 유형</label>
      <span>{cl_ai}</span>
    </div>
    <div class="meta-item">
      <label>생성일시</label>
      <span>{generated_at}</span>
    </div>
    <div class="meta-item">
      <label>버전</label>
      <span>KAIS v{KAIS_VERSION}</span>
    </div>
    <div class="meta-item">
      <label>위협 수</label>
      <span>{len(result['threats'])}개</span>
    </div>
    <div class="meta-item">
      <label>대책 수</label>
      <span>{len(result['measures'])}개</span>
    </div>
  </div>

  <div class="warning">
    ⚠️ <strong>실험적 서비스 (Experimental)</strong> — 본 체크리스트는 연구·교육 목적의 비공식 자료이며 국가정보원(NIS)과 무관합니다.
    답변은 NIS AI보안 가이드북(2025.12)을 기반으로 생성되며, 공식 보안 검토를 대체하지 않습니다.
  </div>

  <h3>주요 보안위협</h3>
  <table>
    <thead>
      <tr><th style="width:80px">위협 ID</th><th style="width:160px">위협명</th><th>위험 내용</th></tr>
    </thead>
    <tbody>{threat_rows}
    </tbody>
  </table>

  <h3>보안대책 체크리스트</h3>
  <table>
    <thead>
      <tr><th class="check-cell">✓</th><th style="width:80px">대책 ID</th><th>점검 항목</th></tr>
    </thead>
    <tbody>{checklist_rows}
    </tbody>
  </table>

  <div class="sources">
    <strong>참고 출처:</strong><br>
    · NIS AI보안 가이드북 (2025.12) — <a href="https://www.nis.go.kr" target="_blank">www.nis.go.kr</a><br>
    · OWASP Top 10 for LLM Applications — <a href="https://genai.owasp.org/" target="_blank">genai.owasp.org</a><br>
    · NIST AI Risk Management Framework — <a href="https://www.nist.gov/artificial-intelligence" target="_blank">nist.gov/artificial-intelligence</a><br>
    · MITRE ATLAS — <a href="https://atlas.mitre.org/" target="_blank">atlas.mitre.org</a>
  </div>

  <div class="footer">
    <span>KAIS v{KAIS_VERSION} · {generated_at} · {cl_build} + {cl_ai}</span>
    <span>
      <a href="https://k-ai-sec.streamlit.app" target="_blank">k-ai-sec.streamlit.app</a> ·
      <a href="https://github.com/sulgik/kais" target="_blank">github.com/sulgik/kais</a> ·
      sulgik@gmail.com
    </span>
  </div>

</div>
</body>
</html>"""


# --- Tab 4: Checklist Generator ---
with tab_checklist:
    st.subheader("보안대책 체크리스트 생성기")
    st.markdown("구축 유형과 AI 유형을 선택하면 맞춤형 체크리스트를 생성합니다.")

    cl_col1, cl_col2 = st.columns(2)
    with cl_col1:
        cl_build = st.selectbox(
            "구축 유형 선택",
            options=["내부망 전용", "외부망 연계", "대민서비스", "상용 AI서비스"],
            key="cl_build",
        )
    with cl_col2:
        cl_ai = st.selectbox(
            "AI 유형 선택",
            options=["생성형 AI", "에이전틱 AI", "피지컬 AI"],
            key="cl_ai",
        )

    # 구축유형 이미지
    bt_key_map = {
        "내부망 전용": "BT_내부망전용",
        "외부망 연계": "BT_외부망연계",
        "대민서비스": "BT_대민서비스",
        "상용 AI서비스": "BT_상용서비스",
    }
    bt_img_key = bt_key_map.get(cl_build)
    if bt_img_key and bt_img_key in image_index:
        img_path = IMAGE_DIR / image_index[bt_img_key]
        if img_path.exists():
            st.image(str(img_path), caption=f"{cl_build} 구성 개념도", width=500)

    if st.button("체크리스트 생성", type="primary"):
        result = kg.query_by_context(build_type=cl_build, ai_type=cl_ai)

        st.markdown(f"### 📋 {cl_build} + {cl_ai} 체크리스트")

        st.markdown("#### 주요 위협")
        for t in result["threats"]:
            bmd(f"- {t['id']} {t['name']}: {t['risk']}")

        st.markdown("#### 보안대책 체크리스트")
        for m in result["measures"]:
            if m.get("checklist"):
                st.checkbox(f"**{m['id']}** {m['checklist']}", key=f"check_{m['id']}")
            else:
                st.checkbox(f"**{m['id']}** {m['name']}", key=f"check_{m['id']}")

        st.divider()
        html_content = _generate_checklist_html(cl_build, cl_ai, result)
        fname = f"kais_checklist_{cl_build}_{cl_ai}_{datetime.now().strftime('%Y%m%d_%H%M')}.html"
        st.download_button(
            label="⬇️ HTML로 내보내기",
            data=html_content.encode("utf-8"),
            file_name=fname,
            mime="text/html",
            help="독립 실행 가능한 HTML 체크리스트 파일로 저장합니다.",
        )

# --- Tab 5: MCP 연결 안내 ---
with tab_mcp:
    st.subheader("🔌 AI 어드바이저와 대화하기 — MCP 연결")
    st.markdown(
        """
KAIS 지식그래프를 Claude와 연결하면, **자연어로 AI 보안 질문**을 할 수 있습니다.
API 키를 여기에 입력할 필요 없이, 본인의 Claude 환경에서 바로 사용합니다.

---

#### 방법 1: `uvx`로 바로 실행 (추천)

```json
// ~/.claude/settings.json 또는 Claude Desktop 설정
{
  "mcpServers": {
    "kais": {
      "command": "uvx",
      "args": ["kais-mcp"]
    }
  }
}
```

#### 방법 2: 소스에서 직접 실행

```bash
git clone https://github.com/your-org/kais.git
cd kais
pip install -e .
```

```json
{
  "mcpServers": {
    "kais": {
      "command": "python",
      "args": ["/path/to/kais/server.py"]
    }
  }
}
```

---

#### 사용 가능한 도구

| 도구 | 설명 |
|------|------|
| `query_by_context` | 구축유형·AI유형·수명주기로 위협·대책 조회 |
| `get_threat` | T## ID로 위협 상세 조회 |
| `get_measure` | M## ID로 대책 상세 조회 |
| `search_threats` | 키워드로 위협 검색 |
| `search_measures` | 키워드로 대책 검색 |
| `list_incidents` | 보안 사고 사례 조회 |
| `get_owasp_mapping` | OWASP LLM Top 10 ↔ NIS 매핑 조회 |
| `summary` | 지식그래프 통계 |

---

#### 예시 질문

> "우리 기관에서 생성형 AI 챗봇을 대민서비스로 도입하려고 합니다. 가장 주의해야 할 보안위협과 대책은?"

> "에이전틱 AI에서 tool poisoning 관련 보안위협과 대책을 알려줘"

> "OWASP LLM01과 대응되는 NIS 가이드북 항목은?"
""",
    )
