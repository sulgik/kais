"""
K-AISecMap - AI Security Mapping Advisor
Streamlit Web UI
"""
import json
import re
from datetime import datetime
from pathlib import Path
import streamlit as st
from knowledge_graph import SecurityKnowledgeGraph

APP_VERSION = "0.1.0"
APP_DATA_SOURCE = "NIS AI보안 가이드북 (2025.12)"

st.set_page_config(
    page_title="K-AISecMap - AI 보안 매핑 어드바이저",
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

def _atlas_badge(aid: str) -> str:
    return f'<span style="background:#7b2d8e;color:#fff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:0.85em;white-space:nowrap;">{aid}</span>'

_BADGE_PATTERN = re.compile(r'\b(AML\.T\d{4}|LLM\d{2}|T\d{2}|M\d{2}|A-M\d{2}|P-M\d{2})\b')

def badged(text: str) -> str:
    '''Replace all LLM##, T##, M##, A-M##, P-M## in text with colored HTML badges.'''
    def _repl(m):
        token = m.group(1)
        if token.startswith("AML."):
            return _atlas_badge(token)
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
    st.title("🛡️ K-AISecMap")

    stats = kg.summary()
    atlas_count = stats.get('atlas_techniques', 0)
    st.caption(f"📊 {stats['total_threats']} 위협 · {stats['total_measures']} 대책 · {atlas_count} ATLAS 공격기법")

    st.divider()

    # 통합 지식맵 필터
    st.markdown("**🗺️ 지식맵 필터**")
    pair_choice = st.radio(
        "표시할 매핑",
        ["🔴 NIS 위협 ↔ 🔵 대책", "🟠 OWASP ↔ 🟣 ATLAS 공격기법"],
        key="trinity_pair", label_visibility="collapsed",
    )

    st.divider()

    # 노드 클릭 상세 정보 (그래프에서 선택된 노드)
    sel_id = st.session_state.get("trinity_selected")
    if sel_id:
        cross = kg.get_cross_framework(sel_id)
        if cross["framework"] == "NIS":
            item = cross["item"]
            st.markdown(f"##### {_t_badge(item['id'])} {item['name']}", unsafe_allow_html=True)
            st.markdown(f"{item.get('definition', '')}")
            st.markdown(f"**위험:** {item.get('risk', '')}")
            if item.get("lifecycles"):
                st.caption(f"수명주기: {' · '.join(item['lifecycles'])}")
            if item.get("examples"):
                with st.expander("실제 사례", expanded=False):
                    for ex in item["examples"]:
                        st.markdown(f"- {ex}")
            if cross["atlas"]:
                st.markdown("**ATLAS 공격기법**")
                for a in cross["atlas"]:
                    st.markdown(f"- {_atlas_badge(a['id'])} {a['name_ko']}", unsafe_allow_html=True)
            if cross["owasp"]:
                st.markdown("**OWASP**")
                for o in cross["owasp"]:
                    st.markdown(f"- {_owasp_badge(o['id'])} {o.get('name_ko', '')}", unsafe_allow_html=True)
            if cross["nis_measures"]:
                st.markdown("**대응 대책**")
                st.markdown(" ".join(_m_badge(m["id"]) for m in cross["nis_measures"]), unsafe_allow_html=True)
        elif cross["framework"] == "ATLAS":
            item = cross["item"]
            tactic_names = [kg.get_atlas_tactic(tid)["name_ko"] for tid in item.get("tactic_ids", []) if kg.get_atlas_tactic(tid)]
            st.markdown(f"##### {_atlas_badge(item['id'])} {item['name_ko']}", unsafe_allow_html=True)
            st.markdown(f"*{item['name']}*")
            if tactic_names:
                st.caption(f"전술: {' · '.join(tactic_names)}")
            st.markdown(item.get("description", ""))
            mapping = kg.get_atlas_mapping(item["id"]) or {}
            if mapping.get("rationale"):
                st.info(f"**매핑 근거:** {mapping['rationale']}")
            if cross["nis_threats"]:
                st.markdown("**NIS 위협**")
                for t in cross["nis_threats"]:
                    st.markdown(f"- {_t_badge(t['id'])} {t['name']}", unsafe_allow_html=True)
            if cross["owasp"]:
                st.markdown("**OWASP**")
                for o in cross["owasp"]:
                    st.markdown(f"- {_owasp_badge(o['id'])} {o.get('name_ko', '')}", unsafe_allow_html=True)
            if cross["nis_measures"]:
                st.markdown("**대응 대책**")
                st.markdown(" ".join(_m_badge(m["id"]) for m in cross["nis_measures"]), unsafe_allow_html=True)
            st.markdown(f"[ATLAS 원문 →]({item.get('url', '')})")
        elif cross["framework"] == "OWASP":
            item = cross["item"]
            st.markdown(f"##### {_owasp_badge(item['id'])} {item.get('name_ko', item['name'])}", unsafe_allow_html=True)
            st.markdown(f"*{item['name']}*")
            st.markdown(item.get("description", "")[:150] + "…" if len(item.get("description", "")) > 150 else item.get("description", ""))
            if cross["nis_threats"]:
                st.markdown("**NIS 위협**")
                for t in cross["nis_threats"]:
                    st.markdown(f"- {_t_badge(t['id'])} {t['name']}", unsafe_allow_html=True)
            if cross["atlas"]:
                st.markdown("**ATLAS 공격기법**")
                for a in cross["atlas"]:
                    st.markdown(f"- {_atlas_badge(a['id'])} {a['name_ko']}", unsafe_allow_html=True)
            if cross["nis_measures"]:
                st.markdown("**대응 대책**")
                st.markdown(" ".join(_m_badge(m["id"]) for m in cross["nis_measures"]), unsafe_allow_html=True)

    st.divider()
    st.markdown("📄 **관련 문서**")
    st.markdown("- [NIS AI보안 가이드북](https://www.nis.go.kr)")
    st.markdown("- [OWASP LLM Top 10](https://genai.owasp.org/)")
    st.markdown("- [MITRE ATLAS](https://atlas.mitre.org/)")
    st.caption("Made by [sulgik@gmail.com](mailto:sulgik@gmail.com)")


# --- Main area ---
st.markdown("""
<div style="padding:16px 0 12px;">
  <div style="font-size:2.2rem; font-weight:900; letter-spacing:-1.5px; color:#1a1a2e; line-height:1.15;">
    K-AISecMap
  </div>
  <div style="font-size:1rem; font-weight:400; color:#2f55a5; letter-spacing:2px; margin-top:6px; text-transform:uppercase;">
    AI Security Mapping Advisor
  </div>
</div>
""", unsafe_allow_html=True)

st.warning(
    "**⚠️ 실험적 서비스 (Experimental)** — 연구·교육 목적의 비공식 서비스이며 국가정보원(NIS)과 무관합니다. "
    "NIS AI보안 가이드북(2025.12) 기반으로 생성되며 공식 보안 검토를 대체하지 않습니다.",
    icon="⚠️",
)

# --- Tabs ---
tab_home, tab_explorer, tab_trinity, tab_owasp, tab_incidents, tab_checklist, tab_mcp = st.tabs(
    ["홈", "🔍 지식 탐색", "🗺️ 통합 지식맵", "🌐 OWASP LLM Top 10", "🔥 사고 사례", "✅ 체크리스트", "🔌 MCP 연결"]
)

# --- Tab 0: Home ---
with tab_home:
    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

    col_nis, col_owasp, col_atlas = st.columns(3, gap="large")

    with col_nis:
        st.markdown("""
<div style="border-left:4px solid #1a1a2e; padding-left:16px; margin-bottom:16px;">
  <div style="font-size:1.05rem; font-weight:700; color:#1a1a2e;">NIS AI보안 가이드북</div>
  <div style="font-size:0.8rem; color:#888;">국가정보원 · 2025년 12월</div>
</div>
""", unsafe_allow_html=True)
        st.markdown("""
국가정보원이 발간한 **국가·공공기관 AI시스템 보안 가이드북**입니다.
생성형·에이전틱·피지컬 AI를 포괄하는 수명주기 전 단계의 보안위협과 대책을 정리한
국내 최초의 공공 AI보안 기준서입니다.

**보안위협 (T01 ~ T15)**
학습데이터 오염, 프롬프트 인젝션, 회피 공격, 공급망 공격 등
AI시스템에 특화된 15개 위협 유형을 정의합니다.

**보안대책 (M01 ~ M30 · A-M · P-M)**
공통 대책 외에 에이전틱 AI(A-M), 피지컬 AI(P-M) 전용 대책을 별도 제시합니다.

**구축유형별 가이드**
내부망 전용 / 외부망 연계 / 대민서비스 / 상용 AI서비스
각 환경에 맞는 중점 위협과 우선 적용 대책을 안내합니다.
""")
        st.link_button("원문 보기 — nis.go.kr", "https://www.nis.go.kr", use_container_width=True)

    with col_owasp:
        st.markdown("""
<div style="border-left:4px solid #f58220; padding-left:16px; margin-bottom:16px;">
  <div style="font-size:1.05rem; font-weight:700; color:#1a1a2e;">OWASP Top 10 for LLM Applications</div>
  <div style="font-size:0.8rem; color:#888;">Open Worldwide Application Security Project · 2025</div>
</div>
""", unsafe_allow_html=True)
        st.markdown("""
**OWASP**가 선정한 LLM 애플리케이션의 10대 취약점으로,
전 세계 AI 보안 실무의 사실상 표준입니다.

| ID | 취약점 |
|----|--------|
| LLM01 | 프롬프트 인젝션 |
| LLM02 | 민감 정보 노출 |
| LLM03 | 공급망 취약점 |
| LLM04 | 데이터·모델 오염 |
| LLM05 | 부적절한 출력 처리 |
| LLM06 | 과도한 권한 위임 |
| LLM07 | 시스템 프롬프트 유출 |
| LLM08 | 벡터·임베딩 취약점 |
| LLM09 | 허위 정보 생성 |
| LLM10 | 무제한 리소스 소비 |

본 시스템에서 NIS 가이드북 위협·대책과 **양방향 교차 매핑**을 제공합니다.
""")
        st.link_button("원문 보기 — genai.owasp.org", "https://genai.owasp.org/", use_container_width=True)

    with col_atlas:
        st.markdown("""
<div style="border-left:4px solid #7b2d8e; padding-left:16px; margin-bottom:16px;">
  <div style="font-size:1.05rem; font-weight:700; color:#1a1a2e;">MITRE ATLAS</div>
  <div style="font-size:0.8rem; color:#888;">Adversarial Threat Landscape for AI Systems</div>
</div>
""", unsafe_allow_html=True)
        st.markdown(f"""
**MITRE ATLAS**는 AI/ML 시스템에 대한 적대적 위협을
ATT&CK 프레임워크 스타일로 체계화한 **taxonomy**입니다.

**{len(kg.atlas_tactics)}개 전술 (Tactics)**
정찰, 초기접근, 실행, 지속성 유지, 유출, 영향 등
공격 킬체인의 각 단계를 정의합니다.

**{len(kg.atlas_techniques)}개 기법 (Techniques)**
학습데이터 오염, 프롬프트 인젝션, 모델 추출,
적대적 데이터 생성 등 구체적 공격 기법입니다.

**본 시스템의 차별점**
NIS 위협(T##) ↔ ATLAS 기법(AML.T####) ↔ OWASP(LLM##)
**3자 교차 매핑**을 제공하여, 어느 프레임워크에서든
관련 항목을 즉시 탐색할 수 있습니다.
""")
        st.link_button("원문 보기 — atlas.mitre.org", "https://atlas.mitre.org/", use_container_width=True)

    st.divider()

    # ── 홈 네트워크 그래프 ──
    st.markdown("""
**🗺️ AI 보안 프레임워크 통합 지도**

아래 그래프는 세 가지 주요 AI 보안 프레임워크의 관계를 시각화합니다.
**선으로 연결된 노드**는 서로 관련된 보안 항목입니다. **노드를 클릭**하면 상세 정보를 확인할 수 있고,
드래그하거나 스크롤하여 그래프를 탐색할 수 있습니다.

| 색상 | 프레임워크 | 설명 |
|------|-----------|------|
| 🔴 빨강 | **NIS 보안위협** (T01~T15) | 국정원 가이드북이 정의한 AI 보안위협 |
| 🟣 보라 | **ATLAS 공격기법** (AML.T0000) | MITRE가 분류한 AI 대상 실제 공격 기법 |
| 🟠 주황 | **OWASP LLM Top 10** (LLM01~10) | LLM 애플리케이션 10대 취약점 |
""")

    try:
        from streamlit_agraph import agraph, Node, Edge, Config

        graph_data = kg.build_graph_data(
            show_nis=True, show_atlas=True,
            show_owasp=True, show_measures=False,
        )

        agraph_nodes = []
        for n in graph_data["nodes"]:
            agraph_nodes.append(Node(
                id=n["id"], label=n["label"], color=n["color"],
                shape=n["shape"], size=n["size"], title=n["title"],
                font={"color": "#333333", "size": 12},
            ))

        agraph_edges = []
        for e in graph_data["edges"]:
            edge_kwargs = {"source": e["source"], "target": e["target"], "color": e.get("color", "#888")}
            if e.get("width"):
                edge_kwargs["width"] = e["width"]
            agraph_edges.append(Edge(**edge_kwargs))

        config = Config(
            width="100%", height=600,
            directed=False, physics=True, hierarchical=False,
        )

        selected_home = agraph(nodes=agraph_nodes, edges=agraph_edges, config=config)
        if selected_home:
            st.session_state["trinity_selected"] = selected_home
            st.rerun()

    except ImportError:
        pass

    st.caption("참고 기준: NIST AI RMF · MITRE ATLAS · OWASP LLM Top 10 · NIS AI보안 가이드북(2025.12)")

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
                # ATLAS cross-reference
                related_atlas = kg.get_atlas_for_threat(t["id"])
                if related_atlas:
                    badges = " ".join(_atlas_badge(a["id"]) for a in related_atlas)
                    st.markdown(f"**ATLAS 연결:** {badges}", unsafe_allow_html=True)
                    for a in related_atlas:
                        st.caption(f"  {a['id']} {a['name_ko']} — {a['name']}")

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

# --- Tab 2: Trinity Knowledge Map ---
with tab_trinity:
    st.subheader("통합 지식맵 — NIS + MITRE ATLAS + OWASP")
    st.caption("← 사이드바에서 매핑 필터를 선택하세요. 그래프 노드를 클릭하면 사이드바에 상세 정보가 표시됩니다.")

    # Read pair choice from sidebar radio
    show_nis_pair = pair_choice.startswith("🔴")
    show_ext_pair = not show_nis_pair

    view_graph, view_sankey = st.tabs(["🕸️ 네트워크 그래프", "🌊 Sankey 흐름도"])

    # ── View 1: Network Graph (full width) ─────────────────────────────────
    with view_graph:
        try:
            from streamlit_agraph import agraph, Node, Edge, Config

            graph_data = kg.build_graph_data(
                show_nis=show_nis_pair, show_atlas=show_ext_pair,
                show_owasp=show_ext_pair, show_measures=show_nis_pair,
            )

            agraph_nodes = []
            for n in graph_data["nodes"]:
                agraph_nodes.append(Node(
                    id=n["id"], label=n["label"], color=n["color"],
                    shape=n["shape"], size=n["size"], title=n["title"],
                    font={"color": "#333333", "size": 12},
                ))

            agraph_edges = []
            for e in graph_data["edges"]:
                edge_kwargs = {"source": e["source"], "target": e["target"], "color": e.get("color", "#888")}
                if e.get("width"):
                    edge_kwargs["width"] = e["width"]
                agraph_edges.append(Edge(**edge_kwargs))

            config = Config(
                width="100%", height=900,
                directed=False, physics=True, hierarchical=False,
            )

            # Legend
            st.markdown(
                '<span style="font-size:0.85em;">'
                '<span style="display:inline-block;width:12px;height:12px;background:#ed1c24;border-radius:50%;vertical-align:middle;"></span> <b>NIS 위협</b> &nbsp; '
                '<span style="display:inline-block;width:12px;height:12px;background:#2f55a5;transform:rotate(45deg);vertical-align:middle;"></span> <b>NIS 대책</b> &nbsp; '
                '<span style="display:inline-block;width:0;height:0;border-left:7px solid transparent;border-right:7px solid transparent;border-bottom:12px solid #7b2d8e;vertical-align:middle;"></span> <b>ATLAS 공격기법</b> &nbsp; '
                '<span style="display:inline-block;width:12px;height:12px;background:#f58220;vertical-align:middle;"></span> <b>OWASP</b>'
                '</span>', unsafe_allow_html=True,
            )

            selected = agraph(nodes=agraph_nodes, edges=agraph_edges, config=config)
            if selected:
                st.session_state["trinity_selected"] = selected
                st.rerun()

        except ImportError:
            st.error("streamlit-agraph가 설치되지 않았습니다. `pip install streamlit-agraph`를 실행해주세요.")

    # ── View 2: Sankey ────────────────────────────────────────────────────
    with view_sankey:
        import plotly.graph_objects as go

        labels = []
        label_idx = {}

        def _strip_ai(s):
            return s.replace('AI ', '').replace('AI', '')

        def _get_idx(label):
            if label not in label_idx:
                label_idx[label] = len(labels)
                labels.append(label)
            return label_idx[label]

        sources, targets, values, link_colors = [], [], [], []

        if show_nis_pair:
            # NIS 위협 → NIS 대책
            for link in kg.links:
                t = kg.get_threat(link["threat_id"])
                m = kg.get_measure(link["measure_id"])
                if t and m:
                    src_label = f"{t['id']} {_strip_ai(t['name'])}"
                    tgt_label = f"{m['id']} {_strip_ai(m['name'])}"
                    sources.append(_get_idx(src_label))
                    targets.append(_get_idx(tgt_label))
                    values.append(1)
                    link_colors.append("rgba(47,85,165,0.3)")

        if show_ext_pair:
            # ATLAS 공격기법 → OWASP (via shared NIS threats)
            for am in kg._atlas_mapping:
                tech = kg.get_atlas_technique(am["atlas_id"])
                if not tech:
                    continue
                src_label = f"{tech['id']} {_strip_ai(tech['name_ko'])}"
                for oid in am.get("owasp_ids", []):
                    o = kg.get_owasp(oid)
                    if o:
                        tgt_label = f"{o['id']} {_strip_ai(o['name_ko'])}"
                        sources.append(_get_idx(src_label))
                        targets.append(_get_idx(tgt_label))
                        values.append(2)
                        link_colors.append("rgba(123,45,142,0.3)")

            # Also show OWASP → NIS 위협 connections (one-hop context)
            # These go from OWASP to the NIS threats they map to
            for om in kg._owasp_mapping:
                o = kg.get_owasp(om["owasp_id"])
                if not o:
                    continue
                src_label = f"{o['id']} {_strip_ai(o['name_ko'])}"
                for tid in om.get("threat_ids", []):
                    t = kg.get_threat(tid)
                    if t:
                        tgt_label = f"{t['id']} {_strip_ai(t['name'])}"
                        sources.append(_get_idx(src_label))
                        targets.append(_get_idx(tgt_label))
                        values.append(1)
                        link_colors.append("rgba(245,130,32,0.3)")

        # 노드 색상
        node_colors = []
        for lbl in labels:
            if lbl.startswith("AML."):
                node_colors.append("#7b2d8e")
            elif lbl.startswith("LLM"):
                node_colors.append("#f58220")
            elif lbl.startswith("T"):
                node_colors.append("#ed1c24")
            elif lbl.startswith("M") or lbl.startswith("A-M") or lbl.startswith("P-M"):
                node_colors.append("#2f55a5")
            else:
                node_colors.append("#888")

        if sources:
            fig = go.Figure(go.Sankey(
                arrangement="snap",
                node=dict(
                    pad=14, thickness=20,
                    label=labels,
                    color=node_colors,
                    line=dict(color="white", width=0.5),
                ),
                textfont=dict(size=13, color="#000000", family="sans-serif"),
                link=dict(
                    source=sources, target=targets, value=values,
                    color=link_colors,
                ),
            ))
            sankey_title = "NIS 위협 → 대책" if show_nis_pair else "ATLAS 공격기법 → OWASP → NIS 위협"
            fig.update_layout(
                title=dict(text=sankey_title, font=dict(size=14)),
                height=800,
                margin=dict(l=10, r=10, t=40, b=10),
                font=dict(size=11, color="#000000"),
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("위에서 표시할 프레임워크를 선택하세요.")

# --- Tab 3: OWASP LLM Top 10 ---
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

            # ATLAS cross-reference (via shared NIS threats)
            atlas_ids = set()
            for tid in threat_ids:
                for a in kg.get_atlas_for_threat(tid):
                    atlas_ids.add(a["id"])
            if atlas_ids:
                st.markdown("##### MITRE ATLAS 매핑")
                for aid in sorted(atlas_ids):
                    tech = kg.get_atlas_technique(aid)
                    if tech:
                        st.markdown(f"- {_atlas_badge(aid)} [{tech['name_ko']}]({tech.get('url', '')}) — {tech['name']}", unsafe_allow_html=True)

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
                        st.image(str(img_path), width=500)
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
<title>K-AISecMap 체크리스트 — {cl_build} + {cl_ai}</title>
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
    <h1>🛡️ K-AISecMap — AI보안 체크리스트</h1>
    <h2>국가·공공기관 AI보안 매핑 어드바이저 · AI Security Mapping Advisor</h2>
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
      <span>K-AISecMap v{APP_VERSION}</span>
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
    <span>K-AISecMap v{APP_VERSION} · {generated_at} · {cl_build} + {cl_ai}</span>
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
K-AISecMap 지식그래프를 Claude와 연결하면, **자연어로 AI 보안 질문**을 할 수 있습니다.
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
| `get_atlas_technique` | ATLAS 기법 상세 + NIS/OWASP 매핑 조회 |
| `search_atlas` | 키워드로 ATLAS 기법 검색 |
| `get_cross_framework_mapping` | 3자 교차 매핑 (T##/AML.T####/LLM##) |
| `summary` | 지식그래프 통계 |

---

#### 예시 질문

> "우리 기관에서 생성형 AI 챗봇을 대민서비스로 도입하려고 합니다. 가장 주의해야 할 보안위협과 대책은?"

> "에이전틱 AI에서 tool poisoning 관련 보안위협과 대책을 알려줘"

> "OWASP LLM01과 대응되는 NIS 가이드북 항목은?"
""",
    )
