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


# --- Sidebar (navigation) ---
with st.sidebar:
    st.markdown("""
<div style="padding:4px 0 12px;">
  <div style="font-size:1.3rem;font-weight:900;letter-spacing:-0.5px;color:#1a1a2e;">K-AISecMap</div>
  <div style="font-size:0.72rem;color:#888;margin-top:2px;line-height:1.4;">
    AI Security Mapping Advisor
  </div>
</div>
""", unsafe_allow_html=True)

    st.divider()

    MENU_ITEMS = [
        ("🏠", "홈",                "home"),
        ("🔍", "지식 탐색",         "explorer"),
        ("🌐", "OWASP LLM Top 10", "owasp"),
        ("🔥", "사고 사례",         "incidents"),
        ("✅", "체크리스트",        "checklist"),
        ("🔌", "MCP 연결",         "mcp"),
    ]
    menu_labels = [f"{icon}  {label}" for icon, label, _ in MENU_ITEMS]
    menu_keys   = [key for _, _, key in MENU_ITEMS]

    selected_label = st.radio(
        "메뉴",
        menu_labels,
        label_visibility="collapsed",
    )
    page = menu_keys[menu_labels.index(selected_label)]

    st.divider()
    st.markdown("📄 **관련 문서**")
    st.markdown("- [NIS AI보안 가이드북](https://www.nis.go.kr)")
    st.markdown("- [OWASP LLM Top 10](https://genai.owasp.org/)")
    st.markdown("- [MITRE ATLAS](https://atlas.mitre.org/)")
    st.divider()
    stats = kg.summary()
    st.caption(f"📊 {stats['total_threats']} 위협 · {stats['total_measures']} 대책 · {len(kg.incidents)} 사고사례")
    st.caption("[k-ai-sec.streamlit.app](https://k-ai-sec.streamlit.app) · [github.com/sulgik/kais](https://github.com/sulgik/kais)")

# --- Title ---
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
st.divider()

# ═══════════════════════════════════════════════════════════
# Helper: Node detail panel (reused on home page)
# ═══════════════════════════════════════════════════════════
def _render_node_detail(sel_id: str):
    """Render detail for a selected graph node."""
    if not sel_id:
        return
    # NIS Threat
    if sel_id in kg._threat_by_id:
        item = kg._threat_by_id[sel_id]
        st.markdown(f"### {_t_badge(item['id'])} {item['name']}", unsafe_allow_html=True)
        st.markdown(item.get("definition", ""))
        st.markdown(f"**위험:** {item.get('risk', '')}")
        if item.get("lifecycles"):
            st.caption(f"수명주기: {' · '.join(item['lifecycles'])}")
        show_threat_image(sel_id)
        inc_ids = kg._incidents_for_threat.get(sel_id, [])
        if inc_ids:
            st.markdown("**🔴 관련 사고사례**")
            for iid in inc_ids:
                inc = kg._incident_by_id[iid]
                st.markdown(f"- **{inc['title']}** ({inc['year']}) — {inc['description'][:80]}…")
        owasp_list = kg.get_owasp_for_threat(sel_id)
        if owasp_list:
            st.markdown("**🟠 OWASP 매핑:** " + " ".join(f"{_owasp_badge(o['id'])}" for o in owasp_list), unsafe_allow_html=True)
        measures = kg.get_measures_for_threat(sel_id)
        if measures:
            st.markdown("**🔵 대응 대책:** " + " ".join(_m_badge(m["id"]) for m in measures), unsafe_allow_html=True)
    # NIS Incident
    elif sel_id in kg._incident_by_id:
        inc = kg._incident_by_id[sel_id]
        st.markdown(f"### ⭐ {inc['title']}")
        st.markdown(f"**{inc['year']}년** · {inc.get('source', '')}")
        st.markdown(inc["description"])
        img_key = inc.get("image")
        if img_key and img_key in image_index:
            img_path = IMAGE_DIR / image_index[img_key]
            if img_path.exists():
                st.image(str(img_path), width=500)
        threat_badges = " ".join(_t_badge(tid) for tid in inc.get("threat_ids", []))
        st.markdown(f"**관련 위협:** {threat_badges}", unsafe_allow_html=True)
    # ATLAS Case Study
    elif sel_id in kg._case_study_by_id:
        cs = kg._case_study_by_id[sel_id]
        st.markdown(f"### 🟣 {cs['name_ko']}")
        st.markdown(f"*{cs['name']}*")
        threat_ids = kg._case_study_threats.get(sel_id, [])
        if threat_ids:
            badges = " ".join(_t_badge(tid) for tid in threat_ids)
            st.markdown(f"**관련 NIS 위협:** {badges}", unsafe_allow_html=True)
        st.markdown(f"[ATLAS 원문 →]({cs.get('url', '')})")
    # OWASP
    elif sel_id in kg._owasp_by_id:
        item = kg._owasp_by_id[sel_id]
        st.markdown(f"### {_owasp_badge(item['id'])} {item.get('name_ko', item['name'])}", unsafe_allow_html=True)
        st.markdown(f"*{item['name']}*")
        st.markdown(item.get("description", "")[:200] + "…" if len(item.get("description", "")) > 200 else item.get("description", ""))
        nis = kg.get_nis_for_owasp(sel_id)
        if nis["threats"]:
            st.markdown("**NIS 위협:** " + " ".join(_t_badge(t["id"]) for t in nis["threats"]), unsafe_allow_html=True)
        if nis["measures"]:
            st.markdown("**대응 대책:** " + " ".join(_m_badge(m["id"]) for m in nis["measures"]), unsafe_allow_html=True)
    # NIS Measure
    elif sel_id in kg._measure_by_id:
        item = kg._measure_by_id[sel_id]
        st.markdown(f"### {_m_badge(item['id'])} {item['name']}", unsafe_allow_html=True)
        st.markdown(item["description"])
        if item.get("details"):
            for d in item["details"]:
                st.markdown(f"- {d}")
        related = kg.get_threats_for_measure(sel_id)
        if related:
            st.markdown("**대응 위협:** " + " ".join(_t_badge(t["id"]) for t in related), unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════
# Helper: Build Sankey figure
# ═══════════════════════════════════════════════════════════
def _build_sankey(show_nis_pair: bool, show_ext_pair: bool):
    """Build and return a plotly Sankey figure."""
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
        for cs in kg.atlas_case_studies:
            threat_ids = kg._case_study_threats.get(cs["id"], [])
            if not threat_ids:
                continue
            src_label = f"{cs['id'][:8]} {_strip_ai(cs['name_ko'])}"
            for tid in threat_ids:
                t = kg.get_threat(tid)
                if t:
                    tgt_label = f"{t['id']} {_strip_ai(t['name'])}"
                    sources.append(_get_idx(src_label))
                    targets.append(_get_idx(tgt_label))
                    values.append(2)
                    link_colors.append("rgba(155,89,182,0.3)")

        for om in kg._owasp_mapping:
            o = kg.get_owasp(om["owasp_id"])
            if not o:
                continue
            tgt_label = f"{o['id']} {_strip_ai(o['name_ko'])}"
            for tid in om.get("threat_ids", []):
                t = kg.get_threat(tid)
                if t:
                    src_label = f"{t['id']} {_strip_ai(t['name'])}"
                    sources.append(_get_idx(src_label))
                    targets.append(_get_idx(tgt_label))
                    values.append(1)
                    link_colors.append("rgba(245,130,32,0.3)")

        for inc in kg.incidents:
            for tid in inc.get("threat_ids", []):
                t = kg.get_threat(tid)
                if t:
                    src_label = f"{t['id']} {_strip_ai(t['name'])}"
                    tgt_label = f"{inc['id']} {inc['title'][:12]}"
                    sources.append(_get_idx(src_label))
                    targets.append(_get_idx(tgt_label))
                    values.append(1)
                    link_colors.append("rgba(231,76,60,0.3)")

    node_colors = []
    for lbl in labels:
        if lbl.startswith("AML.CS"):
            node_colors.append("#9b59b6")
        elif lbl.startswith("AML."):
            node_colors.append("#7b2d8e")
        elif lbl.startswith("LLM"):
            node_colors.append("#f58220")
        elif lbl.startswith("INC"):
            node_colors.append("#e74c3c")
        elif lbl.startswith("T"):
            node_colors.append("#ed1c24")
        elif lbl.startswith("M") or lbl.startswith("A-M") or lbl.startswith("P-M"):
            node_colors.append("#2f55a5")
        else:
            node_colors.append("#888")

    if not sources:
        return None

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
    sankey_title = "NIS 위협 → 대책" if show_nis_pair else "ATLAS 사례연구 → NIS 위협 → OWASP / 사고사례"
    fig.update_layout(
        title=dict(text=sankey_title, font=dict(size=14)),
        height=800,
        margin=dict(l=10, r=10, t=40, b=10),
        font=dict(size=11, color="#000000"),
    )
    return fig


# ═══════════════════════════════════════════════════════════
# HTML Checklist Generator (module-level helper)
# ═══════════════════════════════════════════════════════════
def _generate_checklist_html(cl_build: str, cl_ai: str, result: dict) -> str:
    """Generate a standalone HTML checklist page."""
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    threat_rows = ""
    for t_ in result["threats"]:
        threat_rows += f'<tr><td><span class="badge badge-threat">{t_["id"]}</span></td><td><strong>{t_["name"]}</strong></td><td>{t_.get("risk","")}</td></tr>'
    checklist_rows = ""
    for m_ in result["measures"]:
        label = m_.get("checklist") or m_["name"]
        checklist_rows += f'<tr><td class="check-cell"><input type="checkbox" id="chk_{m_["id"]}"></td><td><label for="chk_{m_["id"]}"><span class="badge badge-measure">{m_["id"]}</span></label></td><td><label for="chk_{m_["id"]}">{label}</label></td></tr>'
    return f"""<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>K-AISecMap 체크리스트 — {cl_build} + {cl_ai}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Malgun Gothic','Apple SD Gothic Neo',sans-serif;font-size:14px;background:#f5f7fa;color:#1a1a2e;padding:24px}}
.page{{max-width:900px;margin:0 auto;background:#fff;border:2px solid #2f55a5;border-radius:10px;padding:32px 36px}}
.header{{border-bottom:3px solid #2f55a5;padding-bottom:16px;margin-bottom:20px}}
.header h1{{font-size:22px;color:#2f55a5;letter-spacing:-0.5px}}
.header h2{{font-size:15px;font-weight:normal;color:#555;margin-top:4px}}
.meta-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;background:#f0f4ff;border:1px solid #c5d3f5;border-radius:8px;padding:14px 18px;margin-bottom:20px}}
.meta-item label{{font-size:11px;color:#777;display:block;margin-bottom:2px}}
.meta-item span{{font-size:14px;font-weight:bold;color:#1a1a2e}}
.warning{{background:#fff8e1;border-left:4px solid #f0a500;border-radius:4px;padding:10px 14px;font-size:12px;color:#7a5c00;margin-bottom:24px;line-height:1.6}}
h3{{font-size:15px;color:#2f55a5;margin:20px 0 10px;padding-left:8px;border-left:4px solid #2f55a5}}
table{{width:100%;border-collapse:collapse;margin-bottom:8px;font-size:13px}}
th{{background:#2f55a5;color:#fff;padding:8px 10px;text-align:left;font-size:12px}}
td{{padding:8px 10px;border-bottom:1px solid #e8eaf0;vertical-align:top;line-height:1.5}}
tr:hover td{{background:#f5f7ff}}
.check-cell{{width:32px;text-align:center}}
input[type="checkbox"]{{width:16px;height:16px;cursor:pointer;accent-color:#2f55a5}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:12px;white-space:nowrap}}
.badge-threat{{background:#ed1c24;color:#fff}}.badge-measure{{background:#2f55a5;color:#fff}}
.footer{{margin-top:28px;padding-top:14px;border-top:1px solid #ddd;font-size:11px;color:#999;display:flex;justify-content:space-between}}
.sources{{font-size:11px;color:#777;margin-top:6px;line-height:1.7}}
@media print{{body{{background:white;padding:0}}.page{{border:1px solid #aaa;padding:20px}}tr:hover td{{background:none}}}}
</style></head><body><div class="page">
<div class="header"><h1>K-AISecMap — AI보안 체크리스트</h1><h2>국가·공공기관 AI보안 매핑 어드바이저 · AI Security Mapping Advisor</h2></div>
<div class="meta-grid">
<div class="meta-item"><label>구축 유형</label><span>{cl_build}</span></div>
<div class="meta-item"><label>AI 유형</label><span>{cl_ai}</span></div>
<div class="meta-item"><label>생성일시</label><span>{generated_at}</span></div>
<div class="meta-item"><label>버전</label><span>K-AISecMap v{APP_VERSION}</span></div>
<div class="meta-item"><label>위협 수</label><span>{len(result['threats'])}개</span></div>
<div class="meta-item"><label>대책 수</label><span>{len(result['measures'])}개</span></div>
</div>
<div class="warning">⚠️ <strong>실험적 서비스</strong> — 본 체크리스트는 연구·교육 목적의 비공식 자료이며 국가정보원(NIS)과 무관합니다.</div>
<h3>주요 보안위협</h3><table><thead><tr><th style="width:80px">위협 ID</th><th style="width:160px">위협명</th><th>위험 내용</th></tr></thead><tbody>{threat_rows}</tbody></table>
<h3>보안대책 체크리스트</h3><table><thead><tr><th class="check-cell">✓</th><th style="width:80px">대책 ID</th><th>점검 항목</th></tr></thead><tbody>{checklist_rows}</tbody></table>
<div class="sources"><strong>참고 출처:</strong><br>· NIS AI보안 가이드북 (2025.12) — <a href="https://www.nis.go.kr">www.nis.go.kr</a><br>· OWASP Top 10 for LLM Applications — <a href="https://genai.owasp.org/">genai.owasp.org</a><br>· MITRE ATLAS — <a href="https://atlas.mitre.org/">atlas.mitre.org</a></div>
<div class="footer"><span>K-AISecMap v{APP_VERSION} · {generated_at} · {cl_build} + {cl_ai}</span><span><a href="https://k-ai-sec.streamlit.app">k-ai-sec.streamlit.app</a> · <a href="https://github.com/sulgik/kais">github.com/sulgik/kais</a> · sulgik@gmail.com</span></div>
</div></body></html>"""


# ═══════════════════════════════════════════════════════════
# Page: Home
# ═══════════════════════════════════════════════════════════
if page == "home":

    # ── Description ────────────────────────────────────────
    st.markdown("""
<div style="background:#f8f9fa;border-radius:8px;padding:16px 20px;font-size:0.92rem;line-height:1.7;margin-bottom:16px;">
  본 웹페이지는 대한민국 국가정보원에서 발간한 <strong>「국가·공공기관 AI 보안 가이드북」</strong>과
  이와 관련된 문서들을 기반으로 AI 보안과 관련된 정보를 쉽게 찾아볼 수 있는 페이지입니다.<br>
  AI와 관련한 어떤 <strong>위협</strong>들이 있고, 관련된 <strong>사고 사례</strong>로는 어떤 것들이 있는지,
  그리고 각 위협은 어떻게 <strong>방어</strong>할 수 있는지 등을 알아볼 수 있습니다.
</div>
""", unsafe_allow_html=True)

    # ── 3-column framework cards ───────────────────────────
    col_nis, col_owasp, col_atlas = st.columns(3, gap="large")
    card_style = "border:1px solid #e5e5e5;border-radius:10px;padding:20px 18px;height:100%;"

    with col_nis:
        st.markdown(f"""
<div style="{card_style}border-top:4px solid #1a1a2e;">
  <div style="font-size:1.05rem;font-weight:800;color:#1a1a2e;">NIS AI보안 가이드북</div>
  <div style="font-size:0.78rem;color:#555;margin-bottom:10px;">국가정보원 · 2025년 12월</div>
</div>""", unsafe_allow_html=True)
        st.markdown("""
**보안위협 T01~T15** — 학습데이터 오염, 프롬프트 인젝션, 회피 공격 등 15개 유형
**보안대책 M01~M30 + A-M · P-M** — 공통 + 에이전틱·피지컬 AI 전용 대책
**구축유형별 가이드** — 내부망 / 외부망 / 대민서비스 / 상용 AI
""")

    with col_owasp:
        st.markdown(f"""
<div style="{card_style}border-top:4px solid #f58220;">
  <div style="font-size:1.05rem;font-weight:800;color:#f58220;">OWASP LLM Top 10</div>
  <div style="font-size:0.78rem;color:#555;margin-bottom:10px;">Open Worldwide Application Security Project · 2025</div>
</div>""", unsafe_allow_html=True)
        st.markdown("""
**LLM01** 프롬프트 인젝션 · **LLM02** 민감정보 노출 · **LLM03** 공급망
**LLM04** 데이터 오염 · **LLM05~10** 출력처리·권한·유출 등
NIS 위협·대책과 **양방향 교차 매핑** 제공
""")

    with col_atlas:
        st.markdown(f"""
<div style="{card_style}border-top:4px solid #7b2d8e;">
  <div style="font-size:1.05rem;font-weight:800;color:#7b2d8e;">MITRE ATLAS</div>
  <div style="font-size:0.78rem;color:#555;margin-bottom:10px;">Adversarial Threat Landscape for AI Systems</div>
</div>""", unsafe_allow_html=True)
        st.markdown(f"""
**{len(kg.atlas_tactics)}개 전술** — 공격 킬체인 각 단계
**{len(kg.atlas_techniques)}개 기법** — 구체적 공격 기법
NIS 위협(T##) ↔ ATLAS(AML.T####) ↔ OWASP(LLM##) **3자 교차 매핑**
""")

    st.divider()

    # ── Map section ────────────────────────────────────────
    st.markdown("### 🗺️ AI 보안 프레임워크 통합 지도")
    st.caption("노드를 클릭하면 오른쪽에 상세 정보가 표시됩니다. 드래그·스크롤로 탐색하세요.")

    # Filters
    filter_col1, filter_col2 = st.columns(2)
    with filter_col1:
        map_view = st.radio(
            "표시할 매핑",
            ["🔴 NIS 위협 ↔ 🟠 OWASP ↔ 🟣 ATLAS ↔ ⭐ 사고사례", "🔴 NIS 위협 ↔ 🔵 대책"],
            key="home_map_pair", horizontal=True, label_visibility="collapsed",
        )
    with filter_col2:
        viz_mode = st.radio(
            "시각화 모드",
            ["🕸️ 네트워크 그래프", "🌊 Sankey 흐름도"],
            key="home_viz_mode", horizontal=True, label_visibility="collapsed",
        )

    show_nis_pair = map_view.startswith("🔴 NIS 위협 ↔ 🔵")
    show_ext_pair = not show_nis_pair

    # Legend
    if show_nis_pair:
        st.markdown(
            '<span style="font-size:0.85em;">'
            '<span style="display:inline-block;width:12px;height:12px;background:#ed1c24;border-radius:50%;vertical-align:middle;"></span> <b>NIS 위협</b> &nbsp; '
            '<span style="display:inline-block;width:12px;height:12px;background:#2f55a5;transform:rotate(45deg);vertical-align:middle;"></span> <b>NIS 대책</b>'
            '</span>', unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<span style="font-size:0.85em;">'
            '<span style="display:inline-block;width:12px;height:12px;background:#ed1c24;border-radius:50%;vertical-align:middle;"></span> <b>NIS 위협</b> &nbsp; '
            '<span style="display:inline-block;width:12px;height:12px;background:#e74c3c;clip-path:polygon(50% 0%,61% 35%,98% 35%,68% 57%,79% 91%,50% 70%,21% 91%,32% 57%,2% 35%,39% 35%);vertical-align:middle;"></span> <b>NIS 사고사례</b> &nbsp; '
            '<span style="display:inline-block;width:0;height:0;border-left:7px solid transparent;border-right:7px solid transparent;border-bottom:12px solid #9b59b6;vertical-align:middle;"></span> <b>ATLAS 사례연구</b> &nbsp; '
            '<span style="display:inline-block;width:12px;height:12px;background:#f58220;vertical-align:middle;"></span> <b>OWASP</b>'
            '</span>', unsafe_allow_html=True,
        )

    # Graph + Detail side-by-side
    col_graph, col_detail = st.columns([3, 1])

    with col_graph:
        if viz_mode == "🕸️ 네트워크 그래프":
            try:
                from streamlit_agraph import agraph, Node, Edge, Config

                graph_data = kg.build_graph_data(
                    show_nis=True,
                    show_owasp=show_ext_pair,
                    show_measures=show_nis_pair,
                    show_incidents=show_ext_pair,
                    show_case_studies=show_ext_pair,
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
                    width="100%", height=750,
                    directed=False, physics=True, hierarchical=False,
                )

                selected = agraph(nodes=agraph_nodes, edges=agraph_edges, config=config)
                if selected:
                    st.session_state["home_selected"] = selected

            except ImportError:
                st.error("streamlit-agraph가 설치되지 않았습니다.")
        else:
            # Sankey
            fig = _build_sankey(show_nis_pair, show_ext_pair)
            if fig:
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("위에서 표시할 매핑을 선택하세요.")

    with col_detail:
        sel_id = st.session_state.get("home_selected")
        if sel_id:
            st.markdown("---")
            _render_node_detail(sel_id)
        else:
            st.markdown("""
<div style="background:#f0f4ff;border-radius:8px;padding:20px;text-align:center;color:#888;margin-top:40px;">
  <div style="font-size:2rem;">👈</div>
  <div style="font-size:0.85rem;margin-top:8px;">그래프에서 노드를 클릭하면<br>여기에 상세 정보가 표시됩니다</div>
</div>""", unsafe_allow_html=True)

    st.caption("참고 기준: NIST AI RMF · MITRE ATLAS · OWASP LLM Top 10 · NIS AI보안 가이드북(2025.12)")

# ═══════════════════════════════════════════════════════════
# Page: Knowledge Explorer
# ═══════════════════════════════════════════════════════════
elif page == "explorer":
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

# ═══════════════════════════════════════════════════════════
# Page: OWASP LLM Top 10
# ═══════════════════════════════════════════════════════════
elif page == "owasp":
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

# ═══════════════════════════════════════════════════════════
# Page: Incidents
# ═══════════════════════════════════════════════════════════
elif page == "incidents":
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

elif page == "checklist":
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

# ═══════════════════════════════════════════════════════════
# Page: MCP 연결
# ═══════════════════════════════════════════════════════════
elif page == "mcp":
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
