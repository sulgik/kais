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
GUIDE_FIGURES_DIR = Path(__file__).parent / "extracted_figures_ai_guide"

_GUIDE_FIG_FILES = {
    1: "figure_01_p009_AI시스템_개념도.png",
    2: "figure_02_p010_AI시스템의_발전.png",
    3: "figure_03_p011_사이버보안과_AI보안.png",
    4: "figure_04_p012_학습데이터_오염.png",
    5: "figure_05_p013_비인가_민감정보_학습.png",
    6: "figure_06_p014_AI_백도어_삽입.png",
    7: "figure_07_p014_학습데이터_추출.png",
    8: "figure_08_p015_학습데이터_비인가자_접근_사용자_A_B_구분없이_학습데이터_노출.png",
    9: "figure_09_p015_AI모델_추출.png",
    10: "figure_10_p016_민감정보_입력_유출.png",
    11: "figure_11_p016_프롬프트_인젝션.png",
    12: "figure_12_p017_회피_공격.png",
    13: "figure_13_p018_통신구간_공격.png",
    14: "figure_14_p018_서비스_거부_공격.png",
    15: "figure_15_p019_사고_이상행위_모니터링_체계_부재.png",
    16: "figure_16_p019_AI시스템_권한관리_부실.png",
    17: "figure_17_p020_공급망_공격.png",
    18: "figure_18_p020_용역업체_보안관리_부실.png",
    19: "figure_19_p023_AI시스템_수명주기.png",
    20: "figure_20_p027_수명주기별_주요_보안위협.png",
    21: "figure_21_p039_모니터링_M09_필터링_M13_및_입력_길이_형식_제한_M14.png",
    22: "figure_22_p041_민감_명령_승인_절차_마련_M20.png",
    23: "figure_23_p044_내부망_전용_AI시스템_개념도.png",
    24: "figure_24_p045_내부망_전용_AI시스템_활용_사례.png",
    25: "figure_25_p048_프롬프트웨어_PromptLock_사례.png",
    26: "figure_26_p049_내부업무용_AI시스템의_외부망_연계_개념도.png",
    27: "figure_27_p050_AI_신고접수시스템_구축_활용_사례.png",
    28: "figure_28_p053_대민서비스용_AI시스템의_내부망_연계_개념도.png",
    29: "figure_29_p054_기관_특화_정보검색_AI_챗봇_구축_활용_사례.png",
    30: "figure_30_p057_상용_AI서비스_활용_개념도.png",
    31: "figure_31_p058_공공기관_AI_비서_도입_활용_사례.png",
    32: "figure_32_p064_에이전틱_AI_개념도.png",
    33: "figure_33_p066_에이전틱_AI를_활용한_행정_원스톱_서비스_활용_예시.png",
    34: "figure_34_p073_AI_메모리_오염_및_무단_권한_침해_사례.png",
    35: "figure_35_p074_구성요소_취약점에_의한_악성행위_수행_사례.png",
    36: "figure_36_p075_피지컬_AI_개념도.png",
    37: "figure_37_p077_피지컬_AI를_활용한_현장설비_안전상태_진단_예시.png",
}

_bt_focuses_path = Path(__file__).parent / "data" / "build_type_focuses.json"
build_type_focuses = json.loads(_bt_focuses_path.read_text(encoding="utf-8")) if _bt_focuses_path.exists() else []

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


def _show_guide_fig(n: int, caption: str = "", width: int = 480):
    """Display a guide figure by its 1-based number from the PDF figure manifest."""
    fn = _GUIDE_FIG_FILES.get(n)
    if fn:
        p = GUIDE_FIGURES_DIR / fn
        if p.exists():
            st.image(str(p), width=width)
            if caption:
                st.caption(f"[그림 {n}] {caption}")


# ── Custom CSS for authoritative look ──────────────────────
st.markdown("""
<style>
/* Sidebar dark header */
[data-testid="stSidebar"] > div:first-child {
    background: linear-gradient(180deg, #0d1b2a 0%, #1b2838 100%);
}
[data-testid="stSidebar"] [data-testid="stMarkdown"] {
    color: #c8d6e5;
}
[data-testid="stSidebar"] hr {
    border-color: rgba(255,255,255,0.08);
}
/* Sidebar nav buttons */
[data-testid="stSidebar"] button {
    background: transparent !important;
    border: none !important;
    color: #c8d6e5 !important;
    text-align: left !important;
    font-size: 0.82rem !important;
    padding: 7px 12px !important;
    border-radius: 6px !important;
    transition: background 0.15s !important;
    justify-content: flex-start !important;
}
[data-testid="stSidebar"] button:hover {
    background: rgba(255,255,255,0.08) !important;
    color: #fff !important;
}
[data-testid="stSidebar"] button:focus {
    box-shadow: none !important;
}
/* Section headers in sidebar */
.sidebar-section {
    font-size: 0.6rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: #5a7a9a;
    padding: 14px 4px 4px;
    margin-top: 4px;
}
</style>
""", unsafe_allow_html=True)

# --- Sidebar (navigation) ---
with st.sidebar:
    st.markdown("""
<div style="padding:12px 0 8px;">
  <div style="font-size:1.4rem;font-weight:900;letter-spacing:-0.5px;color:#fff;">K-AISecMap</div>
  <div style="font-size:0.68rem;color:#5a7a9a;margin-top:4px;line-height:1.4;letter-spacing:0.5px;">
    AI Security Mapping Advisor
  </div>
</div>
""", unsafe_allow_html=True)

    st.divider()

    ALL_MENU = {
        "home": "홈",
        "guidebook": "📖 가이드북 (웹북)",
        "explorer": "NIS AI보안 가이드 — 위협·대책",
        "incidents": "사고 사례",
        "checklist": "체크리스트 생성기",
        "owasp": "OWASP LLM Top 10",
        "mcp": "MCP 연결",
    }

    # Check for card-based navigation
    nav_override = st.session_state.pop("_nav", None)
    if nav_override and nav_override in ALL_MENU:
        st.session_state["_page"] = nav_override

    current_page = st.session_state.get("_page", "home")

    def _nav_button(key, label, section=None):
        is_active = (current_page == key)
        if section:
            st.markdown(f'<div class="sidebar-section">{section}</div>', unsafe_allow_html=True)
        active_style = "background:rgba(47,85,165,0.3);color:#fff;font-weight:700;" if is_active else "color:#c8d6e5;"
        st.markdown(
            f'<div style="padding:7px 12px;border-radius:6px;font-size:0.82rem;cursor:pointer;{active_style}">{label}</div>',
            unsafe_allow_html=True
        )
        return st.button(label, key=f"nav_{key}", label_visibility="collapsed", use_container_width=True) if not is_active else False

    # Build nav with section headers using simple buttons
    st.markdown('<div class="sidebar-section">국내 기준</div>', unsafe_allow_html=True)
    for key in ["home", "guidebook", "explorer", "incidents", "checklist"]:
        if st.button(ALL_MENU[key], key=f"nav_{key}", use_container_width=True):
            st.session_state["_page"] = key
            st.rerun()

    st.markdown('<div class="sidebar-section">해외 기준</div>', unsafe_allow_html=True)
    for key in ["owasp"]:
        if st.button(ALL_MENU[key], key=f"nav_{key}", use_container_width=True):
            st.session_state["_page"] = key
            st.rerun()

    st.markdown('<div class="sidebar-section">도구</div>', unsafe_allow_html=True)
    for key in ["mcp"]:
        if st.button(ALL_MENU[key], key=f"nav_{key}", use_container_width=True):
            st.session_state["_page"] = key
            st.rerun()

    page = current_page

    st.divider()
    stats = kg.summary()
    st.markdown(
        f'<div style="font-size:0.7rem;color:#5a7a9a;line-height:1.8;padding:0 4px;">'
        f'{stats.get("total_threats",0)} NIS 위협 · {stats.get("atlas_techniques",0)} ATLAS 기법 · {stats.get("atlas_case_studies",0)} 사례연구<br>'
        f'{stats.get("total_measures",0)} 대책 · {stats.get("atlas_mitigations",0)} ATLAS 완화책 · {stats.get("nist_functions",0)} NIST 기능<br>'
        f'<a href="https://k-ai-sec.streamlit.app" style="color:#5a7a9a;">k-ai-sec.streamlit.app</a> · '
        f'<a href="https://github.com/sulgik/kais" style="color:#5a7a9a;">GitHub</a>'
        f'</div>', unsafe_allow_html=True
    )

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
    "**실험적 서비스 (Experimental)** — 연구·교육 목적의 비공식 서비스이며 국가정보원(NIS)과 무관합니다. "
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
        cs_ko = kg.atlas_name_ko(cs["id"])
        st.markdown(f"### 🟣 {cs_ko}")
        st.markdown(f"*{cs['name']}*")
        if cs.get("summary"):
            st.markdown(cs["summary"][:300] + "…" if len(cs.get("summary", "")) > 300 else cs.get("summary", ""))
        threat_ids = kg._case_study_threats.get(sel_id, [])
        if threat_ids:
            badges = " ".join(_t_badge(tid) for tid in threat_ids)
            st.markdown(f"**관련 NIS 위협:** {badges}", unsafe_allow_html=True)
        # Show techniques used
        if cs.get("technique_ids"):
            tech_names = [f"`{tid}` {kg.atlas_name_ko(tid)}" for tid in cs["technique_ids"]]
            st.markdown("**사용 기법:** " + " · ".join(tech_names))
        refs = cs.get("references", [])
        if refs:
            st.markdown(f"[ATLAS 원문 →]({refs[0]})")
        elif cs.get("url"):
            st.markdown(f"[ATLAS 원문 →]({cs['url']})")
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
            cs_ko = kg.atlas_name_ko(cs["id"])
            src_label = f"{cs['id'][:8]} {_strip_ai(cs_ko)}"
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

    # ── 3-column framework cards (with links) ───────────────
    col_nis, col_owasp, col_atlas = st.columns(3, gap="large")

    with col_nis:
        st.markdown("""
<div style="border:1px solid #d0d5dd;border-radius:10px;padding:20px 18px;border-top:4px solid #1a1a2e;">
  <div style="font-size:1.05rem;font-weight:800;color:#1a1a2e;">NIS AI보안 가이드북</div>
  <div style="font-size:0.75rem;color:#888;margin-bottom:10px;">국가정보원 · 2025년 12월</div>
  <div style="font-size:0.85rem;line-height:1.6;color:#444;">
    <b>보안위협 T01~T15</b> — 15개 AI 위협 유형<br>
    <b>보안대책 M01~M30 + A-M · P-M</b><br>
    <b>구축유형별</b> 내부망 / 외부망 / 대민 / 상용
  </div>
</div>""", unsafe_allow_html=True)
        lc1, lc2 = st.columns(2)
        with lc1:
            st.page_link("https://www.nis.go.kr", label="원문 보기", icon="🔗")
        with lc2:
            if st.button("위협·대책 보기", key="card_nis", use_container_width=True):
                st.session_state["_nav"] = "explorer"
                st.rerun()

    with col_owasp:
        st.markdown("""
<div style="border:1px solid #d0d5dd;border-radius:10px;padding:20px 18px;border-top:4px solid #f58220;">
  <div style="font-size:1.05rem;font-weight:800;color:#f58220;">OWASP LLM Top 10</div>
  <div style="font-size:0.75rem;color:#888;margin-bottom:10px;">OWASP · 2025</div>
  <div style="font-size:0.85rem;line-height:1.6;color:#444;">
    LLM 10대 취약점 — 프롬프트 인젝션,<br>
    민감정보 노출, 공급망, 데이터 오염 등<br>
    NIS 위협·대책과 <b>양방향 교차 매핑</b>
  </div>
</div>""", unsafe_allow_html=True)
        lc1, lc2 = st.columns(2)
        with lc1:
            st.page_link("https://genai.owasp.org/", label="원문 보기", icon="🔗")
        with lc2:
            if st.button("OWASP 매핑", key="card_owasp", use_container_width=True):
                st.session_state["_nav"] = "owasp"
                st.rerun()

    with col_atlas:
        st.markdown(f"""
<div style="border:1px solid #d0d5dd;border-radius:10px;padding:20px 18px;border-top:4px solid #7b2d8e;">
  <div style="font-size:1.05rem;font-weight:800;color:#7b2d8e;">MITRE ATLAS</div>
  <div style="font-size:0.75rem;color:#888;margin-bottom:10px;">Adversarial Threat Landscape for AI Systems</div>
  <div style="font-size:0.85rem;line-height:1.6;color:#444;">
    <b>{len(kg.atlas_tactics)}개 전술</b> · <b>{len(kg.atlas_techniques)}개 기법</b><br>
    NIS(T##) ↔ ATLAS(AML.T####) ↔ OWASP(LLM##)<br>
    <b>3자 교차 매핑</b> 제공
  </div>
</div>""", unsafe_allow_html=True)
        lc1, lc2 = st.columns(2)
        with lc1:
            st.page_link("https://atlas.mitre.org/", label="원문 보기", icon="🔗")
        with lc2:
            if st.button("위협 탐색", key="card_atlas", use_container_width=True):
                st.session_state["_nav"] = "explorer"
                st.rerun()

    st.divider()

    # ── Map section ────────────────────────────────────────
    st.markdown("""
<div style="font-size:1.15rem;font-weight:800;color:#1a1a2e;margin-bottom:4px;">
  AI 보안 프레임워크 통합 지도
</div>""", unsafe_allow_html=True)
    st.caption("노드를 클릭하면 오른쪽에 상세 정보가 표시됩니다. 드래그·스크롤로 탐색하세요.")

    # View selector
    MAP_VIEWS = [
        "NIS 사고사례 → 위협 → 대책",
        "NIS 위협 → 대책 (Sankey)",
        "NIS ↔ OWASP ↔ ATLAS 통합",
        "NIS 위협 → ATLAS → OWASP (3자 매핑)",
    ]
    map_view = st.radio(
        "지도 유형",
        MAP_VIEWS,
        key="home_map_view", horizontal=True, label_visibility="collapsed",
    )

    # Determine graph params based on selection
    use_sankey = ("Sankey" in map_view)

    if map_view == MAP_VIEWS[0]:
        # NIS 사고사례 → 위협 → 대책
        gp = dict(show_nis=True, show_owasp=False, show_measures=True,
                  show_incidents=True, show_case_studies=False)
        legend_html = (
            '<span style="display:inline-block;width:12px;height:12px;background:#e74c3c;clip-path:polygon(50% 0%,61% 35%,98% 35%,68% 57%,79% 91%,50% 70%,21% 91%,32% 57%,2% 35%,39% 35%);vertical-align:middle;"></span> <b>사고사례</b> &nbsp; '
            '<span style="display:inline-block;width:12px;height:12px;background:#ed1c24;border-radius:50%;vertical-align:middle;"></span> <b>NIS 위협</b> &nbsp; '
            '<span style="display:inline-block;width:12px;height:12px;background:#2f55a5;transform:rotate(45deg);vertical-align:middle;"></span> <b>NIS 대책</b>'
        )
    elif map_view == MAP_VIEWS[1]:
        # Sankey: 위협 → 대책
        gp = dict(show_nis=True, show_owasp=False, show_measures=True,
                  show_incidents=False, show_case_studies=False)
        legend_html = ""
    elif map_view == MAP_VIEWS[2]:
        # 통합
        gp = dict(show_nis=True, show_owasp=True, show_measures=False,
                  show_incidents=True, show_case_studies=True)
        legend_html = (
            '<span style="display:inline-block;width:12px;height:12px;background:#ed1c24;border-radius:50%;vertical-align:middle;"></span> <b>NIS 위협</b> &nbsp; '
            '<span style="display:inline-block;width:12px;height:12px;background:#e74c3c;clip-path:polygon(50% 0%,61% 35%,98% 35%,68% 57%,79% 91%,50% 70%,21% 91%,32% 57%,2% 35%,39% 35%);vertical-align:middle;"></span> <b>사고사례</b> &nbsp; '
            '<span style="display:inline-block;width:0;height:0;border-left:7px solid transparent;border-right:7px solid transparent;border-bottom:12px solid #9b59b6;vertical-align:middle;"></span> <b>ATLAS</b> &nbsp; '
            '<span style="display:inline-block;width:12px;height:12px;background:#f58220;vertical-align:middle;"></span> <b>OWASP</b>'
        )
    else:
        # 3자 매핑 — NIS + OWASP + ATLAS (no incidents, no measures)
        gp = dict(show_nis=True, show_owasp=True, show_measures=False,
                  show_incidents=False, show_case_studies=True)
        legend_html = (
            '<span style="display:inline-block;width:12px;height:12px;background:#ed1c24;border-radius:50%;vertical-align:middle;"></span> <b>NIS 위협</b> &nbsp; '
            '<span style="display:inline-block;width:0;height:0;border-left:7px solid transparent;border-right:7px solid transparent;border-bottom:12px solid #9b59b6;vertical-align:middle;"></span> <b>ATLAS</b> &nbsp; '
            '<span style="display:inline-block;width:12px;height:12px;background:#f58220;vertical-align:middle;"></span> <b>OWASP</b>'
        )

    if legend_html:
        st.markdown(f'<span style="font-size:0.82em;">{legend_html}</span>', unsafe_allow_html=True)

    # Graph + Detail side-by-side
    col_graph, col_detail = st.columns([3, 1])

    with col_graph:
        if use_sankey:
            fig = _build_sankey(show_nis_pair=True, show_ext_pair=False)
            if fig:
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("매핑 데이터가 없습니다.")
        else:
            try:
                from streamlit_agraph import agraph, Node, Edge, Config

                graph_data = kg.build_graph_data(**gp)

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
                        st.markdown(f"- {_atlas_badge(aid)} [{kg.atlas_name_ko(aid)}]({tech.get('url', '')}) — {tech['name']}", unsafe_allow_html=True)

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
# Page: Guidebook (PDF Navigator Style)
# ═══════════════════════════════════════════════════════════
elif page == "guidebook":
    st.markdown("""
<div style="padding:4px 0 12px;">
  <div style="font-size:1.45rem;font-weight:900;letter-spacing:-0.5px;color:#1a1a2e;">
    국가·공공기관 AI 보안 가이드북
  </div>
  <div style="font-size:0.78rem;color:#5a7a9a;margin-top:4px;">
    국가정보원 발간 (2025년 12월) · 인터랙티브 웹북
  </div>
</div>
""", unsafe_allow_html=True)

    LIFECYCLES = ["데이터 수집", "AI 학습", "AI시스템 구축", "AI시스템 운영", "AI시스템 폐기"]
    LC_SHORT = ["수집", "학습", "구축", "운영", "폐기"]

    tab_intro, tab_threats, tab_measures, tab_buildtype, tab_aitype = st.tabs([
        "1장 · AI시스템 이해",
        "2장 · 보안위협 T01~T15",
        "3장 · 보안대책 M01~M30+",
        "4장 · 구축유형별 가이드",
        "5장 · 특수 AI 유형",
    ])

    # ── 1장: AI시스템 이해 ────────────────────────────────────
    with tab_intro:
        st.markdown("### AI시스템이란?")
        st.markdown(
            "AI시스템은 학습 데이터를 기반으로 훈련된 AI 모델을 핵심으로, "
            "데이터 파이프라인·추론 엔진·사용자 인터페이스 등이 결합된 복합 시스템입니다."
        )
        _show_guide_fig(1, "AI시스템 개념도")

        st.divider()
        st.markdown("### AI시스템의 발전")
        st.markdown(
            "AI는 단순 분류·예측 모델에서 생성형 AI, 에이전틱 AI로 급격히 발전하며 "
            "공공 행정 전반에 활용되고 있습니다."
        )
        _show_guide_fig(2, "AI시스템의 발전")

        st.divider()
        st.markdown("### 사이버보안과 AI보안")
        st.markdown(
            "기존 사이버보안 위협이 AI시스템에도 적용되지만, "
            "학습데이터 오염·모델 추출 등 AI 고유 위협이 추가로 존재합니다."
        )
        _show_guide_fig(3, "사이버보안과 AI보안")

        st.divider()
        st.markdown("### AI시스템 수명주기")
        st.markdown(
            "AI시스템은 **데이터 수집 → AI 학습 → AI시스템 구축 → 운영 → 폐기** "
            "5단계 수명주기를 가지며, 각 단계마다 고유한 보안위협이 존재합니다."
        )
        _show_guide_fig(19, "AI시스템 수명주기")

    # ── 2장: 보안위협 T01~T15 ─────────────────────────────────
    with tab_threats:
        threats_list = kg.threats

        col_toc2, col_content2 = st.columns([1, 3], gap="large")

        with col_toc2:
            st.markdown(
                '<div style="font-size:0.68rem;font-weight:700;text-transform:uppercase;'
                'letter-spacing:1px;color:#5a7a9a;padding:4px 0 8px;">위협 목록</div>',
                unsafe_allow_html=True,
            )
            for t in threats_list:
                is_sel = st.session_state.get("guide_threat") == t["id"]
                btn_style = (
                    "background:rgba(237,28,36,0.10);color:#c0101a;font-weight:700;"
                    if is_sel else ""
                )
                if st.button(
                    f"{t['id']}  {t['name']}",
                    key=f"guide_t_{t['id']}",
                    use_container_width=True,
                    type="primary" if is_sel else "secondary",
                ):
                    st.session_state["guide_threat"] = t["id"]
                    st.session_state.pop("guide_show_matrix", None)
                    st.rerun()

            st.divider()
            if st.button("📊 수명주기 매트릭스", key="guide_matrix_btn", use_container_width=True):
                st.session_state["guide_show_matrix"] = True
                st.session_state.pop("guide_threat", None)
                st.rerun()

        with col_content2:
            show_matrix = st.session_state.get("guide_show_matrix", False)
            sel_threat_id = st.session_state.get("guide_threat")

            if show_matrix:
                st.markdown("#### 수명주기별 주요 보안위협")
                _show_guide_fig(20, "수명주기별 주요 보안위협")
                st.divider()
                lc_header = (
                    "<tr>"
                    "<th style='padding:6px 10px;text-align:left;'>ID</th>"
                    "<th style='padding:6px 10px;text-align:left;'>위협명</th>"
                    + "".join(f"<th style='padding:6px 8px;white-space:nowrap;'>{lc}</th>" for lc in LC_SHORT)
                    + "</tr>"
                )
                lc_rows = ""
                for t in threats_list:
                    lcs = t.get("lifecycles", [])
                    cells = "".join(
                        '<td style="text-align:center;color:#ed1c24;font-size:1.05em;font-weight:bold;">●</td>'
                        if LIFECYCLES[i] in lcs
                        else '<td style="text-align:center;color:#dde;">○</td>'
                        for i in range(len(LIFECYCLES))
                    )
                    lc_rows += (
                        f'<tr>'
                        f'<td style="padding:5px 8px;">{_t_badge(t["id"])}</td>'
                        f'<td style="padding:5px 8px;font-size:0.85em;white-space:nowrap;">{t["name"]}</td>'
                        f'{cells}'
                        f'</tr>'
                    )
                st.markdown(
                    f'<table style="border-collapse:collapse;width:100%;font-size:0.85em;margin-top:12px;">'
                    f'<thead style="background:#1a1a2e;color:white;">{lc_header}</thead>'
                    f'<tbody>{lc_rows}</tbody>'
                    f'</table>',
                    unsafe_allow_html=True,
                )

            elif sel_threat_id:
                t = kg.get_threat(sel_threat_id)
                if t:
                    tid_num = int(sel_threat_id[1:])  # T01→1, T15→15
                    fig_num = tid_num + 3             # T01→fig4, T15→fig18

                    st.markdown(f"### {_t_badge(t['id'])} {t['name']}", unsafe_allow_html=True)

                    lc_pills = " ".join(
                        f'<span style="background:#e8f0ff;color:#2f55a5;padding:2px 10px;'
                        f'border-radius:12px;font-size:0.78em;">{lc}</span>'
                        for lc in t.get("lifecycles", [])
                    )
                    st.markdown(f'<div style="margin-bottom:14px;">{lc_pills}</div>', unsafe_allow_html=True)

                    _show_guide_fig(fig_num, t["name"])

                    st.markdown(f"**정의**")
                    st.markdown(t.get("definition", ""))
                    st.markdown(f"**위험**")
                    st.markdown(t.get("risk", ""))

                    if t.get("examples"):
                        st.markdown("**사고 사례**")
                        for ex in t["examples"]:
                            st.markdown(f"> {ex}")

                    measures = kg.get_measures_for_threat(sel_threat_id)
                    owasp_list = kg.get_owasp_for_threat(sel_threat_id)
                    if measures or owasp_list:
                        st.divider()
                        c1, c2 = st.columns(2)
                        with c1:
                            if measures:
                                st.markdown("**관련 대책**")
                                st.markdown(
                                    " ".join(_m_badge(m["id"]) for m in measures),
                                    unsafe_allow_html=True,
                                )
                        with c2:
                            if owasp_list:
                                st.markdown("**OWASP 매핑**")
                                st.markdown(
                                    " ".join(_owasp_badge(o["id"]) for o in owasp_list),
                                    unsafe_allow_html=True,
                                )
            else:
                st.markdown("""
<div style="background:#f8f9fa;border-radius:10px;padding:48px 30px;text-align:center;color:#888;margin-top:20px;">
  <div style="font-size:2.2rem;margin-bottom:14px;">👈</div>
  <div style="font-size:0.9rem;line-height:1.7;">
    왼쪽 목록에서 위협을 선택하거나<br>
    <strong>수명주기 매트릭스</strong>를 확인하세요
  </div>
</div>
""", unsafe_allow_html=True)

    # ── 3장: 보안대책 ──────────────────────────────────────────
    with tab_measures:
        m_basic = sorted(
            [m for m in kg.measures if m["id"].startswith("M") and not m["id"].startswith("M0") or
             (m["id"].startswith("M") and not m["id"].startswith("A-") and not m["id"].startswith("P-"))],
            key=lambda x: int(re.findall(r'\d+', x["id"])[0]),
        )
        # Safer filter: anything starting with "M" but not "A-M" or "P-M"
        m_basic = sorted(
            [m for m in kg.measures if re.match(r'^M\d', m["id"])],
            key=lambda x: int(re.findall(r'\d+', x["id"])[0]),
        )
        m_agentic = sorted(
            [m for m in kg.measures if m["id"].startswith("A-M")],
            key=lambda x: int(re.findall(r'\d+', x["id"])[0]),
        )
        m_physical = sorted(
            [m for m in kg.measures if m["id"].startswith("P-M")],
            key=lambda x: int(re.findall(r'\d+', x["id"])[0]),
        )

        msearch = st.text_input(
            "대책 검색 (키워드)",
            key="guide_msearch",
            placeholder="예: 모니터링, 암호화, 접근제어, 프롬프트 …",
        )

        def _filter_m(lst):
            if not msearch:
                return lst
            q = msearch.lower()
            return [
                m for m in lst
                if q in m["name"].lower() or q in m.get("description", "").lower()
            ]

        def _render_measure_expander(m, shown_figs: set):
            with st.expander(f"{m['id']} — {m['name']}"):
                st.markdown(m.get("description", ""))
                if m.get("details"):
                    for d in m["details"]:
                        st.markdown(f"- {d}")
                if m.get("checklist"):
                    st.info(f"✅ **체크리스트 항목**: {m['checklist']}")
                # Inline figures for specific measures
                if m["id"] in ("M09", "M13", "M14") and 21 not in shown_figs:
                    _show_guide_fig(21, "모니터링(M09), 필터링(M13), 입력 길이·형식 제한(M14)")
                    shown_figs.add(21)
                if m["id"] == "M20" and 22 not in shown_figs:
                    _show_guide_fig(22, "민감 명령 승인 절차 마련(M20)")
                    shown_figs.add(22)
                related = kg.get_threats_for_measure(m["id"])
                if related:
                    st.markdown(
                        "**대응 위협:** " + " ".join(_t_badge(t["id"]) for t in related),
                        unsafe_allow_html=True,
                    )

        shown_figs: set = set()

        st.markdown(f"#### NIS 기본 대책 (M01~M{len(m_basic):02d})")
        st.caption(f"공공기관 AI시스템 전반에 적용되는 {len(m_basic)}개 보안대책")
        for m in _filter_m(m_basic):
            _render_measure_expander(m, shown_figs)

        if m_agentic:
            st.divider()
            st.markdown("#### 에이전틱 AI 대책 (A-M)")
            st.caption(f"에이전틱 AI 전용 {len(m_agentic)}개 추가 대책")
            for m in _filter_m(m_agentic):
                _render_measure_expander(m, shown_figs)

        if m_physical:
            st.divider()
            st.markdown("#### 피지컬 AI 대책 (P-M)")
            st.caption(f"피지컬 AI 전용 {len(m_physical)}개 추가 대책")
            for m in _filter_m(m_physical):
                _render_measure_expander(m, shown_figs)

    # ── 4장: 구축유형별 가이드 ────────────────────────────────
    with tab_buildtype:
        BUILD_CONFIGS = [
            {
                "key": "내부망 전용 AI시스템",
                "concept_fig": 23, "usecase_fig": 24,
                "extra_figs": [],
                "desc": (
                    "외부 인터넷과 완전히 분리된 내부망에서만 운용되는 AI시스템. "
                    "내부 행정자료 기반 생성형 AI, 내부 문서 검색 AI 등에 적용되며, "
                    "데이터 유출 차단이 가장 핵심 보안 목표입니다."
                ),
                "page_range": "pp. 43–46",
            },
            {
                "key": "내부업무용 AI시스템의 외부망 연계",
                "concept_fig": 26, "usecase_fig": 27,
                "extra_figs": [(25, "프롬프트웨어 PromptLock 사례")],
                "desc": (
                    "내부 업무에 AI를 활용하되 외부 인터넷과 연계가 필요한 시스템. "
                    "외부 최신 정보 검색·RAG 보강 등에 사용됩니다. "
                    "외부 연계 지점에서의 프롬프트 인젝션·공급망 공격이 주요 위협입니다."
                ),
                "page_range": "pp. 47–51",
            },
            {
                "key": "대민서비스용 AI시스템의 내부망 연계",
                "concept_fig": 28, "usecase_fig": 29,
                "extra_figs": [],
                "desc": (
                    "일반 국민 대상 서비스를 제공하는 AI시스템. "
                    "AI 민원 챗봇, 정보 제공 서비스 등에 적용됩니다. "
                    "불특정 다수 사용자로부터의 악의적 입력 차단이 핵심입니다."
                ),
                "page_range": "pp. 52–55",
            },
            {
                "key": "상용 AI서비스 활용",
                "concept_fig": 30, "usecase_fig": 31,
                "extra_figs": [],
                "desc": (
                    "ChatGPT·Claude 등 민간 상용 AI 서비스를 공공업무에 직접 활용하는 형태. "
                    "업무 민감정보 외부 유출 방지와 상용 서비스 약관·보안 정책 검토가 필수입니다."
                ),
                "page_range": "pp. 56–59",
            },
        ]

        bt_tabs = st.tabs([
            f"① 내부망 전용",
            f"② 외부망 연계",
            f"③ 대민서비스",
            f"④ 상용 AI",
        ])

        for bt_tab, bc in zip(bt_tabs, BUILD_CONFIGS):
            with bt_tab:
                st.markdown(f"#### {bc['key']}")
                st.caption(bc["page_range"])
                st.markdown(bc["desc"])

                col_concept, col_case = st.columns(2)
                with col_concept:
                    st.markdown("**개념도**")
                    _show_guide_fig(bc["concept_fig"])
                with col_case:
                    st.markdown("**활용 사례**")
                    _show_guide_fig(bc["usecase_fig"])

                for fig_n, fig_cap in bc.get("extra_figs", []):
                    st.divider()
                    _show_guide_fig(fig_n, fig_cap)

                focus = next(
                    (f for f in build_type_focuses if f["build_type"] == bc["key"]),
                    None,
                )
                if focus:
                    st.divider()
                    c1, c2 = st.columns(2)
                    with c1:
                        st.markdown("**중점 보안위협**")
                        st.markdown(
                            " ".join(_t_badge(tid) for tid in focus.get("priority_threats", [])),
                            unsafe_allow_html=True,
                        )
                    with c2:
                        st.markdown("**적용 보안대책**")
                        st.markdown(
                            " ".join(_m_badge(mid) for mid in focus.get("priority_measures", [])),
                            unsafe_allow_html=True,
                        )

    # ── 5장: 특수 AI 유형 ─────────────────────────────────────
    with tab_aitype:
        st.markdown("### 에이전틱 AI (Agentic AI)")
        st.markdown("""
에이전틱 AI는 자율적으로 목표를 설정하고, 다수의 도구·외부 시스템을 연계하며,
순차적 또는 병렬로 작업을 수행하는 AI시스템입니다.
기존 챗봇 형태보다 훨씬 넓은 권한과 자율성을 가지므로 특별한 보안 고려가 필요합니다.
""")
        col_a1, col_a2 = st.columns(2)
        with col_a1:
            _show_guide_fig(32, "에이전틱 AI 개념도")
        with col_a2:
            _show_guide_fig(33, "에이전틱 AI를 활용한 행정 원스톱 서비스")

        st.markdown("**에이전틱 AI 주요 보안 위협 사례**")
        col_a3, col_a4 = st.columns(2)
        with col_a3:
            _show_guide_fig(34, "AI 메모리 오염 및 무단 권한 침해 사례")
        with col_a4:
            _show_guide_fig(35, "구성요소 취약점에 의한 악성행위 수행 사례")

        # A-M measures summary
        a_measures = sorted(
            [m for m in kg.measures if m["id"].startswith("A-M")],
            key=lambda x: int(re.findall(r'\d+', x["id"])[0]),
        )
        if a_measures:
            with st.expander(f"에이전틱 AI 전용 보안대책 {len(a_measures)}개 보기"):
                for m in a_measures:
                    st.markdown(
                        f"**{_m_badge(m['id'])}** {m['name']}  \n{m.get('description','')}",
                        unsafe_allow_html=True,
                    )
                    st.markdown("---")

        st.divider()
        st.markdown("### 피지컬 AI (Physical AI)")
        st.markdown("""
피지컬 AI는 물리적 환경과 상호작용하는 AI시스템으로, 로봇·드론·자율주행 차량·
제조 자동화 장비 등에 탑재됩니다.
오동작 시 인적·물적 피해가 직접 발생할 수 있어 높은 수준의 안전·보안 설계가 요구됩니다.
""")
        col_p1, col_p2 = st.columns(2)
        with col_p1:
            _show_guide_fig(36, "피지컬 AI 개념도")
        with col_p2:
            _show_guide_fig(37, "피지컬 AI를 활용한 현장설비 안전상태 진단 예시")

        p_measures = sorted(
            [m for m in kg.measures if m["id"].startswith("P-M")],
            key=lambda x: int(re.findall(r'\d+', x["id"])[0]),
        )
        if p_measures:
            with st.expander(f"피지컬 AI 전용 보안대책 {len(p_measures)}개 보기"):
                for m in p_measures:
                    st.markdown(
                        f"**{_m_badge(m['id'])}** {m['name']}  \n{m.get('description','')}",
                        unsafe_allow_html=True,
                    )
                    st.markdown("---")

    st.caption("참고: 국가정보원 「국가·공공기관 AI 보안 가이드북」 (2025.12)")


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
