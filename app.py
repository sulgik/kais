"""
KAIS - K-AI Security Advisor
Streamlit Web UI
"""
import json
import re
from pathlib import Path
import streamlit as st
from knowledge_graph import SecurityKnowledgeGraph
from advisor import advise, build_context

st.set_page_config(
    page_title="KAIS - 국가·공공기관 AI보안 어드바이저",
    page_icon="🛡️",
    layout="wide",
)

# --- Init ---
@st.cache_resource
def load_kg():
    return SecurityKnowledgeGraph()

@st.cache_data
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

    api_key = st.text_input("Anthropic API Key", type="password", help="Claude API 키를 입력하세요")

    st.divider()
    st.subheader("🎯 컨텍스트 필터")

    build_type = st.selectbox(
        "구축 유형",
        options=["전체", "내부망 전용", "외부망 연계", "대민서비스", "상용 AI서비스"],
        index=0,
    )

    ai_type = st.selectbox(
        "AI 유형",
        options=["전체", "생성형 AI", "에이전틱 AI", "피지컬 AI"],
        index=0,
    )

    lifecycle = st.selectbox(
        "수명주기 단계",
        options=["전체", "데이터 수집", "AI 학습", "AI시스템 구축", "AI시스템 운영", "AI시스템 폐기"],
        index=0,
    )

    st.divider()
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
st.markdown("## 🛡️ 국가·공공기관 AI보안 어드바이저")
st.markdown("# KAIS — K-AI Security Advisor")
st.caption("NIS AI보안 가이드북 기반 · 안전한 AI시스템 도입·활용을 위한 보안 안내 시스템")

st.warning(
    """**⚠️ 실험적 서비스 안내 (Experimental)**

- 본 서비스는 연구·교육 목적의 **비공식 실험 서비스**이며, 국가정보원(NIS)과 무관합니다.
- AI 보안을 안내하는 서비스이지만, **본 서비스 자체도 보안 취약점을 가질 수 있습니다.** 민감한 기관 정보나 업무 데이터를 입력하지 마세요.
- 입력한 질문은 Anthropic Claude API를 통해 처리됩니다. 본인의 API 키와 입력 내용에 대한 책임은 사용자에게 있습니다.
- 답변은 NIS AI보안 가이드북(2025.12)을 기반으로 생성되며, 공식 보안 검토를 대체하지 않습니다.
""",
    icon="⚠️",
)

# --- Tabs ---
tab_explorer, tab_owasp, tab_incidents, tab_checklist, tab_advisor = st.tabs(
    ["🔍 지식 탐색", "🌐 OWASP LLM Top 10", "🔥 사고 사례", "✅ 체크리스트", "💬 어드바이저"]
)

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
    else:
        st.info("사고 사례 데이터가 없습니다.")

# --- Tab 3: Checklist Generator ---
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

# --- Tab 4: Advisor (Chat) ---
with tab_advisor:
    if "messages" not in st.session_state:
        st.session_state.messages = []

    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    if prompt := st.chat_input("AI 보안에 대해 질문하세요 (예: 에이전틱 AI 도입 시 주의사항은?)"):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        if not api_key:
            with st.chat_message("assistant"):
                st.warning("사이드바에서 Anthropic API Key를 입력해주세요.")
            st.session_state.messages.append({"role": "assistant", "content": "⚠️ API Key가 필요합니다."})
        else:
            with st.chat_message("assistant"):
                with st.spinner("NIS 가이드북을 기반으로 답변 생성 중..."):
                    bt = None if build_type == "전체" else build_type
                    at = None if ai_type == "전체" else ai_type
                    lc = None if lifecycle == "전체" else lifecycle

                    response = advise(
                        user_query=prompt,
                        kg=kg,
                        build_type=bt,
                        ai_type=at,
                        lifecycle=lc,
                        api_key=api_key,
                    )
                    st.markdown(response)
            st.session_state.messages.append({"role": "assistant", "content": response})
