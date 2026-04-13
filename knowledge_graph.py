"""
K-AISecMap Knowledge Graph Query Engine
Loads structured JSON data and provides multi-dimensional queries.
Integrates: NIS AI보안 가이드북, MITRE ATLAS, OWASP LLM Top 10, NIST AI RMF
"""
import json
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"


def _safe_load(path: Path) -> list | dict:
    if path.exists():
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return []


class SecurityKnowledgeGraph:
    def __init__(self, data_dir: Path = DATA_DIR):
        # ── NIS (한국 특화) ───────────────────────────────────
        self.threats = _safe_load(data_dir / "threats.json") or []
        self.measures = _safe_load(data_dir / "measures.json") or []
        self.links = _safe_load(data_dir / "threat_measure_links.json") or []
        self.build_types = _safe_load(data_dir / "build_type_focuses.json") or []
        self.incidents = _safe_load(data_dir / "incidents.json") or []

        # ── OWASP LLM Top 10 ─────────────────────────────────
        self.owasp = _safe_load(data_dir / "owasp_llm.json") or []
        self._owasp_mapping = _safe_load(data_dir / "owasp_nis_mapping.json") or []
        self._owasp_by_id = {o["id"]: o for o in self.owasp}
        self._owasp_map_by_id = {m["owasp_id"]: m for m in self._owasp_mapping}

        # ── MITRE ATLAS (individual files from aisecmap) ──────
        self.atlas_tactics = _safe_load(data_dir / "atlas_tactics.json") or []
        self.atlas_techniques = _safe_load(data_dir / "atlas_techniques.json") or []
        self.atlas_mitigations = _safe_load(data_dir / "atlas_mitigations.json") or []
        self.atlas_case_studies = _safe_load(data_dir / "atlas_case_studies.json") or []
        self._atlas_ko = _safe_load(data_dir / "atlas_ko.json") or {}
        self._atlas_tactic_by_id = {t["id"]: t for t in self.atlas_tactics}
        self._atlas_tech_by_id = {t["id"]: t for t in self.atlas_techniques}
        self._atlas_mit_by_id = {m["id"]: m for m in self.atlas_mitigations}

        # ATLAS → NIS mapping
        self._atlas_mapping = _safe_load(data_dir / "atlas_nis_mapping.json") or []
        self._atlas_map_by_id = {m["atlas_id"]: m for m in self._atlas_mapping}
        self._atlas_for_threat = {}
        for am in self._atlas_mapping:
            for tid in am.get("threat_ids", []):
                self._atlas_for_threat.setdefault(tid, []).append(am["atlas_id"])

        # ATLAS technique → mitigations (from mitigation.technique_ids)
        self._mits_for_technique = {}
        for m in self.atlas_mitigations:
            for tid in m.get("technique_ids", []):
                self._mits_for_technique.setdefault(tid, []).append(m["id"])

        # ATLAS technique → case studies
        self._cs_for_technique = {}
        for cs in self.atlas_case_studies:
            for tid in cs.get("technique_ids", []):
                self._cs_for_technique.setdefault(tid, []).append(cs["id"])

        # ── Cross-framework mapping (OWASP → ATLAS → NIST) ───
        self._cross_mapping = _safe_load(data_dir / "cross_mapping.json") or []
        self._xmap_by_owasp = {x["owasp_id"]: x for x in self._cross_mapping}

        # ── NIST AI RMF ──────────────────────────────────────
        self.nist = _safe_load(data_dir / "nist_ai_rmf.json") or []
        self._nist_by_id = {f["id"]: f for f in self.nist}

        # ── NIS indexes ──────────────────────────────────────
        self._threat_by_id = {t["id"]: t for t in self.threats}
        self._measure_by_id = {m["id"]: m for m in self.measures}
        self._measures_for_threat = {}
        self._threats_for_measure = {}
        for link in self.links:
            self._measures_for_threat.setdefault(link["threat_id"], []).append(link["measure_id"])
            self._threats_for_measure.setdefault(link["measure_id"], []).append(link["threat_id"])

        # NIS Incidents
        self._incident_by_id = {i["id"]: i for i in self.incidents}
        self._incidents_for_threat = {}
        for inc in self.incidents:
            for tid in inc.get("threat_ids", []):
                self._incidents_for_threat.setdefault(tid, []).append(inc["id"])

        # ATLAS Case Studies → NIS threats (via technique → atlas_nis_mapping)
        self._case_study_by_id = {cs["id"]: cs for cs in self.atlas_case_studies}
        self._case_study_threats = {}
        for cs in self.atlas_case_studies:
            threat_ids = set()
            for tech_id in cs.get("technique_ids", []):
                mapping = self._atlas_map_by_id.get(tech_id, {})
                for tid in mapping.get("threat_ids", []):
                    threat_ids.add(tid)
            self._case_study_threats[cs["id"]] = sorted(threat_ids)

    # === Query by threat ===
    def get_threat(self, threat_id: str) -> dict | None:
        return self._threat_by_id.get(threat_id)

    def get_measures_for_threat(self, threat_id: str) -> list[dict]:
        measure_ids = self._measures_for_threat.get(threat_id, [])
        return [self._measure_by_id[mid] for mid in measure_ids if mid in self._measure_by_id]

    # === Query by measure ===
    def get_measure(self, measure_id: str) -> dict | None:
        return self._measure_by_id.get(measure_id)

    def get_threats_for_measure(self, measure_id: str) -> list[dict]:
        threat_ids = self._threats_for_measure.get(measure_id, [])
        return [self._threat_by_id[tid] for tid in threat_ids if tid in self._threat_by_id]

    # === Query by lifecycle ===
    def get_threats_by_lifecycle(self, lifecycle: str) -> list[dict]:
        return [t for t in self.threats if lifecycle in t.get("lifecycles", [])]

    # === Query by build type ===
    def get_focus_for_build_type(self, build_type: str) -> dict | None:
        for bt in self.build_types:
            if build_type in bt["build_type"]:
                return bt
        return None

    def get_priority_threats_for_build_type(self, build_type: str) -> list[dict]:
        focus = self.get_focus_for_build_type(build_type)
        if not focus:
            return []
        return [self._threat_by_id[tid] for tid in focus["priority_threats"] if tid in self._threat_by_id]

    def get_priority_measures_for_build_type(self, build_type: str) -> list[dict]:
        focus = self.get_focus_for_build_type(build_type)
        if not focus:
            return []
        return [self._measure_by_id[mid] for mid in focus["priority_measures"] if mid in self._measure_by_id]

    # === Query by AI type ===
    def get_measures_by_ai_type(self, ai_type: str | None = None) -> list[dict]:
        return [m for m in self.measures if m.get("ai_type") == ai_type]

    # === Composite query: context-aware ===
    def query_by_context(
        self,
        build_type: str | None = None,
        ai_type: str | None = None,
        lifecycle: str | None = None,
    ) -> dict:
        '''
        Multi-dimensional query: given context, return relevant threats + measures.
        '''
        result_threats = set()
        result_measures = set()

        # Filter by build type
        if build_type:
            focus = self.get_focus_for_build_type(build_type)
            if focus:
                result_threats.update(focus["priority_threats"])
                result_measures.update(focus["priority_measures"])

        # Filter by lifecycle
        if lifecycle:
            lifecycle_threats = self.get_threats_by_lifecycle(lifecycle)
            lifecycle_threat_ids = {t["id"] for t in lifecycle_threats}
            if result_threats:
                result_threats &= lifecycle_threat_ids
            else:
                result_threats = lifecycle_threat_ids

        # Add measures for filtered threats (if not already from build_type)
        if result_threats and not build_type:
            for tid in result_threats:
                result_measures.update(self._measures_for_threat.get(tid, []))

        # Add AI-type specific measures
        if ai_type:
            type_measures = self.get_measures_by_ai_type(ai_type)
            result_measures.update(m["id"] for m in type_measures)

        # If no filters applied, return everything
        if not any([build_type, ai_type, lifecycle]):
            return {
                "threats": self.threats,
                "measures": self.measures,
            }

        threats = [self._threat_by_id[tid] for tid in sorted(result_threats) if tid in self._threat_by_id]
        measures = [self._measure_by_id[mid] for mid in sorted(result_measures) if mid in self._measure_by_id]

        return {
            "threats": threats,
            "measures": measures,
            "context": {
                "build_type": build_type,
                "ai_type": ai_type,
                "lifecycle": lifecycle,
            }
        }

    # === OWASP queries ===
    def get_owasp(self, owasp_id: str) -> dict | None:
        return self._owasp_by_id.get(owasp_id)

    def get_nis_for_owasp(self, owasp_id: str) -> dict:
        mapping = self._owasp_map_by_id.get(owasp_id, {})
        threat_ids = mapping.get("threat_ids", [])
        measure_ids = mapping.get("measure_ids", [])
        return {
            "threats": [self._threat_by_id[tid] for tid in threat_ids if tid in self._threat_by_id],
            "measures": [self._measure_by_id[mid] for mid in measure_ids if mid in self._measure_by_id],
        }

    def get_owasp_for_threat(self, threat_id: str) -> list[dict]:
        result = []
        for m in self._owasp_mapping:
            if threat_id in m.get("threat_ids", []):
                owasp = self._owasp_by_id.get(m["owasp_id"])
                if owasp:
                    result.append(owasp)
        return result

    # === ATLAS queries ===
    def get_atlas_technique(self, technique_id: str) -> dict | None:
        return self._atlas_tech_by_id.get(technique_id)

    def get_atlas_tactic(self, tactic_id: str) -> dict | None:
        return self._atlas_tactic_by_id.get(tactic_id)

    def get_atlas_for_threat(self, threat_id: str) -> list[dict]:
        atlas_ids = self._atlas_for_threat.get(threat_id, [])
        return [self._atlas_tech_by_id[aid] for aid in atlas_ids if aid in self._atlas_tech_by_id]

    def get_threats_for_atlas(self, atlas_id: str) -> list[dict]:
        mapping = self._atlas_map_by_id.get(atlas_id, {})
        return [self._threat_by_id[tid] for tid in mapping.get("threat_ids", []) if tid in self._threat_by_id]

    def get_atlas_mapping(self, atlas_id: str) -> dict | None:
        return self._atlas_map_by_id.get(atlas_id)

    def search_atlas(self, keyword: str) -> list[dict]:
        kw = keyword.lower()
        results = []
        for t in self.atlas_techniques:
            ko = self._atlas_ko.get("techniques", {}).get(t["id"], {})
            searchable = " ".join([t["name"], ko.get("name", ""), t.get("description", "")]).lower()
            if kw in searchable:
                results.append(t)
        return results

    # === ATLAS mitigation queries ===
    def get_atlas_mitigation(self, mid: str) -> dict | None:
        return self._atlas_mit_by_id.get(mid)

    def get_mitigations_for_technique(self, tech_id: str) -> list[dict]:
        mids = self._mits_for_technique.get(tech_id, [])
        return [self._atlas_mit_by_id[m] for m in mids if m in self._atlas_mit_by_id]

    def get_case_studies_for_technique(self, tech_id: str) -> list[dict]:
        csids = self._cs_for_technique.get(tech_id, [])
        return [self._case_study_by_id[c] for c in csids if c in self._case_study_by_id]

    # === NIST AI RMF queries ===
    def get_nist(self, nist_id: str) -> dict | None:
        return self._nist_by_id.get(nist_id)

    def get_nist_for_owasp(self, owasp_id: str) -> list[dict]:
        xmap = self._xmap_by_owasp.get(owasp_id, {})
        return [self._nist_by_id[nid] for nid in xmap.get("nist_categories", [])
                if nid in self._nist_by_id]

    def get_atlas_for_owasp(self, owasp_id: str) -> list[dict]:
        """Get ATLAS techniques mapped to an OWASP item (via cross_mapping)."""
        xmap = self._xmap_by_owasp.get(owasp_id, {})
        return [self._atlas_tech_by_id[tid] for tid in xmap.get("atlas_technique_ids", [])
                if tid in self._atlas_tech_by_id]

    # === Korean name helpers ===
    def atlas_name_ko(self, atlas_id: str) -> str:
        """Get Korean name for any ATLAS ID (technique, tactic, mitigation, case study)."""
        for category in ["techniques", "tactics", "mitigations"]:
            entry = self._atlas_ko.get(category, {}).get(atlas_id, {})
            if entry:
                return entry.get("name", atlas_id)
        # Case studies — use English name (no Korean in atlas_ko)
        cs = self._case_study_by_id.get(atlas_id)
        if cs:
            return cs["name"]
        return atlas_id

    def get_cross_framework(self, item_id: str) -> dict:
        """Unified cross-framework lookup by any ID (T##, LLM##, AML.T####)."""
        result = {"id": item_id, "framework": None, "item": None, "nis_threats": [], "nis_measures": [], "owasp": [], "atlas": []}

        # NIS Threat
        if item_id in self._threat_by_id:
            t = self._threat_by_id[item_id]
            result["framework"] = "NIS"
            result["item"] = t
            result["nis_measures"] = self.get_measures_for_threat(item_id)
            result["owasp"] = self.get_owasp_for_threat(item_id)
            result["atlas"] = self.get_atlas_for_threat(item_id)
            return result

        # OWASP
        if item_id in self._owasp_by_id:
            o = self._owasp_by_id[item_id]
            result["framework"] = "OWASP"
            result["item"] = o
            nis = self.get_nis_for_owasp(item_id)
            result["nis_threats"] = nis["threats"]
            result["nis_measures"] = nis["measures"]
            # Find linked ATLAS via NIS threats
            atlas_ids = set()
            for t in nis["threats"]:
                for aid in self._atlas_for_threat.get(t["id"], []):
                    atlas_ids.add(aid)
            result["atlas"] = [self._atlas_tech_by_id[aid] for aid in atlas_ids if aid in self._atlas_tech_by_id]
            return result

        # ATLAS
        if item_id in self._atlas_tech_by_id:
            tech = self._atlas_tech_by_id[item_id]
            mapping = self._atlas_map_by_id.get(item_id, {})
            result["framework"] = "ATLAS"
            result["item"] = tech
            result["nis_threats"] = [self._threat_by_id[tid] for tid in mapping.get("threat_ids", []) if tid in self._threat_by_id]
            result["nis_measures"] = [self._measure_by_id[mid] for mid in mapping.get("measure_ids", []) if mid in self._measure_by_id]
            result["owasp"] = [self._owasp_by_id[oid] for oid in mapping.get("owasp_ids", []) if oid in self._owasp_by_id]
            return result

        return result

    def build_graph_data(self, show_nis: bool = True, show_owasp: bool = True,
                         show_measures: bool = False, show_incidents: bool = True,
                         show_case_studies: bool = True) -> dict:
        """Build nodes and edges for streamlit-agraph visualization."""
        nodes = []
        edges = []
        seen_nodes = set()

        def _add_node(nid, label, color, shape, size, group, title=""):
            if nid not in seen_nodes:
                seen_nodes.add(nid)
                nodes.append({
                    "id": nid, "label": label, "color": color,
                    "shape": shape, "size": size, "group": group, "title": title,
                })

        def _strip_ai(s):
            return s.replace('AI ', '').replace('AI', '')

        # NIS Threats (central hub)
        if show_nis:
            for t in self.threats:
                _add_node(t["id"], f"{t['id']}\n{_strip_ai(t['name'])}", "#ed1c24", "dot", 25, "NIS 위협", t["name"])

        # OWASP
        if show_owasp:
            for o in self.owasp:
                _add_node(o["id"], f"{o['id']}\n{_strip_ai(o['name_ko'])}", "#f58220", "square", 22, "OWASP", o["name"])

        # NIS Measures
        if show_measures and show_nis:
            for m in self.measures:
                _add_node(m["id"], f"{m['id']}\n{m['name'][:8]}", "#2f55a5", "diamond", 12, "NIS 대책", m["name"])

        # NIS Incidents (사고사례)
        if show_incidents and show_nis:
            for inc in self.incidents:
                _add_node(inc["id"], f"{inc['id']}\n{inc['title'][:10]}", "#e74c3c", "star", 18, "NIS 사고사례", inc["title"])

        # ATLAS Case Studies (사례연구)
        if show_case_studies:
            for cs in self.atlas_case_studies:
                if self._case_study_threats.get(cs["id"]):  # only if linked to NIS threats
                    ko = self._atlas_ko.get("case_studies", {}).get(cs["id"], {})
                    label = ko.get("name", cs["name"])[:12]
                    title = ko.get("name", cs["name"])
                    _add_node(cs["id"], f"{cs['id'][:8]}\n{label}", "#9b59b6", "triangle", 18, "ATLAS 사례연구", title)

        # --- Edges ---
        # NIS Threat <-> NIS Measure
        if show_measures and show_nis:
            for link in self.links:
                if link["threat_id"] in seen_nodes and link["measure_id"] in seen_nodes:
                    edges.append({"source": link["threat_id"], "target": link["measure_id"], "color": "#2f55a5", "width": 1})

        # NIS Threat <-> OWASP
        if show_nis and show_owasp:
            for om in self._owasp_mapping:
                oid = om["owasp_id"]
                for tid in om.get("threat_ids", []):
                    if oid in seen_nodes and tid in seen_nodes:
                        edges.append({"source": tid, "target": oid, "color": "#f58220", "width": 2, "dashes": True})

        # NIS Threat <-> NIS Incident
        if show_incidents and show_nis:
            for inc in self.incidents:
                for tid in inc.get("threat_ids", []):
                    if inc["id"] in seen_nodes and tid in seen_nodes:
                        edges.append({"source": tid, "target": inc["id"], "color": "#e74c3c", "width": 1})

        # ATLAS Case Study <-> NIS Threat (via technique mapping)
        if show_case_studies and show_nis:
            for cs in self.atlas_case_studies:
                for tid in self._case_study_threats.get(cs["id"], []):
                    if cs["id"] in seen_nodes and tid in seen_nodes:
                        edges.append({"source": tid, "target": cs["id"], "color": "#9b59b6", "width": 2, "dashes": True})

        # ATLAS Case Study <-> OWASP (via technique -> mapping -> owasp_ids)
        if show_case_studies and show_owasp:
            for cs in self.atlas_case_studies:
                owasp_ids = set()
                for tech_id in cs.get("technique_ids", []):
                    mapping = self._atlas_map_by_id.get(tech_id, {})
                    for oid in mapping.get("owasp_ids", []):
                        owasp_ids.add(oid)
                for oid in owasp_ids:
                    if cs["id"] in seen_nodes and oid in seen_nodes:
                        edges.append({"source": cs["id"], "target": oid, "color": "#cc6600", "width": 1, "dashes": [5, 5]})

        return {"nodes": nodes, "edges": edges}

    # === Summary stats ===
    def summary(self) -> dict:
        return {
            "total_threats": len(self.threats),
            "total_measures": len(self.measures),
            "total_links": len(self.links),
            "total_build_types": len(self.build_types),
            "common_measures": len(self.get_measures_by_ai_type(None)),
            "agentic_measures": len(self.get_measures_by_ai_type("에이전틱 AI")),
            "physical_measures": len(self.get_measures_by_ai_type("피지컬 AI")),
            "atlas_techniques": len(self.atlas_techniques),
            "atlas_mitigations": len(self.atlas_mitigations),
            "atlas_case_studies": len(self.atlas_case_studies),
            "atlas_mappings": len(self._atlas_mapping),
            "nist_functions": len(self.nist),
            "cross_mappings": len(self._cross_mapping),
        }


if __name__ == "__main__":
    kg = SecurityKnowledgeGraph()
    print("=== Knowledge Graph Summary ===")
    for k, v in kg.summary().items():
        print(f"  {k}: {v}")

    print("\n=== Example: 내부망 전용 + 에이전틱 AI ===")
    result = kg.query_by_context(build_type="내부망 전용", ai_type="에이전틱 AI")
    print(f"  Threats: {[t['id'] + ' ' + t['name'] for t in result['threats']]}")
    print(f"  Measures: {len(result['measures'])} items")
    for m in result["measures"][:5]:
        print(f"    {m['id']}: {m['name']}")
