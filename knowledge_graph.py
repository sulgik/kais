"""
NIS AI보안 가이드북 Knowledge Graph Query Engine
Loads structured JSON data and provides multi-dimensional queries.
"""
import json
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"


class SecurityKnowledgeGraph:
    def __init__(self, data_dir: Path = DATA_DIR):
        self.threats = self._load(data_dir / "threats.json")
        self.measures = self._load(data_dir / "measures.json")
        self.links = self._load(data_dir / "threat_measure_links.json")
        self.build_types = self._load(data_dir / "build_type_focuses.json")
        incidents_path = data_dir / "incidents.json"
        self.incidents = self._load(incidents_path) if incidents_path.exists() else []

        # OWASP LLM Top 10
        owasp_path = data_dir / "owasp_llm.json"
        self.owasp = self._load(owasp_path) if owasp_path.exists() else []
        owasp_map_path = data_dir / "owasp_nis_mapping.json"
        self._owasp_mapping = self._load(owasp_map_path) if owasp_map_path.exists() else []
        self._owasp_by_id = {o["id"]: o for o in self.owasp}
        self._owasp_map_by_id = {m["owasp_id"]: m for m in self._owasp_mapping}

        # MITRE ATLAS
        atlas_path = data_dir / "atlas_data.json"
        self._atlas_raw = self._load_json(atlas_path) if atlas_path.exists() else {}
        self.atlas_tactics = self._atlas_raw.get("tactics", [])
        self.atlas_techniques = self._atlas_raw.get("techniques", [])
        self.atlas_mitigations = self._atlas_raw.get("mitigations", [])
        self.atlas_case_studies = self._atlas_raw.get("case_studies", [])
        self._atlas_tactic_by_id = {t["id"]: t for t in self.atlas_tactics}
        self._atlas_tech_by_id = {t["id"]: t for t in self.atlas_techniques}
        atlas_map_path = data_dir / "atlas_nis_mapping.json"
        self._atlas_mapping = self._load(atlas_map_path) if atlas_map_path.exists() else []
        self._atlas_map_by_id = {m["atlas_id"]: m for m in self._atlas_mapping}
        # Reverse index: NIS threat -> ATLAS techniques
        self._atlas_for_threat = {}
        for am in self._atlas_mapping:
            for tid in am.get("threat_ids", []):
                self._atlas_for_threat.setdefault(tid, []).append(am["atlas_id"])

        # Index for fast lookup
        self._threat_by_id = {t["id"]: t for t in self.threats}
        self._measure_by_id = {m["id"]: m for m in self.measures}
        self._measures_for_threat = {}
        self._threats_for_measure = {}
        for link in self.links:
            self._measures_for_threat.setdefault(link["threat_id"], []).append(link["measure_id"])
            self._threats_for_measure.setdefault(link["measure_id"], []).append(link["threat_id"])

    def _load(self, path: Path) -> list[dict]:
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def _load_json(self, path: Path) -> dict:
        with open(path, encoding="utf-8") as f:
            return json.load(f)

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
            searchable = " ".join([t["name"], t["name_ko"], t.get("description", "")]).lower()
            if kw in searchable:
                results.append(t)
        return results

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

    def build_graph_data(self, show_nis: bool = True, show_atlas: bool = True,
                         show_owasp: bool = True, show_measures: bool = False) -> dict:
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

        # NIS Threats
        if show_nis:
            for t in self.threats:
                short = t['name'].replace('AI ', '').replace('AI', '')
                _add_node(t["id"], f"{t['id']}\n{short}", "#ed1c24", "dot", 25, "NIS Threat", t["name"])

        # OWASP
        if show_owasp:
            for o in self.owasp:
                short = o['name_ko'].replace('AI ', '').replace('AI', '')
                _add_node(o["id"], f"{o['id']}\n{short}", "#f58220", "square", 22, "OWASP", o["name"])

        # ATLAS Techniques (only mapped ones)
        if show_atlas:
            for am in self._atlas_mapping:
                tech = self._atlas_tech_by_id.get(am["atlas_id"])
                if tech:
                    short = tech['name_ko'].replace('AI ', '').replace('AI', '')
                    _add_node(tech["id"], f"{tech['id']}\n{short}", "#7b2d8e", "triangle", 20, "ATLAS", tech["name"])

        # NIS Measures (optional, can be noisy)
        if show_measures and show_nis:
            for m in self.measures:
                _add_node(m["id"], f"{m['id']}\n{m['name'][:8]}", "#2f55a5", "diamond", 12, "NIS Measure", m["name"])

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

        # NIS Threat <-> ATLAS Technique
        if show_nis and show_atlas:
            for am in self._atlas_mapping:
                aid = am["atlas_id"]
                for tid in am.get("threat_ids", []):
                    if aid in seen_nodes and tid in seen_nodes:
                        edges.append({"source": tid, "target": aid, "color": "#7b2d8e", "width": 2, "dashes": True})

        # ATLAS <-> OWASP (via shared NIS threats)
        if show_atlas and show_owasp:
            for am in self._atlas_mapping:
                aid = am["atlas_id"]
                for oid in am.get("owasp_ids", []):
                    if aid in seen_nodes and oid in seen_nodes:
                        edges.append({"source": aid, "target": oid, "color": "#cc6600", "width": 1, "dashes": [5, 5]})

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
            "atlas_mappings": len(self._atlas_mapping),
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
