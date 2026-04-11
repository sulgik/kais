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
