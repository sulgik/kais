"""
NIS AI보안 가이드북 Knowledge Graph Schema
"""
from dataclasses import dataclass, field
from enum import Enum


class Lifecycle(str, Enum):
    DATA_COLLECTION = "데이터 수집"
    AI_TRAINING = "AI 학습"
    SYSTEM_BUILD = "AI시스템 구축"
    SYSTEM_OPERATION = "AI시스템 운영"
    SYSTEM_DECOMMISSION = "AI시스템 폐기"


class BuildType(str, Enum):
    INTERNAL_ONLY = "내부망 전용 AI시스템"
    INTERNAL_EXTERNAL_LINK = "내부업무용 AI시스템의 외부망 연계"
    PUBLIC_SERVICE_INTERNAL_LINK = "대민서비스용 AI시스템의 내부망 연계"
    COMMERCIAL_SERVICE = "상용 AI서비스 활용"


class AIType(str, Enum):
    PREDICTIVE = "예측형 AI"
    GENERATIVE = "생성형 AI"
    AGENTIC = "에이전틱 AI"
    PHYSICAL = "피지컬 AI"


@dataclass
class Threat:
    id: str                          # T01~T15
    name: str                        # 학습데이터 오염
    definition: str                  # 정의
    risk: str                        # 위협 설명
    examples: list[str] = field(default_factory=list)
    lifecycles: list[Lifecycle] = field(default_factory=list)


@dataclass
class Measure:
    id: str                          # M01~M30, A-M01~A-M17, P-M01~P-M10
    name: str                        # 신뢰할 수 있는 출처의 데이터 활용
    description: str                 # 상세 설명
    details: list[str] = field(default_factory=list)  # 세부 항목
    checklist: str = ""              # 체크리스트 질문
    ai_type: AIType | None = None    # None=공통, Agentic, Physical


@dataclass
class ThreatMeasureLink:
    threat_id: str
    measure_id: str


@dataclass
class BuildTypeFocus:
    build_type: BuildType
    priority_threats: list[str]      # T-ids
    priority_measures: list[str]     # M-ids


@dataclass
class KnowledgeGraph:
    threats: list[Threat]
    measures: list[Measure]
    threat_measure_links: list[ThreatMeasureLink]
    build_type_focuses: list[BuildTypeFocus]
