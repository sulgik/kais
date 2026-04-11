# KAIS — K-AI Security Advisor

NIS AI보안 가이드북을 Knowledge Graph로 구조화하여, 공공기관 담당자가 AI시스템을 안전하게 도입·운영하도록 돕는 AI 어드바이저.

## Features

- **💬 어드바이저**: 구축유형·AI유형·수명주기 컨텍스트 기반 보안 Q&A (Claude 사용)
- **🔍 지식 탐색**: 보안위협(T01~T15) / 보안대책(M01~M30, A-M, P-M) 브라우징
- **✅ 체크리스트**: 구축유형 + AI유형 선택 → 맞춤형 체크리스트 자동 생성

## 데이터 출처

- [국가정보원 AI보안 가이드북 (2025.12)](https://www.nis.go.kr)
- OWASP LLM Top 10 (추가 예정)

## 실행

```bash
pip install -r requirements.txt
streamlit run app.py
```

사이드바에서 Anthropic API Key를 입력하면 어드바이저 기능이 활성화됩니다.

## Knowledge Graph 구조

| 항목 | 수 |
|------|---|
| 보안위협 | 15개 (T01~T15) |
| 보안대책 | 57개 (M30 + A-M17 + P-M10) |
| 위협-대책 매핑 | 89개 |
| 구축유형 | 4개 |
