# CAPE 통합 패치 번들

이 번들은 업로드된 패치 파일들을 **한 번에 적용**할 수 있도록 묶은 설치용 번들입니다.

## 기본 포함 동작
- Attack Story reporting + web 통합
- 커스텀 시그니처 5종 설치
- 한국어 UI diff 패치 적용
- 시그니처 한글 보조설명 JS 패치 적용

## 왜 전부를 그대로 단일 diff로 합치지 않았나
업로드된 파일 중 일부는 **같은 파일을 서로 다른 방식으로 수정**합니다.
특히 아래 파일은 충돌 가능성이 있습니다.
- `web/templates/analysis/overview/_signatures.html`
- `web/analysis/templatetags/analysis_tags.py`
- `web/templates/analysis/report.html`

그래서 이 번들은 다음 기준으로 통합했습니다.
- **기본값**: 비교적 버전 의존성이 낮은 방식 우선
  - Attack Story: 원본 설치 스크립트 재사용
  - Korean UI: diff 패치
  - Signature Korean helper: JS 주입 방식 사용
- **대체/실험용 패치**는 `extras/`에 보관
  - backend `analysis_tags.py` 번역 보강
  - 예전/대체 시그니처 번역 패치

## 파일 구조
- `install_unified_patch.sh` : 메인 설치 스크립트
- `payload/` : 기본 설치에 사용하는 패치들
- `extras/` : 충돌 가능성 있는 대체 패치/보조 유틸

## 설치
```bash
cd /경로/cape_unified_patch_bundle
sudo ./install_unified_patch.sh --root /opt/CAPEv2
```

## 자주 쓰는 옵션
```bash
# 한국어 UI 패치 없이 적용
sudo ./install_unified_patch.sh --root /opt/CAPEv2 --no-ko-ui

# 시그니처 JS 보조설명 없이 적용
sudo ./install_unified_patch.sh --root /opt/CAPEv2 --no-signature-js

# submission 페이지만 한국어 적용
sudo ./install_unified_patch.sh --root /opt/CAPEv2 --no-ko-ui --submission-only

# backend signature 번역 보강까지 같이 적용
sudo ./install_unified_patch.sh --root /opt/CAPEv2 --backend-signature-translate
```

## 백업
- 통합 백업: `/opt/CAPEv2/unified_patch_backups/<timestamp>/`
- 일부 개별 스크립트는 자체 백업도 추가 생성할 수 있습니다.

## 권장 적용 순서
이미 스크립트 안에 반영되어 있어 수동 적용은 보통 필요 없습니다.
1. Attack Story
2. Korean UI diff
3. Custom signatures
4. Signature Korean helper JS
5. optional backend signature translate

## 주의
- `patch` 유틸리티가 필요합니다.
- CAPE 포크 구조가 많이 다르면 diff 일부가 dry-run 단계에서 건너뛰어질 수 있습니다.
- 그런 경우에도 나머지 구성요소는 계속 설치되도록 만들었습니다.

## 포함된 원본/대체 파일
`extras/` 안에 참고용으로 같이 넣어 두었습니다.
