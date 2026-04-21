#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path("/opt/CAPEv2")
tags_path = ROOT / "web" / "analysis" / "templatetags" / "analysis_tags.py"
sig_tpl_path = ROOT / "web" / "templates" / "analysis" / "overview" / "_signatures.html"

if not tags_path.exists():
    print(f"analysis_tags.py not found: {tags_path}", file=sys.stderr)
    sys.exit(1)
if not sig_tpl_path.exists():
    print(f"_signatures.html not found: {sig_tpl_path}", file=sys.stderr)
    sys.exit(1)

tags_text = tags_path.read_text(encoding="utf-8")
tpl_text = sig_tpl_path.read_text(encoding="utf-8")

filter_block = '''
# --- CAPE Korean signature translation patch ---
SIGNATURE_DESCRIPTION_EXACT_KO = {
    "The PE file contains a PDB path": "PE 파일 내부에 PDB(디버그 경로) 정보가 포함되어 있습니다.",
    "The binary contains an unknown PE section name indicative of packing": "비정상적인 PE 섹션명이 확인되어 패킹/난독화가 의심됩니다.",
    "The PE file contains an overlay": "PE 파일 끝부분에 추가 데이터(overlay)가 포함되어 있습니다.",
    "Terminates another process": "다른 프로세스를 종료하려고 시도합니다.",
    "Contains .tls (Thread Local Storage) section": "`.tls`(Thread Local Storage) 섹션이 포함되어 있습니다.",
    "Drops a binary and executes it": "실행 파일을 생성(드롭)한 뒤 실행합니다.",
    "Uses Windows utilities for basic functionality": "기본 기능 수행을 위해 Windows 기본 유틸리티를 사용합니다.",
    "Touches a file containing cookies, possibly for information gathering": "쿠키 파일에 접근하여 정보 수집을 시도할 가능성이 있습니다.",
}

SIGNATURE_DESCRIPTION_KEYWORDS_KO = [
    ("terminates another process", "다른 프로세스를 종료하려고 시도합니다."),
    ("contains .tls", "`.tls`(Thread Local Storage) 섹션이 포함되어 있습니다."),
    ("overlay", "PE 파일 끝부분에 추가 데이터(overlay)가 포함되어 있습니다."),
    ("unknown pe section name", "비정상적인 PE 섹션명이 확인되어 패킹/난독화가 의심됩니다."),
    ("pdb path", "PE 파일 내부에 PDB(디버그 경로) 정보가 포함되어 있습니다."),
    ("drops a binary and executes it", "실행 파일을 생성(드롭)한 뒤 실행합니다."),
    ("uses windows utilities", "기본 기능 수행을 위해 Windows 기본 유틸리티를 사용합니다."),
    ("queries registry mount points", "레지스트리의 마운트 지점을 조회하여 이동식/네트워크 드라이브 이력을 확인하려고 합니다."),
    ("volume serial number", "볼륨 시리얼 번호 또는 하드웨어 식별자를 조회합니다. 안티샌드박스/환경 식별 목적일 수 있습니다."),
    ("physical hardware id", "물리 하드웨어 식별자를 조회합니다. 안티샌드박스/환경 식별 목적일 수 있습니다."),
    ("suspicious io control codes", "의심스러운 IO 제어 코드를 사용합니다. 부트킷/와이퍼 계열 행위일 수 있습니다."),
    ("modifies the memory protection of ntdll.dll", "ntdll.dll의 메모리 보호 속성을 수정합니다. EDR 우회/언후킹 시도일 수 있습니다."),
    ("rwx memory", "실행 권한이 있는 RWX 메모리 사용이 확인되었습니다."),
    ("mutex", "뮤텍스를 사용한 프로세스 간 동기화 흔적이 있습니다."),
    ("named shared memory", "이름 있는 공유 메모리(파일 매핑)를 통한 프로세스 간 통신 흔적이 있습니다."),
    ("manually resolves api addresses", "동적으로 할당된 메모리에서 API 주소를 수동으로 해석합니다. 쉘코드/언패커 행위일 수 있습니다."),
    ("dynamically allocated (unbacked) memory", "파일에 매핑되지 않은 동적 메모리(unbacked memory)에서 동작하는 흔적이 있습니다."),
    ("loads a new dll", "새 DLL을 로드합니다."),
    ("altered memory protections", "동적으로 할당된 메모리의 보호 속성을 변경했습니다. 셸코드/메모리 패칭일 수 있습니다."),
    ("paused execution", "실행을 일시 중단(sleep/delay)했습니다. 샌드박스 우회 또는 지연 실행일 수 있습니다."),
    ("attempted to resolve a domain name", "동적으로 할당된 메모리에서 도메인 이름을 해석하려고 시도했습니다."),
    ("network connection initiated", "동적으로 할당된 메모리에서 네트워크 연결을 시작했습니다. 파일리스 C2 행위일 수 있습니다."),
    ("queries registry", "레지스트리 조회 행위가 확인되었습니다."),
    ("unhook", "후킹 해제 또는 모니터링 우회 시도가 의심됩니다."),
    ("edr", "EDR 우회와 관련된 행위가 의심됩니다."),
    ("driver", "드라이버 관련 행위가 확인되었습니다."),
    ("service", "서비스 생성 또는 시작과 관련된 행위가 확인되었습니다."),
    ("injection", "프로세스 인젝션 관련 행위가 의심됩니다."),
    ("cookie", "쿠키 파일 접근이 확인되었습니다."),
]

@register.filter(name="translate_signature_desc_ko")
def translate_signature_desc_ko(description, signature_name=""):
    if not description:
        return description
    exact = SIGNATURE_DESCRIPTION_EXACT_KO.get(description)
    if exact:
        return exact
    lowered = str(description).lower()
    for key, value in SIGNATURE_DESCRIPTION_KEYWORDS_KO:
        if key in lowered:
            return value
    return description
# --- end CAPE Korean signature translation patch ---
'''

marker = 'def playback_url(task_id):'
if 'translate_signature_desc_ko' not in tags_text:
    if marker in tags_text:
        tags_text = tags_text.replace(marker, filter_block + '\n' + marker, 1)
        tags_path.write_text(tags_text, encoding='utf-8')
        print('analysis_tags.py: translate_signature_desc_ko 필터 추가 완료')
    else:
        print('analysis_tags.py: 삽입 위치를 찾지 못해 필터 추가 실패', file=sys.stderr)
        sys.exit(2)
else:
    print('analysis_tags.py: translate_signature_desc_ko 필터가 이미 존재함')

old = '{{signature.description}}'
new = '{{signature.description|translate_signature_desc_ko:signature.name}}'
if new not in tpl_text:
    if old in tpl_text:
        tpl_text = tpl_text.replace(old, new, 1)
        sig_tpl_path.write_text(tpl_text, encoding='utf-8')
        print('_signatures.html: 한국어 번역 필터 적용 완료')
    else:
        print('_signatures.html: signature.description 출력 구문을 찾지 못했습니다.', file=sys.stderr)
        sys.exit(3)
else:
    print('_signatures.html: 한국어 번역 필터가 이미 적용되어 있음')

print('완료')
