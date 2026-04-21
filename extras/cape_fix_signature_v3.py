from pathlib import Path
import re

path = Path('/opt/CAPEv2/web/analysis/templatetags/analysis_tags.py')
text = path.read_text(encoding='utf-8')
orig = text

keywords_block = '''

SIGNATURE_DESCRIPTION_KEYWORDS_KO = [
    ("terminates another process", "다른 프로세스를 종료하려는 행위가 확인되었습니다."),
    ("contains .tls (thread local storage) section", ".tls(Thread Local Storage) 섹션이 포함되어 있습니다."),
    ("queries registry mount points", "레지스트리 마운트 포인트를 조회하여 이동식/네트워크 드라이브 이력을 확인합니다."),
    ("drops a binary and executes it", "추가 실행 파일을 생성(드롭)한 뒤 실행합니다."),
    ("uses windows utilities for basic functionality", "기본 기능 수행을 위해 Windows 기본 유틸리티를 사용합니다."),
    ("tries to unhook or modify windows functions monitored by cape", "CAPE가 감시하는 Windows 함수의 후킹 해제 또는 변조를 시도합니다."),
    ("queries the volume serial number or physical hardware id", "볼륨 시리얼 번호 또는 물리 하드웨어 ID를 조회합니다. 안티샌드박스/환경 식별 가능성이 있습니다."),
    ("uses suspicious io control codes", "의심스러운 IO 제어 코드를 사용합니다. 부트킷 또는 와이퍼 행위 가능성이 있습니다."),
    ("modifies the memory protection of ntdll.dll to page_readwrite", "ntdll.dll의 메모리 보호 속성을 PAGE_READWRITE로 변경합니다. EDR 언후킹 정황일 수 있습니다."),
    ("touches a file containing cookies", "쿠키 파일에 접근하여 정보 수집을 시도할 수 있습니다."),
    ("inter-process synchronization via mutexes", "뮤텍스를 이용한 프로세스 간 동기화가 확인되었습니다. 로컬 C2 라우팅 또는 인젝션에 쓰일 수 있습니다."),
    ("inter-process communication via named shared memory", "이름 있는 공유 메모리(file mapping)를 이용한 프로세스 간 통신이 확인되었습니다."),
    ("manually resolves api addresses from dynamically allocated (unbacked) memory", "동적으로 할당된 비백업 메모리에서 API 주소를 수동으로 해석합니다. 쉘코드 또는 언패커 정황일 수 있습니다."),
    ("loads a new dll where the caller address originates from dynamically allocated (unbacked) memory", "동적으로 할당된 비백업 메모리에서 호출된 새 DLL 로드가 확인되었습니다."),
    ("altered memory protections from dynamically allocated (unbacked) memory", "동적으로 할당된 비백업 메모리의 보호 속성 변경이 확인되었습니다. 자가 수정 쉘코드나 메모리 패칭 가능성이 있습니다."),
    ("paused execution (sleep/delay) in a thread executing in dynamically allocated (unbacked) memory", "동적으로 할당된 비백업 메모리에서 실행 중인 스레드가 sleep/delay를 수행했습니다. 샌드박스 회피 또는 C2 대기 정황일 수 있습니다."),
    ("attempted to resolve a domain name from dynamically allocated (unbacked) memory", "동적으로 할당된 비백업 메모리에서 도메인 이름 해석을 시도했습니다."),
    ("network connection initiated from dynamically allocated (unbacked) memory", "동적으로 할당된 비백업 메모리에서 네트워크 연결이 시작되었습니다. 파일리스 C2 행위 가능성이 있습니다."),
    ("pdb path", "PE 파일 내부에 PDB(디버그 경로) 정보가 포함되어 있습니다."),
    ("overlay", "PE 파일 끝부분에 추가 데이터(overlay)가 포함되어 있습니다."),
    ("packing", "패킹/난독화 정황이 확인되었습니다."),
    ("driver", "드라이버 관련 행위가 확인되었습니다."),
    ("service", "서비스 생성 또는 시작 행위가 확인되었습니다."),
    ("powershell", "PowerShell 실행 정황이 확인되었습니다."),
    ("shadow copies", "섀도 복사본 삭제 시도가 확인되었습니다."),
    ("windows defender", "Windows Defender 비활성화 시도가 확인되었습니다."),
    ("cookies", "쿠키 파일 접근 정황이 확인되었습니다."),
    ("mutex", "뮤텍스 기반 프로세스 간 동기화가 확인되었습니다."),
    ("named shared memory", "공유 메모리 기반 프로세스 간 통신이 확인되었습니다."),
    ("volume serial number", "볼륨 시리얼 번호 또는 하드웨어 ID 조회 정황이 확인되었습니다."),
    ("ntdll.dll", "ntdll.dll 관련 메모리 보호 속성 변경 정황이 확인되었습니다."),
    ("rwx", "실행 권한이 있는 RWX 메모리 사용이 확인되었습니다."),
    ("unhook", "후킹 해제 또는 보안 우회 시도가 확인되었습니다."),
    ("drop", "추가 파일 생성 또는 드롭 행위가 확인되었습니다."),
    ("network connection", "네트워크 연결 시도가 확인되었습니다."),
]
'''

if 'SIGNATURE_DESCRIPTION_KEYWORDS_KO = [' not in text:
    marker = 'SIGNATURE_DESCRIPTION_KO = {'
    start = text.find(marker)
    if start == -1:
        raise SystemExit('SIGNATURE_DESCRIPTION_KO 블록을 찾지 못했습니다.')
    # find end of dict block by locating the first standalone closing brace after marker
    end = text.find('\n}\n', start)
    if end == -1:
        raise SystemExit('SIGNATURE_DESCRIPTION_KO 블록 끝을 찾지 못했습니다.')
    end += len('\n}\n')
    text = text[:end] + keywords_block + text[end:]

pattern = re.compile(
    r'@register\.filter\(name="translate_signature_desc"\)\ndef translate_signature_desc\(description, signature_name=""\):\n(?:    .*\n)+?(?=\n\n@register\.filter\(name="flare_capa_capability"\))',
    re.M,
)

replacement = '''@register.filter(name="translate_signature_desc")
def translate_signature_desc(description, signature_name=""):
    if not description:
        return description

    if signature_name and signature_name in SIGNATURE_NAME_KO:
        return SIGNATURE_NAME_KO[signature_name]

    translated = SIGNATURE_DESCRIPTION_KO.get(description)
    if translated:
        return translated

    desc_lc = description.lower().strip()
    for keyword, korean in SIGNATURE_DESCRIPTION_KEYWORDS_KO:
        if keyword in desc_lc:
            return korean

    if desc_lc.startswith("queries "):
        return f"정보 조회 행위가 확인되었습니다: {description}"

    return description'''

new_text, count = pattern.subn(replacement, text)
if count != 1:
    raise SystemExit(f'translate_signature_desc 함수 치환 실패: {count}')
text = new_text

if text == orig:
    print('변경 사항이 없습니다.')
else:
    path.write_text(text, encoding='utf-8')
    print('analysis_tags.py 수정 완료')
