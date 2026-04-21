from pathlib import Path
import re

ROOT = Path('/opt/CAPEv2')
SIG_FILE = ROOT / 'web/templates/analysis/overview/_signatures.html'
PARTIAL_FILE = ROOT / 'web/templates/analysis/overview/_signature_desc_ko.html'

partial = r'''
{# 안전한 키워드 기반 시그니처 한글화 템플릿 #}
{% if "The PE file contains a PDB path" in signature.description %}PE 파일 안에 PDB(디버그 경로) 정보가 포함되어 있음
{% elif "contains an overlay" in signature.description %}실행 파일 끝부분에 추가 데이터(overlay)가 붙어 있음
{% elif "unknown PE section name" in signature.description %}비정상적인 PE 섹션명이 있어 패킹/난독화 가능성이 있음
{% elif "Contains .tls section" in signature.description or "contains .tls section" in signature.description %}.tls 섹션이 포함되어 있음
{% elif "RWX memory" in signature.description or "allocates RWX" in signature.description or "rwx" in signature.name %}읽기/쓰기/실행(RWX) 권한 메모리를 사용함
{% elif "Terminates another process" in signature.description %}다른 프로세스를 종료하려고 시도함
{% elif "Drops a binary and executes it" in signature.description %}실행 파일을 드롭한 뒤 실행함
{% elif "Uses Windows utilities for basic functionality" in signature.description %}기본 동작에 Windows 유틸리티를 활용함
{% elif "Queries the Volume Serial Number" in signature.description %}볼륨 시리얼 번호를 조회함
{% elif "Creates a service" in signature.description or "created_services" in signature.name or "persistence_service" in signature.name %}서비스를 생성해 지속성을 확보하려고 시도함
{% elif "Starts a service" in signature.description or "started_services" in signature.name %}서비스를 시작함
{% elif "Loads a driver" in signature.description or "driver_load" in signature.name %}드라이버를 로드하려고 시도함
{% elif "driver_filtermanager" in signature.name %}필터 매니저 드라이버 동작 흔적이 있음
{% elif "bootkit" in signature.name or "Bootkit" in signature.description %}부트킷 성격의 동작 흔적이 있음
{% elif "wiper" in signature.name or "Wiper" in signature.description %}시스템/파일 파괴형 와이퍼 행위가 의심됨
{% elif "virus" in signature.name and "antivirus" not in signature.name %}바이러스 계열 특성이 의심됨
{% elif "dropper" in signature.name or "Dropper" in signature.description %}추가 페이로드를 떨어뜨리는 드로퍼 성격이 있음
{% elif "downloader" in signature.name or "downloads" in signature.description or "download" in signature.description %}외부에서 추가 파일을 내려받으려는 동작이 있음
{% elif "payload_download" in signature.name %}추가 페이로드를 다운로드하려고 시도함
{% elif "Creates an executable" in signature.description or "creates_exe" in signature.name %}실행 파일을 생성함
{% elif "Deletes itself" in signature.description or "deletes_self" in signature.name %}자기 자신을 삭제하려고 시도함
{% elif "Copies itself" in signature.description or "copies_self" in signature.name %}자기 자신을 다른 위치로 복사함
{% elif "Deletes shadow copies" in signature.description or "deletes_shadowcopies" in signature.name %}볼륨 섀도 복사본을 삭제하려고 시도함
{% elif "Deletes system backup" in signature.description or "deletes_system_backup" in signature.name %}시스템 백업을 삭제하거나 무력화하려고 시도함
{% elif "Disables Windows Defender" in signature.description or "disables_windefender" in signature.name %}Windows Defender를 비활성화하려고 시도함
{% elif "Disables Windows Firewall" in signature.description or "disables_winfirewall" in signature.name %}Windows 방화벽을 비활성화하려고 시도함
{% elif "Disables SmartScreen" in signature.description or "disables_smartscreen" in signature.name %}SmartScreen 보호 기능을 끄려고 시도함
{% elif "Disables security" in signature.description or "disables_security" in signature.name %}보안 관련 기능을 비활성화하려고 시도함
{% elif "Disables event logging" in signature.description or "disables_event_logging" in signature.name %}이벤트 로그 기능을 비활성화하려고 시도함
{% elif "Clears logs" in signature.description or "clears_logs" in signature.name %}로그를 삭제하거나 정리하려고 시도함
{% elif "Disables UAC" in signature.description or "disables_uac" in signature.name %}UAC를 비활성화하려고 시도함
{% elif "Bypasses UAC" in signature.description or "bypass_uac" in signature.name %}UAC 우회를 시도함
{% elif "Bypasses AppLocker" in signature.description or "bypass_applocker" in signature.name %}AppLocker 우회를 시도함
{% elif "bypass_firewall" in signature.name %}방화벽 우회를 시도함
{% elif "bypass_edr" in signature.name %}EDR 탐지/후킹 우회를 시도함
{% elif "tampers_etw" in signature.name or "ETW" in signature.description %}ETW 로깅을 방해하려고 시도함
{% elif "tampers_lsa" in signature.name or "LSA" in signature.description %}LSA 보안 구성을 건드리려는 흔적이 있음
{% elif "tampers_powershell_logging" in signature.name %}PowerShell 로깅을 방해하려고 시도함
{% elif "credential_dumping" in signature.name or "Credential dumping" in signature.description %}자격 증명 덤프를 시도함
{% elif "credential_access" in signature.name or "Credential access" in signature.description %}자격 증명 접근 행위가 있음
{% elif "reads_password_database" in signature.name %}비밀번호 저장소를 읽으려고 시도함
{% elif "mimikatz" in signature.name or "Mimikatz" in signature.description %}Mimikatz 관련 행위가 탐지됨
{% elif "comsvcs" in signature.name %}comsvcs 기반 자격 증명 덤프 흔적이 있음
{% elif "infostealer_browser_password" in signature.name %}브라우저 저장 비밀번호 탈취 시도가 있음
{% elif "infostealer_browser" in signature.name %}브라우저 정보 탈취 행위가 있음
{% elif "infostealer_cookies" in signature.name %}브라우저 쿠키 탈취 시도가 있음
{% elif "infostealer_mail" in signature.name %}메일/클라이언트 정보 탈취 시도가 있음
{% elif "infostealer_ftp" in signature.name %}FTP 계정 정보 탈취 시도가 있음
{% elif "infostealer_keylog" in signature.name or "keylog" in signature.description %}키로깅 행위가 탐지됨
{% elif "infostealer_screenshot" in signature.name or "screenshot" in signature.description %}화면 캡처/스크린샷 탈취 행위가 있음
{% elif "set_clipboard_data" in signature.name or "clipboard" in signature.description %}클립보드 데이터를 조작하거나 탈취함
{% elif "memory_scraping" in signature.name or "scraping" in signature.description %}메모리 스크래핑 행위가 있음
{% elif "injection_createremotethread" in signature.name or "CreateRemoteThread" in signature.description %}CreateRemoteThread 기반 프로세스 인젝션이 의심됨
{% elif "injection_runpe" in signature.name or "RunPE" in signature.description %}RunPE/프로세스 할로잉 계열 인젝션이 의심됨
{% elif "injection_writememory" in signature.name or "WriteProcessMemory" in signature.description %}원격 프로세스 메모리 쓰기 행위가 탐지됨
{% elif "injection_thread" in signature.name or "thread injection" in signature.description %}스레드 기반 인젝션 행위가 의심됨
{% elif "injection_rwx" in signature.name %}RWX 메모리를 이용한 인젝션 가능성이 있음
{% elif "injection_network" in signature.name %}네트워크 연계형 프로세스 인젝션 흔적이 있음
{% elif "createsuspended" in signature.name or "CreateProcess" in signature.description and "suspended" in signature.description %}일시중단 프로세스를 생성해 주입하려는 행위가 있음
{% elif "dll_sideloading" in signature.name or "DLL sideloading" in signature.description %}DLL 사이드로딩이 의심됨
{% elif "dll_load_uncommon" in signature.name %}비정상적 DLL 로드가 탐지됨
{% elif "dynamic_function_loading" in signature.name %}동적 함수 로딩을 수행함
{% elif "malicious_dynamic_function_loading" in signature.name %}의심스러운 동적 함수 로딩을 수행함
{% elif "memory_unbacked_execution" in signature.name %}비정상 메모리 영역에서 실행이 일어남
{% elif "memory_unbacked_network" in signature.name %}비정상 메모리 영역 실행과 네트워크 활동이 연계됨
{% elif "memory_unbacked_misc" in signature.name %}비정상 메모리 실행 흔적이 있음
{% elif "powershell_command" in signature.name or "PowerShell" in signature.description %}PowerShell 명령 실행 흔적이 있음
{% elif "script_downloader" in signature.name %}스크립트 기반 다운로드 행위가 있음
{% elif "script_misc" in signature.name %}스크립트 기반 의심 동작이 있음
{% elif "office_macro_suspicious" in signature.name or "suspicious macro" in signature.description %}의심스러운 Office 매크로가 탐지됨
{% elif "office_macro" in signature.name or "macro" in signature.description %}Office 매크로가 포함되어 있거나 실행됨
{% elif "office_exploit" in signature.name or "Office exploit" in signature.description %}Office 문서 취약점 악용 흔적이 있음
{% elif "office_write_exe" in signature.name %}Office 문서가 실행 파일을 생성하려고 시도함
{% elif "office_suspicious_process" in signature.name %}Office 문서가 비정상 프로세스를 실행함
{% elif "office_suspicious" in signature.name %}의심스러운 Office 동작이 탐지됨
{% elif "js_phish" in signature.name or "phish" in signature.description %}피싱 목적의 스크립트/페이지 행위가 의심됨
{% elif "secure_login_phish" in signature.name %}로그인 정보 탈취형 피싱 행위가 의심됨
{% elif "webmail_phish" in signature.name %}웹메일 피싱 행위가 의심됨
{% elif "browser_proxy" in signature.name %}브라우저 프록시 설정을 변경하려고 시도함
{% elif "browser_security" in signature.name %}브라우저 보안 설정을 약화시키려는 행위가 있음
{% elif "browser_startpage" in signature.name %}브라우저 시작 페이지를 변경하려고 시도함
{% elif "browser_addon" in signature.name or "BHO" in signature.description %}브라우저 확장/BHO 설치 흔적이 있음
{% elif "modifies_hostsfile" in signature.name or "hosts file" in signature.description %}hosts 파일을 수정하려고 시도함
{% elif "modifies_certs" in signature.name or "cert" in signature.description and "modify" in signature.description %}인증서 저장소 또는 인증서 관련 설정을 변경하려고 시도함
{% elif "modifies_zoneid_ads" in signature.name or "zoneid" in signature.description %}Zone.Identifier ADS를 조작함
{% elif "removes_zoneid_ads" in signature.name %}Zone.Identifier ADS를 제거함
{% elif "recon_systeminfo" in signature.name or "systeminfo" in signature.description %}시스템 정보 수집 행위가 있음
{% elif "recon_programs" in signature.name %}설치 프로그램/환경 정보를 수집함
{% elif "recon_fingerprint" in signature.name or "fingerprint" in signature.description %}시스템 지문 정보 수집 행위가 있음
{% elif "recon_beacon" in signature.name or "beacon" in signature.description %}비콘 통신/호출집(home) 흔적이 있음
{% elif "process_discovery" in signature.name or "process discovery" in signature.description %}프로세스 목록을 탐색함
{% elif "computer_discovery" in signature.name %}컴퓨터/호스트 정보를 수집함
{% elif "domain_enumeration" in signature.name %}도메인/AD 정보를 열거하려고 시도함
{% elif "user_enum" in signature.name %}사용자 계정 정보를 열거함
{% elif "network_cnc_http" in signature.name or "HTTP C2" in signature.description %}HTTP 기반 C2 통신이 의심됨
{% elif "network_cnc_generic" in signature.name or "command and control" in signature.description %}명령제어(C2) 통신이 의심됨
{% elif "network_cnc_encrypted" in signature.name %}암호화된 C2 통신이 의심됨
{% elif "network_dns_suspicious" in signature.name %}의심스러운 DNS 통신이 탐지됨
{% elif "network_dga" in signature.name or "DGA" in signature.description %}도메인 생성 알고리즘(DGA) 사용이 의심됨
{% elif "network_tor_service" in signature.name or "Tor service" in signature.description %}Tor 서비스 사용 흔적이 있음
{% elif "network_tor" in signature.name or "TOR" in signature.description %}Tor 네트워크 사용 흔적이 있음
{% elif "network_open_proxy" in signature.name %}오픈 프록시 성격의 네트워크 행위가 있음
{% elif "network_p2p" in signature.name or "peer-to-peer" in signature.description %}P2P 네트워크 사용 흔적이 있음
{% elif "network_irc" in signature.name or "IRC" in signature.description %}IRC 통신 흔적이 있음
{% elif "network_smtp" in signature.name or "SMTP" in signature.description %}SMTP 메일 전송 흔적이 있음
{% elif "network_icmp" in signature.name or "ICMP" in signature.description %}ICMP 통신 흔적이 있음
{% elif "network_excessive_udp" in signature.name %}과도한 UDP 통신이 탐지됨
{% elif "network_http" in signature.name or "http_request" in signature.name %}HTTP 요청 행위가 탐지됨
{% elif "filehostings" in signature.name %}파일 호스팅 서비스를 악용하려는 흔적이 있음
{% elif "livingofftrustedsites" in signature.name %}신뢰된 사이트를 악용한 통신이 의심됨
{% elif "legitdomainabuse" in signature.name %}정상 도메인을 악용한 통신이 의심됨
{% elif "fake_useragent" in signature.name %}가짜/비정상 User-Agent 사용 흔적이 있음
{% elif "Stealth" in signature.description or "stealth_" in signature.name %}은폐 목적의 동작이 탐지됨
{% elif "antiav" in signature.name or "anti-virus" in signature.description or "antivirus" in signature.description %}백신/보안 제품 회피 또는 탐지 행위가 있음
{% elif "antisandbox" in signature.name or "sandbox" in signature.description %}샌드박스 회피/탐지 행위가 있음
{% elif "antivm" in signature.name or "virtual machine" in signature.description %}가상 머신 탐지/회피 행위가 있음
{% elif "antidebug" in signature.name or "debugger" in signature.description %}디버거 탐지/방해 행위가 있음
{% elif "antiemu" in signature.name or "emulator" in signature.description %}에뮬레이터 회피 행위가 있음
{% elif "antianalysis" in signature.name or "analysis" in signature.description and "avoid" in signature.description %}분석 회피 행위가 의심됨
{% elif "cuckoo" in signature.name.lower %}CAPE/Cuckoo 샌드박스 탐지 흔적이 있음
{% elif "sandboxie" in signature.name.lower or "sboxie" in signature.name.lower %}Sandboxie 환경 탐지 흔적이 있음
{% elif "vmware" in signature.name.lower %}VMware 환경 탐지 흔적이 있음
{% elif "vbox" in signature.name.lower %}VirtualBox 환경 탐지 흔적이 있음
{% elif "hyperv" in signature.name.lower %}Hyper-V 환경 탐지 흔적이 있음
{% elif "wine" in signature.name.lower %}Wine 환경 탐지 흔적이 있음
{% elif "mousemovement" in signature.name.lower or "mouse_hook" in signature.name.lower %}마우스 움직임/입력 여부를 확인해 분석을 회피하려고 시도함
{% elif "sleep" in signature.name.lower or "suspend" in signature.name.lower %}지연/절전 기반 분석 회피 행위가 있음
{% elif "restart" in signature.name.lower %}재시작을 이용한 분석 회피 행위가 있음
{% elif "persistence_autorun" in signature.name %}자동 실행 등록을 통한 지속성 확보 시도가 있음
{% elif "persistence_bootexecute" in signature.name %}BootExecute 등록을 통한 지속성 확보 시도가 있음
{% elif "persistence_ads" in signature.name %}대체 데이터 스트림(ADS)을 이용한 지속성 확보 시도가 있음
{% elif "persistence_ifeo" in signature.name %}IFEO를 이용한 지속성 확보 시도가 있음
{% elif "persistence_shim" in signature.name %}Shim DB를 이용한 지속성 확보 시도가 있음
{% elif "persistence_fileless" in signature.name %}파일리스 지속성 확보 시도가 있음
{% elif "remote_desktop" in signature.name %}원격 데스크톱 관련 설정/행위가 탐지됨
{% elif "uses_adfind" in signature.name %}AdFind를 사용해 AD 정보를 수집함
{% elif "uses_mmc" in signature.name %}MMC를 사용한 관리 작업 흔적이 있음
{% elif "uses_ms_protocol" in signature.name %}Microsoft 관련 프로토콜을 활용함
{% elif "lolbas" in signature.name %}LOLBin/LOLBas를 악용하려는 흔적이 있음
{% elif "bcdedit_command" in signature.name %}bcdedit 명령을 사용해 부팅 설정을 변경하려고 시도함
{% elif "windows_utilities" in signature.name %}Windows 기본 유틸리티를 활용함
{% elif "sysinternals" in signature.name %}Sysinternals 도구 사용 흔적이 있음
{% elif "cryptomining" in signature.name or "miner" in signature.description %}암호화폐 채굴 행위가 의심됨
{% elif "cryptopools" in signature.name %}채굴 풀 통신 흔적이 있음
{% elif "ransomware_crypto" in signature.name %}암호화 API를 활용한 랜섬웨어 성격의 동작이 있음
{% elif "ransomware_files" in signature.name %}대량 파일 접근/변형 등 랜섬웨어 성격의 파일 행위가 있음
{% elif "ransomware_filemodifications" in signature.name %}랜섬웨어성 파일 수정 행위가 탐지됨
{% elif "ransomware_fileextensions" in signature.name %}랜섬웨어가 사용하는 확장자 변경 흔적이 있음
{% elif "ransomware_message" in signature.name %}몸값 요구 메시지/문구 흔적이 있음
{% elif "ransomware_recyclebin" in signature.name %}휴지통/파일 삭제를 이용한 랜섬웨어성 행위가 있음
{% elif "malware_data_encryption" in signature.name %}악성 목적의 데이터 암호화가 의심됨
{% elif "packer_" in signature.name or "packed" in signature.description or "packing" in signature.description %}패커/난독화 흔적이 있음
{% else %}{{ signature.description }}
{% endif %}
'''.strip() + "\n"

sig_text = SIG_FILE.read_text(encoding='utf-8')

if 'analysis/overview/_signature_desc_ko.html' not in sig_text:
    replacements = [
        (r'{{\s*signature\.description\s*}}', '{% include "analysis/overview/_signature_desc_ko.html" %}'),
        (r'{{\s*signature\.description\|translate_signature_desc_ko:signature\.name\s*}}', '{% include "analysis/overview/_signature_desc_ko.html" %}'),
    ]
    changed = False
    for pattern, repl in replacements:
        new_text, count = re.subn(pattern, repl, sig_text)
        if count:
            sig_text = new_text
            changed = True
            break
    if not changed:
        raise SystemExit('_signatures.html 안에서 signature.description 출력 구문을 찾지 못했습니다.')
    SIG_FILE.write_text(sig_text, encoding='utf-8')
    print('_signatures.html: 한글 시그니처 include 적용 완료')
else:
    print('_signatures.html: 이미 한글 시그니처 include가 적용되어 있습니다.')

PARTIAL_FILE.write_text(partial, encoding='utf-8')
print('_signature_desc_ko.html: 100개 이상 키워드 매핑 저장 완료')
