#!/usr/bin/env python3
from pathlib import Path
import shutil

TARGET = Path("/opt/CAPEv2/web/templates/analysis/overview/_signatures.html")
BACKUP = TARGET.with_name("_signatures.html.bak.js100kw")

JS_BLOCK = r"""
<script id="signature-ko-translation-script">
document.addEventListener("DOMContentLoaded", function() {
  const signatureMap = [
    ["terminates another process", "다른 프로세스 종료 시도"],
    ["contains .tls section", ".tls 섹션 포함"],
    ["drops a binary and executes it", "실행 파일을 드롭한 뒤 실행함"],
    ["uses windows utilities for basic functionality", "Windows 기본 유틸리티를 활용함"],
    ["queries the volume serial number", "볼륨 시리얼 번호 조회"],
    ["contains an overlay", "실행 파일 끝에 overlay 데이터 포함"],
    ["contains a pdb path", "PDB 디버그 경로 포함"],
    ["unknown pe section name indicative of packing", "패킹/난독화 의심 비정상 PE 섹션명"],
    ["rwx memory region", "RWX 메모리 영역 사용"],
    ["allocates rwx memory", "RWX 메모리 할당"],
    ["writes into another process", "다른 프로세스 메모리 쓰기"],
    ["creates a remote thread", "원격 스레드 생성"],
    ["process injection", "프로세스 인젝션"],
    ["runpe", "RunPE/프로세스 위장 실행"],
    ["thread injection", "스레드 인젝션"],
    ["module stomping", "모듈 스톰핑"],
    ["unbacked executable memory", "비정상 비백업 실행 메모리"],
    ["suspicious process hollowing", "프로세스 할로잉 의심"],
    ["hollowing", "프로세스 할로잉"],
    ["drops a file", "파일 드롭"],
    ["creates exe", "실행 파일 생성"],
    ["creates a service", "서비스 생성"],
    ["started services", "서비스 시작"],
    ["service", "서비스 관련 행위"],
    ["persistence", "지속성 확보"],
    ["autorun", "자동실행 등록"],
    ["bootexecute", "BootExecute 등록"],
    ["shim", "Shim 기반 지속성"],
    ["ifeo", "IFEO 기반 지속성"],
    ["scheduled task", "예약 작업 등록"],
    ["registry", "레지스트리 행위"],
    ["modified registry keys", "레지스트리 키 수정"],
    ["deleted registry keys", "레지스트리 키 삭제"],
    ["reads registry keys", "레지스트리 키 읽기"],
    ["writes registry keys", "레지스트리 키 쓰기"],
    ["deletes shadowcopies", "볼륨 섀도 복사본 삭제"],
    ["disables system restore", "시스템 복원 비활성화"],
    ["disables windows update", "Windows 업데이트 비활성화"],
    ["disables security", "보안 기능 비활성화"],
    ["disables windows defender", "Windows Defender 비활성화"],
    ["disables smartscreen", "SmartScreen 비활성화"],
    ["disables firewall", "방화벽 우회/비활성화"],
    ["disables uac", "UAC 비활성화"],
    ["bypass uac", "UAC 우회"],
    ["bypass applocker", "AppLocker 우회"],
    ["bypass edr", "EDR 우회"],
    ["credential dumping", "자격 증명 덤프 시도"],
    ["credential access", "자격 증명 접근"],
    ["reads password database", "비밀번호 데이터베이스 읽기"],
    ["mimikatz", "Mimikatz 관련 흔적"],
    ["keylog", "키로깅"],
    ["screenshot", "스크린샷 수집"],
    ["clipboard", "클립보드 탈취/조작"],
    ["cookies", "쿠키 탈취"],
    ["browser password", "브라우저 비밀번호 탈취"],
    ["ftp", "FTP 자격 증명/통신"],
    ["mail", "메일 관련 탈취/행위"],
    ["browser", "브라우저 관련 행위"],
    ["phish", "피싱 관련 행위"],
    ["phishing", "피싱 관련 행위"],
    ["webmail", "웹메일 피싱/접근"],
    ["secure login", "로그인 페이지 위장/피싱"],
    ["network cnc", "C2 통신 의심"],
    ["cnc", "C2 통신 의심"],
    ["command and control", "명령제어 통신"],
    ["http request", "HTTP 요청 수행"],
    ["payload download", "추가 페이로드 다운로드"],
    ["tor", "Tor 관련 통신/서비스"],
    ["dns", "DNS 관련 행위"],
    ["smtp", "SMTP 메일 전송"],
    ["icmp", "ICMP 통신"],
    ["irc", "IRC 통신"],
    ["open proxy", "오픈 프록시 성격 통신"],
    ["dyndns", "동적 DNS 사용"],
    ["dga", "DGA 도메인 생성 의심"],
    ["network anomaly", "비정상 네트워크 행위"],
    ["questionable host", "수상한 호스트 접속"],
    ["questionable http path", "수상한 HTTP 경로 요청"],
    ["fake useragent", "가짜/비정상 User-Agent 사용"],
    ["encrypted", "암호화된 통신/데이터"],
    ["packer", "패커/압축기 흔적"],
    ["upx", "UPX 패킹 흔적"],
    ["themida", "Themida 패킹 흔적"],
    ["vmprotect", "VMProtect 패킹 흔적"],
    ["smartassembly", "SmartAssembly 난독화 흔적"],
    ["confuser", ".NET Confuser 난독화 흔적"],
    ["aspack", "ASPack 패킹 흔적"],
    ["mpress", "MPRESS 패킹 흔적"],
    ["enigma", "Enigma 보호/패킹 흔적"],
    ["antiav", "백신 탐지/우회"],
    ["antivirus", "백신 관련 흔적"],
    ["antidebug", "디버거 탐지/우회"],
    ["anti-debug", "디버거 탐지/우회"],
    ["antisandbox", "샌드박스 탐지/우회"],
    ["anti sandbox", "샌드박스 탐지/우회"],
    ["antivm", "가상환경 탐지"],
    ["anti vm", "가상환경 탐지"],
    ["sleep", "지연 실행/회피"],
    ["checkremotedebuggerpresent", "원격 디버거 존재 확인"],
    ["outputdebugstring", "디버거 탐지용 OutputDebugString 사용"],
    ["gettickcount", "시간 기반 분석 회피"],
    ["volume serial", "볼륨 시리얼 기반 식별"],
    ["systeminfo", "시스템 정보 수집"],
    ["recon", "정찰/정보수집"],
    ["computer discovery", "컴퓨터 정보 탐지"],
    ["domain enumeration", "도메인 열거"],
    ["process discovery", "프로세스 목록 수집"],
    ["user enum", "사용자 계정 열거"],
    ["mountpoints", "드라이브/마운트 지점 탐색"],
    ["filesystem", "파일시스템 탐색"],
    ["crypto", "암호화 관련 행위"],
    ["ransomware", "랜섬웨어 성격 행위"],
    ["encrypt", "파일/데이터 암호화"],
    ["file modifications", "대량 파일 수정"],
    ["file extensions", "파일 확장자 변경"],
    ["recyclebin", "휴지통 관련 랜섬웨어 흔적"],
    ["wiper", "와이퍼 성격 행위"],
    ["bootkit", "부트킷 성격 행위"],
    ["driver", "드라이버 관련 행위"],
    ["driver load", "드라이버 로드"],
    ["filtermanager", "필터 드라이버 관련 행위"],
    ["powershell", "PowerShell 실행"],
    ["cmd", "명령 실행"],
    ["windows utilities", "Windows 기본 유틸리티 사용"],
    ["lolbas", "LOLBin/LOLBas 활용"],
    ["sysinternals", "Sysinternals 도구 사용"],
    ["wmic", "WMIC 사용"],
    ["wmi", "WMI 사용"],
    ["bcdedit", "BCDEdit 사용"],
    ["mshta", "MSHTA 사용"],
    ["rundll32", "rundll32 사용"],
    ["regsvr32", "regsvr32 사용"],
    ["certutil", "certutil 사용"],
    ["schtasks", "schtasks 사용"],
    ["bitsadmin", "bitsadmin 사용"],
    ["curl", "curl 사용"],
    ["download", "다운로드 행위"],
    ["self-delete", "자기 삭제"],
    ["deletes self", "자기 삭제"],
    ["copies self", "자기 복제"],
    ["spoofs process name", "프로세스명 위장"],
    ["mimics", "정상 파일/속성 위장"],
    ["hidden file", "숨김 파일 사용"],
    ["hidden reg", "숨김 레지스트리 사용"],
    ["stealth", "은폐 행위"],
    ["tamper", "보안 기능/기록 변조"],
    ["etw", "ETW 무력화/변조"],
    ["lsa", "LSA 변조"],
    ["powershell logging", "PowerShell 로깅 무력화"],
    ["sysvol", "SYSVOL 접근"],
    ["netlogon", "NETLOGON 접근"]
  ];

  function translateText(text) {
    if (!text) return "";
    const lower = text.toLowerCase();
    for (const [k, v] of signatureMap) {
      if (lower.includes(k)) return v;
    }
    return "";
  }

  const nodes = document.querySelectorAll("#signatures .list-group-item .mb-1");
  nodes.forEach(function(node) {
    if (node.querySelector(".ko-signature-hint")) return;
    const original = node.textContent.trim();
    const ko = translateText(original);
    if (!ko) return;

    const hint = document.createElement("div");
    hint.className = "ko-signature-hint";
    hint.style.fontSize = "0.85em";
    hint.style.marginTop = "2px";
    hint.style.opacity = "0.9";
    hint.textContent = "한글 설명: " + ko;
    node.appendChild(hint);
  });
});
</script>
"""

def main():
    if not TARGET.exists():
        raise SystemExit(f"대상 파일이 없습니다: {TARGET}")

    text = TARGET.read_text(encoding="utf-8")

    if "signature-ko-translation-script" in text:
        print("이미 JS 한글화 블록이 적용되어 있습니다.")
        return

    shutil.copy2(TARGET, BACKUP)

    # append safely at the end; does not depend on exact signature.description line
    text = text.rstrip() + "\n\n" + JS_BLOCK.strip() + "\n"
    TARGET.write_text(text, encoding="utf-8")
    print(f"적용 완료: {TARGET}")
    print(f"백업 생성: {BACKUP}")

if __name__ == "__main__":
    main()
