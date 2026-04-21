#!/usr/bin/env python3
from pathlib import Path
import shutil
import re

TARGET = Path("/opt/CAPEv2/web/templates/analysis/overview/_signatures.html")
BACKUP = TARGET.with_name("_signatures.html.bak.manual_kofix")

JS_BLOCK = r"""
<script id="signature-ko-manual-fix-script">
document.addEventListener("DOMContentLoaded", function() {
  const exactMap = {
    "Checks available memory": "사용 가능한 메모리를 확인함",
    "Queries computer hostname": "컴퓨터 호스트명을 조회함",
    "Queries the username": "사용자 이름을 조회함",
    "Queries the keyboard layout": "키보드 레이아웃을 조회함",
    "Queries the computer locale (possible geofencing)": "컴퓨터 로캘을 조회함 (지오펜싱 가능성)",
    "SetUnhandledExceptionFilter detected (possible anti-debug)": "SetUnhandledExceptionFilter 호출이 탐지됨 (안티디버깅 가능성)",
    "Uses Windows utilities for basic functionality": "Windows 기본 유틸리티를 사용함",
    "Tries to unhook or modify Windows functions monitored by CAPE": "CAPE가 감시하는 Windows 함수의 후킹을 해제하거나 수정하려고 시도함",
    "Uses suspicious IO control codes, indicative of a bootkit or wiper": "부트킷 또는 와이퍼를 시사하는 수상한 IO 제어 코드를 사용함",
    "Touches a file containing cookies, possibly for information gathering": "정보 수집 목적으로 쿠키가 포함된 파일에 접근함",
    "Manually resolves API addresses from dynamically allocated (unbacked) memory, indicative of shellcode or an unpacker": "쉘코드 또는 언패커를 시사하는 동적 할당(비백업) 메모리에서 API 주소를 수동으로 해석함",
    "Loads a new DLL where the caller address originates from dynamically allocated (unbacked) memory": "호출자 주소가 동적 할당(비백업) 메모리에서 시작되는 새 DLL을 로드함",
    "Attempted to resolve a domain name from dynamically allocated (unbacked) memory": "동적 할당(비백업) 메모리에서 도메인 이름 해석을 시도함",
    "Possible date expiration check, exits too soon after checking local time": "로컬 시간을 확인한 직후 너무 빨리 종료함 (날짜 만료/시간 기반 실행 제한 가능성)",
    "Anomalous file deletion behavior detected (10+)": "비정상적인 파일 삭제 행위가 탐지됨 (10개 이상)"
  };

  const regexRules = [
    [
      /^Attempts to connect to a dead IP:Port \((.+?) unique times\)$/i,
      "응답 없는 IP:Port에 연결을 시도함 (고유 $1회)"
    ],
    [
      /^Executed a command line with \/C or \/R argument to terminate command shell on completion which can be used to hide execution$/i,
      "/C 또는 /R 인자를 사용해 완료 후 명령 셸을 종료하는 명령줄을 실행함 (실행 흔적 은폐 가능성)"
    ],
    [
      /^Queries the Volume Serial Number or Physical Hardware ID, possibly for anti-sandbox, victim profiling or environmental keying$/i,
      "안티샌드박스, 피해자 식별 또는 환경 키잉을 위해 볼륨 시리얼 번호 또는 물리 하드웨어 ID를 조회함"
    ],
    [
      /^Modifies the memory protection of ntdll\.dll to PAGE_READWRITE, indicative of EDR unhooking$/i,
      "EDR 언후킹을 시사하는 ntdll.dll의 메모리 보호 속성을 PAGE_READWRITE로 변경함"
    ],
    [
      /^Inter-process synchronization via mutexes, possibly for routing local C2 traffic or injection$/i,
      "로컬 C2 트래픽 전달 또는 인젝션을 위해 뮤텍스를 통한 프로세스 간 동기화를 수행함"
    ],
    [
      /^Inter-process communication via named shared memory \(file mappings\), possibly for routing local C2 traffic or injection$/i,
      "로컬 C2 트래픽 전달 또는 인젝션을 위해 이름 있는 공유 메모리(파일 매핑)를 통한 프로세스 간 통신을 수행함"
    ],
    [
      /^Altered memory protections from dynamically allocated \(unbacked\) memory, indicative of self-modifying shellcode or memory patching$/i,
      "동적 할당(비백업) 메모리에서 메모리 보호 속성을 변경함 (자기 수정 쉘코드 또는 메모리 패치 가능성)"
    ],
    [
      /^Paused execution \(sleep\/delay\) in a thread executing in dynamically allocated \(unbacked\) memory, indicative of sandbox evasion or C2 sleeping between callbacks$/i,
      "동적 할당(비백업) 메모리에서 실행 중인 스레드가 sleep/delay로 일시 중지됨 (샌드박스 회피 또는 C2 콜백 간 대기 가능성)"
    ],
    [
      /^Network connection initiated from dynamically allocated \(unbacked\) memory, indicative of fileless C2 activity$/i,
      "동적 할당(비백업) 메모리에서 네트워크 연결을 시작함 (파일리스 C2 활동 가능성)"
    ]
  ];

  function translateText(text) {
    const original = (text || "").trim();
    if (!original) return "";
    if (exactMap[original]) return exactMap[original];
    for (const [re, replacement] of regexRules) {
      if (re.test(original)) return original.replace(re, replacement);
    }
    return "";
  }

  function hasHangul(text) {
    return /[가-힣]/.test(text || "");
  }

  const signatureRoot = document.querySelector("#signatures") || document;
  const items = Array.from(signatureRoot.querySelectorAll(".list-group-item, .card, .panel, .accordion-item, tr"))
    .filter(el => (el.innerText || "").trim().length > 0);

  function candidateNodes(container) {
    return Array.from(container.querySelectorAll("p, div, span, small, td, li"))
      .filter(el => {
        const txt = (el.textContent || "").trim();
        if (!txt) return false;
        if (txt.startsWith("이름:")) return false;
        if (txt.startsWith("한글 설명:")) return false;
        if (txt.length < 12 || txt.length > 420) return false;
        return true;
      });
  }

  items.forEach(item => {
    const nodes = candidateNodes(item);
    if (!nodes.length) return;

    nodes.sort((a, b) => (b.textContent || "").trim().length - (a.textContent || "").trim().length);
    const target = nodes[0];
    const original = (target.childNodes[0] && target.childNodes[0].textContent ? target.childNodes[0].textContent : target.textContent || "").trim();
    const ko = translateText(original);
    if (!ko || !hasHangul(ko)) return;

    const oldHints = item.querySelectorAll(".ko-signature-hint");
    oldHints.forEach(h => h.remove());

    const hint = document.createElement("div");
    hint.className = "ko-signature-hint";
    hint.style.fontSize = "0.86em";
    hint.style.marginTop = "4px";
    hint.style.opacity = "0.92";
    hint.style.lineHeight = "1.4";
    hint.textContent = "한글 설명: " + ko;
    target.appendChild(hint);
  });
});
</script>
"""

def main():
    if not TARGET.exists():
        raise SystemExit(f"대상 파일이 없습니다: {TARGET}")

    text = TARGET.read_text(encoding="utf-8")
    if "signature-ko-manual-fix-script" in text:
        print("이미 manual fix 블록이 적용되어 있습니다.")
        return

    shutil.copy2(TARGET, BACKUP)
    text = text.rstrip() + "\n\n" + JS_BLOCK.strip() + "\n"
    TARGET.write_text(text, encoding="utf-8")
    print(f"적용 완료: {TARGET}")
    print(f"백업 생성: {BACKUP}")

if __name__ == "__main__":
    main()
