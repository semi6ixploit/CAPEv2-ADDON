현재 업로드된 cape_signature_catalog.json 기준으로 거의 전체 시그니처 설명에 대한 한글 보조설명을 추가하는 스크립트입니다.
백엔드 Python 파일을 건드리지 않고 _signatures.html 끝에 JS를 붙이는 방식이라 비교적 안전합니다.

적용:
cd /opt/CAPEv2
sudo cp web/templates/analysis/overview/_signatures.html web/templates/analysis/overview/_signatures.html.bak.catalogpre
sudo python3 /mnt/data/cape_apply_signature_ko_from_catalog_full.py
sudo systemctl restart cape-web
sudo systemctl status cape-web --no-pager -l

그다음 브라우저에서 Ctrl+Shift+R 강력 새로고침

참고:
- cape_signature_catalog_ko_autofill.json / .csv 에 자동 번역 결과가 들어 있습니다.
- 원문과 1:1 매칭 위주라 현재 설치된 시그니처에는 기존 100키워드 방식보다 훨씬 넓게 적용됩니다.
- {0}, {1} 같은 자리표시자가 있는 시그니처는 정규식 규칙으로 처리합니다.
