# NIKKE PC 런처 감염 점검 도구

[Releases](https://github.com/lunaiz-corp/nikke-checker/releases/latest) 에서 `NikkeChecker.exe` 를 내려받아 실행합니다.
설치가 필요 없습니다 (Windows 10/11 기본 .NET Framework 4.8 사용).

2026년 9월 27일 Level Infinite CDN 의 스크립트 4개가 변조되어, NIKKE PC 런처가 `insightjs.com/l.js` 를 불러왔습니다.
10월 23일부터는 일부 실행 시 원격 제어 에이전트(`insight.bundle`)가 내려받아져 실행되었습니다.

## 점검 항목 (체크한 항목만 점검)

| # | 항목 | 감염(●) | 노출(▲) |
|---|---|---|---|
| 1 | 브라우저 지속성 DLL | Chrome·Edge·Brave·Vivaldi·Opera·Opera GX·Chromium `User Data\PlatformExperienceHelper` 의 64자리 폴더(DLL 이 없어도) 또는 `platform_experience_helper.dll`, 구버전 `Chrome\Application\PlatformExperienceHelper` 의 `platform_experience_helper.dll(.old)`·`old-clsid.txt` | |
| 2 | 레지스트리 CLSID | `HKCU\Software\Classes\(WOW6432Node\)CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}` (DLL 경로 또는 빈 잔여 키), 64자리 폴더 DLL 을 가리키는 변종 CLSID | |
| 3 | 실행 중 프로세스 | 런처 실행 중, 악성 DLL 이 로드된 프로세스 | |
| 4 | 런처 데이터 `%APPDATA%\nikke_launcher(_hmt)` | `k2f.agent` / `k2f_chan`, HSTS(`TransportSecurity`)·`Network Persistent State` 의 analytics.insightjs.com | `Cache`/`Code Cache` 의 insightjs, HSTS 의 insightjs.com/org, `Reporting and NEL` |
| 5 | 임시 폴더 | `k2f-bcreds-*`(탈취한 자격 증명), `k2f_screen_*.jpg`(화면 캡처) | |
| 6 | 니케 설치 폴더 | `debug.log` 의 `k2f_chan`·analytics.insightjs.com·insight.bundle, `Launcher\log` 의 insight.bundle 다운로드 기록, LuaJIT 바이트코드(`1B 4C 4A`) 에이전트 파일 | insightjs 만 있는 로그 |
| 7 | 유출 가능 데이터 (참고) | 저장된 비밀번호가 있는 브라우저 프로필, 지갑 확장 28종, 인증 파일(SSH 키, 클라우드 CLI 토큰 등) — 존재 여부만 확인하고 열지 않음 | |
| 8 | 차단 상태 (참고) | hosts 의 세 도메인, 방화벽 규칙 | |

설치 폴더는 레지스트리 `GameInstallPath`·`UninstallString`, `nikkelauncher` 프로토콜, `url_protocol.reg` 에서 먼저 찾고, 없으면 드라이브를 탐색합니다.
`tinyget.mem.log` 의 ETag 로 내려받은 에이전트 빌드(업로드 시각, 크기)를 보여 줍니다.

**판정**: 감염 흔적이 하나라도 있으면 *감염*, 노출 흔적만 있으면 *노출*, 없으면 *흔적 없음*, NIKKE 를 못 찾으면 *찾지 못함*.

## 조치 ([조치 실행], 확인 창 → 보고서를 바탕화면에 자동 저장 → 실행)

1. 런처 종료
2. HKCU CLSID 키 삭제 (먼저 끊어야 브라우저가 DLL 을 다시 로드하지 않음)
3. 악성 DLL 을 로드한 프로세스와 해당 브라우저 종료 (explorer.exe 제외)
4. 64자리 폴더 / DLL 삭제 — 잠겨 있으면 **Windows 재시작 후 다시 실행**하라고 안내
5. 런처 캐시 `tbs_cache` 삭제 (흔적이 없어도 권장 옵션)
6. Temp 의 `k2f*` 파일, 저장된 에이전트 파일 삭제 (로그 자체는 증거로 남김)
7. (관리자, UAC) Program Files 의 구버전 지속성 파일 삭제, hosts 에 세 도메인 차단, 방화벽에서 `89.127.233.127`, `89.126.250.172` 아웃바운드 차단
8. (선택) 브라우저 쿠키 초기화

프로그램은 일반 권한으로 실행되고, 관리자 작업만 UAC 로 승격한 자기 자신에게 맡깁니다.
관리자 계정이 다른 경우에도 실제 사용자의 HKCU/AppData 를 점검하기 위해서입니다.
승격된 프로세스는 정해진 구버전 지속성 파일 외에는 삭제하지 않습니다.

조치 후에도 감염 판정이었다면 깨끗한 기기에서 비밀번호 변경, 모든 세션 로그아웃, 토큰·SSH 키 재발급, 지갑 이전을 하세요.
흔적이 없다고 깨끗함이 보장되지는 않습니다.

## 빌드
```
cd src
dotnet build -c Release
```
결과물: `src/bin/Release/net48/NikkeChecker.exe`

## 참고
진단 규칙(IoC, HSTS 키, 에이전트 빌드 ETag, 지갑 확장·인증 파일 목록)은 이 사고를 처음 분석한
[MotherSphere/NIKKE-Launcher-Check](https://github.com/MotherSphere/NIKKE-Launcher-Check) 의 문서와
[분석 글](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5)을 바탕으로 했습니다.
코드는 이 저장소에서 새로 작성했습니다.
