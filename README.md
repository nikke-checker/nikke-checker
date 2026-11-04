# NIKKE PC 런처 감염 점검 도구

[English](README.en.md)

[Releases](https://github.com/nikke-checker/nikke-checker/releases/latest) 에서 `NikkeChecker.exe` 를 내려받아 실행합니다.
설치가 필요 없습니다 (Windows 10/11 기본 .NET Framework 4.8 사용).
영어 화면은 `NikkeChecker_EN.exe` (같은 프로그램)이고, 프로그램 오른쪽 위에서도 언어를 바꿀 수 있습니다.
한국어가 아닌 Windows 에서는 처음부터 영어로 열립니다.

2026년 9월 27일 Level Infinite CDN 의 스크립트 4개가 변조되어, NIKKE PC 런처가 `insightjs.com/l.js` 를 불러왔습니다.
10월 23일부터는 일부 실행 시 원격 제어 에이전트(`insight.bundle`)가 내려받아져 실행되었습니다.
Level Infinite 는 11월 4일 수정을 발표했지만, 공격자가 CDN 에 어떻게 접근했는지는 아직 알려지지 않았습니다.
런처를 다시 열기 전에 런처 캐시(`tbs_cache`)를 지우고, 차단은 유지하세요.

**공식 안내 (11월 4일, 레벨 인피니트)**: 9월 27일 15:41(UTC+9) 이후 Windows PC 런처를 한 번이라도 실행했다면 점검이 필요합니다. 모바일 버전은 영향이 없습니다.
공식 PC 클라이언트의 보안 기능(ACE)으로도 점검할 수 있습니다. 이 도구는 공식 안내의 수동 점검 기준(`debug.log` 의 `k2f_chan registered`, `HKCU\Software\Classes\CLSID` 의 키, DLL 이 든 64자리 폴더, `Launcher\log\tinyget` 의 205,135 bytes 파일, `tbs_cache`)을 모두 포함합니다.

## 점검 항목 (체크한 항목만 점검)

| # | 항목 | 감염(●) | 노출(▲) |
|---|---|---|---|
| 1 | 브라우저 지속성 DLL | Chromium 계열 14종(Chrome·Edge·Brave·Vivaldi·Opera·Opera GX·Chromium·네이버 웨일·Arc·Yandex·Cốc Cốc·Comodo Dragon·Thorium·Epic) `User Data\PlatformExperienceHelper` 에서 `platform_experience_helper.dll` 이 든 64자리 폴더(공식 안내 기준. DLL 이 없는 64자리 폴더는 참고로만 표시하고 지우지 않음) 또는 그 밖의 `platform_experience_helper.dll`, 구버전 `Chrome\Application\PlatformExperienceHelper` 의 `platform_experience_helper.dll(.old)`·`old-clsid.txt` | |
| 2 | 레지스트리 CLSID | `HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}` (DLL 경로 또는 빈 잔여 키)와 그 키가 가리키는 DLL 파일. 같은 이름의 키가 다른 경로에도 있으므로(공식 안내) `WOW6432Node` 쪽은 악성 위치를 가리킬 때만 판정·삭제. 다른 이름의 CLSID 라도 `InprocServer32` 가 `PlatformExperienceHelper` 나 브라우저 `User Data` 를 가리키면 같은 수법으로 판정 | |
| 3 | 실행 중 프로세스 | `platform_experience_helper*` 모듈이 로드된 프로세스. 실행 중인 런처(`nikke_launcher*`)는 같은 점검에서 다른 감염 흔적이 있을 때만 감염, 없으면 참고 | |
| 4 | 런처 데이터 `%APPDATA%\nikke_launcher(_hmt, _google)` 와 런처 로그인 브라우저 프로필 `%LOCALAPPDATA%\CEF\User Data` | `k2f.agent` / `k2f_chan` (압축된 LevelDB `.ldb` 테이블을 풀어서도 찾음), HSTS(`TransportSecurity`)·`Network Persistent State` 의 analytics.insightjs.com | `Cache`/`Code Cache` 의 insightjs, HSTS 의 insightjs.com/org, `Reporting and NEL` |
| 5 | 임시 폴더 | `k2f-bcreds-*`(탈취한 자격 증명), `k2f-keyscan-*`(수집한 키·인증 파일), `k2f_screen_*`(화면 캡처) — 이름이 `k2f-`·`k2f_`·`k2f.` 로 시작하는 것만 | |
| 6 | 전체 드라이브 파일 이름 | 정해진 위치 밖의 `platform_experience_helper.dll*`, LuaJIT 바이트코드로 시작하는 `insight.bundle`·`k2f.lua`·`tinyget*`, `k2f-bcreds*`·`k2f-keyscan*`·`k2f_screen*`·`k2f.agent*` (클라우드 드라이브·`\Windows`·정션 제외). 임시 폴더 밖의 `k2f-*` 와 사용자 폴더 밖의 DLL 은 보고만 하고 자동 삭제하지 않음. 찾은 `nikke_launcher.exe` 는 설치 폴더 후보로 사용 | |
| 7 | 니케 설치 폴더 | `debug.log` 의 `k2f_chan`·`agent started as`·`lua downloaded to`·`adopted/resuming <uuid>`·analytics.insightjs.com·insight.bundle, `Launcher\log` 의 **끝까지 받아진** insight.bundle 다운로드 기록, LuaJIT 바이트코드(`1B 4C 4A`) 또는 `k2f*` 에이전트 파일, 로그로 위장한 `Launcher\log\tinyget\tinyget.<날짜>-<시간>.log` 중 알려진 에이전트 크기(205,135 / 165,108 bytes)인 파일 | insightjs 만 있는 로그, 받지 못한(서버 무응답) insight.bundle 요청 |
| 8 | 자동 실행 프로그램 (확인 필요) | 9월 27일 이후 생겼고 제작사 서명(파일·카탈로그)이 없는 자동 실행 대상: 자동 실행 목록(HKCU·HKLM Run/RunOnce), 시작 프로그램 폴더, 작업 스케줄러, 서비스(svchost 는 ServiceDll), WMI 이벤트 소비자. 숨겨진 PowerShell·mshta 명령은 위험 높음으로 표시. 각 파일을 Windows Defender 로 검사. **판정에는 영향 없음** | |
| 9 | 추가 보안 점검 | **지금 해커 서버(89.127.233.127, 89.126.250.172)와 연결 중인 프로그램** | **해커 주소 DNS 캐시 기록** |
|   | (확인 필요, 판정 영향 없음) | 원격 조종 모드(`--remote-debugging-*`, `--load-extension`)로 켜진 브라우저와 그런 바로가기, 정책으로 강제 설치되는 확장, 위험한 Windows Defender 검사 제외(드라이브 전체·AppData·Temp·실행 파일 확장자 등), 9/27 이후 설치되거나 실행 중인 원격 접속 프로그램(AnyDesk·TeamViewer 등), 프록시·자동 설정(PAC), Winlogon Shell·Userinit 변경, IFEO Debugger, AppInit_DLLs | |
| 10 | 차단 상태 (참고) | hosts 의 7개 도메인(insightjs.com·www·analytics·portal·docs, insightjs.org·analytics), 방화벽 규칙 내용(사용·아웃바운드·차단·두 IP) | |

설치 폴더는 레지스트리 Uninstall 아래 NIKKE 키의 `GameInstallPath`·`InstallLocation`·`DisplayIcon`·`UninstallString`, `nikkelauncher` 프로토콜, `url_protocol.reg`, 전체 드라이브 검사 결과에서 찾고, 없으면 드라이브를 탐색합니다.
`tinyget.mem.log` 의 ETag 로 내려받은 에이전트 빌드(업로드 시각, 크기)를 보여 줍니다 (알려진 빌드 7개).
읽지 못한 파일은 보고서에 "검사가 불완전한 파일"로 남깁니다.
PC 전체 범위(HKLM, 작업 스케줄러, 서비스, WMI, Defender 설정)는 관리자 권한이 있어야 읽을 수 있어, 8·9번 항목은 점검할 때 UAC 를 한 번 요청합니다 (읽기만 함).

**판정**
- *감염*: 감염 흔적이 지금 남아 있음 (파일·등록·연결 등)
- *감염됐던 기록 (과거 기록)*: 런처 로그(`debug.log`, 다운로드 기록)에만 흔적이 남음. 로그라서 다시 검사해도 계속 나오지만, 지금 해킹 파일이 남아 있다는 뜻은 아님. 비밀번호는 꼭 변경
- *노출*: 노출 흔적만 있음
- *흔적 없음* / *찾지 못함*

## 화면

시작 → 점검 중 → 결과 → 정리 완료의 4단계 화면입니다. 시작 화면에서 [점검 시작]만 누르면 되고, 점검 항목 고르기와 설치 경로 지정은 「고급 설정」에 있습니다.
결과 화면은 판정 배너와 발견한 것을 항목별 카드로 보여 주고, 정리 완료 화면에서는 해야 할 일(비밀번호 변경 등)을 체크리스트로 보여 줍니다.
점검 기록은 「자세히 보기」에서 보고, 보고서는 그 기록을 그대로 저장합니다.

## 정리 ([정리하기], 확인 창 → 보고서를 바탕화면에 자동 저장 → 실행. 보고서를 저장하지 못하면 아무것도 지우지 않음)

1. 런처와 게임 종료
2. HKCU CLSID 키 삭제 (먼저 끊어야 브라우저가 DLL 을 다시 로드하지 않음)
3. 악성 DLL 을 로드한 프로세스, 해커 서버와 연결 중인 프로그램(Windows 프로그램 제외), 해당 브라우저 종료 (explorer.exe 제외)
4. 64자리 폴더 / DLL 삭제 — 잠겨 있으면 **Windows 재시작 후 다시 실행**하라고 안내
5. 런처 캐시 `tbs_cache` 삭제 (흔적이 없어도 권장 옵션), 흔적이 있던 런처 로그인 브라우저 프로필(CEF) 삭제(런처 로그인만 다시 하면 됨), DNS 캐시 비우기
6. Temp 의 `k2f*` 파일, 저장된 에이전트 파일, 전체 드라이브 검사에서 찾은 파일 삭제 (로그 자체는 증거로 남김)
7. 「확인 필요」 항목: 목록 창에서 **직접 고른 것만** 정리. Defender 가 악성으로 확인한 항목은 미리 체크됨
   - 자동 실행: 등록을 끊고 실행되던 파일 삭제. **Windows·Program Files 안 파일은 등록만 끊음**
   - 브라우저는 끄기만, 바로가기는 원격 조종 옵션만 지움, 설정은 끄거나 Windows 기본값으로 되돌림, Defender 제외는 목록에서만 뺌
   - 원격 접속 프로그램: 끄고, PC 전체 설치본이면 공식 제거 프로그램만 띄움 (사용자 영역에 등록된 제거 명령은 바뀌었을 수 있어 실행하지 않음)
8. (관리자, UAC) Program Files 의 구버전 지속성 파일과 PC 전체 범위 항목 정리, hosts 에 7개 도메인 차단, 방화벽에서 `89.127.233.127`, `89.126.250.172` 아웃바운드 차단 (규칙 내용이 다르면 다시 만듦)
9. (선택) Windows Defender 오프라인 검사: 재부팅 전에 한 번 더 묻고, Defender 가 주 백신이 아니거나 BitLocker 가 켜져 있거나 Windows 복구 환경이 꺼진 PC 에서는 대신 「전체 검사」 방법을 안내. 24시간 안에 이미 했으면 건너뜀

**니케 완전 삭제 (선택, 결과·정리 완료 화면의 「니케 완전 삭제…」)** — 니케를 계속 할 사람은 쓰지 않습니다. 두 번 확인한 뒤 설치 폴더(게임·런처), 런처 데이터, 게임 데이터(`AppData\LocalLow`, 약 5GB), 내려받은 설치 파일(`nikkeminiloader*.exe`), 「설치된 앱」 등록·`nikkelauncher://`·게임 설정, 바로가기를 지웁니다. 계정과 진행 상황은 서버에 있어 지워지지 않습니다.
- 지울 런처 폴더는 `nikke_launcher.exe` 가 있고 이름이 `Launcher` 이거나 `nikke` 가 들어간 폴더만 (상위가 `NIKKE` 이면 그 폴더)
- 바탕 화면·문서·다운로드처럼 사용자 폴더 바로 아래 폴더, 드라이브 전체, Windows·Program Files·사용자 폴더 자체는 제외
- 같은 회사(`com.proximabeta`)의 다른 게임 데이터·설정은 건드리지 않고 이름에 `nikke` 가 든 하위 폴더·키만
- 런처가 깔아 둔 실행 파일(제거 프로그램 등)은 실행하지 않음

**안전**
- 프로그램은 일반 권한으로 실행되고, 관리자 작업만 UAC 로 승격한 자기 자신에게 맡깁니다 (관리자 계정이 달라도 실제 사용자의 HKCU/AppData 를 점검하기 위해).
- 승격된 프로세스는 요청된 경로·항목을 같은 규칙으로 스스로 다시 확인한 것만 처리합니다 (구버전 지속성 파일, 다시 점검해 찾은 「확인 필요」 항목, 니케 폴더 규칙을 통과한 폴더 등).
- Program Files·Windows·시스템 프로그램 경로는 환경 변수가 아니라 Windows API 로 얻고, `sc.exe`·`ipconfig.exe`·`netstat.exe`·`msiexec.exe` 는 System32 전체 경로로 실행합니다.
- 상위 폴더에 정션·심볼릭 링크가 있는 경로는 엉뚱한 곳을 지울 수 있어 삭제하지 않고 직접 확인하라고 안내합니다.

조치 후에도 감염 판정이었다면 깨끗한 기기에서 비밀번호 변경, 브라우저 설정에서 쿠키 삭제, 모든 세션 로그아웃, 토큰·SSH 키·클라우드 CLI 자격 증명 재발급, 지갑 이전을 하세요.
다른 Windows 사용자 계정도 이 PC 를 쓴다면 그 계정으로 로그인해 한 번 더 실행하세요 (HKCU 와 AppData 는 계정마다 따로 있음).
흔적이 없다고 깨끗함이 보장되지는 않습니다.

## 빌드
```
cd src
dotnet build -c Release
```
결과물: `src/bin/Release/net48/NikkeChecker.exe` (Linux 에서도 빌드됩니다)

## 릴리스
`src/NikkeChecker.csproj` 의 `<Version>` 을 올려 main 에 푸시하면 GitHub Actions(ubuntu-latest)가
`v<Version>` 릴리스가 아직 없을 때 자동으로 빌드해, 그 커밋에 태그를 만들고 릴리스에 exe 와 SHA-256 을 올립니다.
같은 버전의 릴리스가 이미 있으면 건너뜁니다. (`v*` 태그를 직접 푸시해도 같은 동작을 합니다.)

릴리스 exe 에는 빌드 출처 증명(artifact attestation)이 붙습니다. 내려받은 파일이 이 리포지토리의
Actions 에서 공개 소스로 빌드된 것인지 [GitHub CLI](https://cli.github.com/) 로 확인할 수 있습니다.
```
gh attestation verify NikkeChecker.exe --repo nikke-checker/nikke-checker
gh attestation verify NikkeChecker_EN.exe --repo nikke-checker/nikke-checker
```

## 참고 자료
이 도구의 코드는 이 저장소에서 새로 작성했고, 다른 도구의 코드를 가져오지 않았습니다. 진단 규칙은 아래 공개 자료를 참고했습니다.
- [MotherSphere/NIKKE-Launcher-Check](https://github.com/MotherSphere/NIKKE-Launcher-Check) (0.5.1 까지)와 [분석 글](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5) — 이 사고를 처음 분석한 자료. IoC, HSTS 키, 에이전트 빌드 ETag, 다운로드 완료 판정, LevelDB 압축 테이블, 런처 로그인 브라우저 프로필 규칙
- [햄찌](https://x.com/choi_hamzzi)의 NIKKE_k2f_cleaner (v3.1~v4.5) — 전체 드라이브 이름 검사, 자동 실행·추가 보안 점검 항목, Defender 개별·오프라인 검사, 과거 기록 판정, 니케 완전 삭제와 그 안전장치 등의 점검 아이디어를 참고
