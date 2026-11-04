# NIKKE PC 런처 감염 점검 도구

[Releases](https://github.com/lunaiz-corp/nikke-checker/releases/latest) 에서 `NikkeChecker.exe` 를 내려받아 더블클릭해 실행합니다. 설치가 필요 없습니다 (Windows 10/11 기본 .NET Framework 4.8 사용).

## 점검 항목 (체크한 항목만 점검)
1. 브라우저 `User Data\PlatformExperienceHelper\<64자리>\platform_experience_helper.dll` (Chrome, Edge, Brave, Vivaldi, Opera, Opera GX)
2. `HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}` 와,
   서버 DLL 이 위 64자리 폴더의 DLL 을 가리키는 변종 CLSID
3. 런처 Local Storage(leveldb) 내 `k2f.agent`
4. 런처 tbs_cache 내 `insightjs.com / insightjs.org`
5. 런처 로그 `debug.log`, `tinyget.*.log` (감염 이력 증거, 삭제하지 않음)

## 조치 ([조치 실행], 확인 창을 거친 뒤 실행)
- 발견 항목 삭제: 64자리 폴더 전체 / CLSID 키 / 런처 tbs_cache
- hosts 에 `insightjs.com`, `analytics.insightjs.com`, `insightjs.org` 차단 등록과
  방화벽 아웃바운드 규칙으로 `89.127.233.127` 차단 (hosts 는 IP 를 막을 수 없어서 방화벽 사용)
- (선택) 브라우저 쿠키 초기화

프로그램은 일반 권한으로 실행되고, hosts/방화벽 차단을 할 때만 UAC 로 관리자 권한을 요청합니다.
관리자 계정이 다른 경우에도 실제 사용자의 HKCU/AppData 를 점검하기 위해서입니다.

## 빌드
```
cd src
dotnet build -c Release
```
결과물: `src/bin/Release/net48/NikkeChecker.exe`

## 릴리스
`v*` 태그를 푸시하면 GitHub Actions 가 Windows 에서 빌드하고 exe 를 릴리스에 첨부합니다.
```
git tag v1.0.1
git push origin v1.0.1
```
