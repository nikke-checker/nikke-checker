using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;
using static NikkeChecker.I18n;

namespace NikkeChecker
{
    public sealed class Scanner
    {
        private const long MaxFileBytes = 64L * 1024 * 1024;
        private const int MaxEvidence = 5;

        private readonly Logger _log;
        private readonly CancellationToken _ct;
        private ScanResult _r;

        public Scanner(Logger log, CancellationToken ct) { _log = log; _ct = ct; }

        private static (CheckId Id, string Title)[] Order => new[]
        {
            (CheckId.Clsid,        L("레지스트리 HKCU CLSID 지속성", "Registry HKCU CLSID persistence")),
            (CheckId.BrowserDll,   L("브라우저 지속성 DLL (PlatformExperienceHelper)", "Browser persistence DLL (PlatformExperienceHelper)")),
            (CheckId.Processes,    L("실행 중인 런처 / 악성 DLL 로드 여부", "Running launcher / loaded malicious DLL")),
            (CheckId.LauncherData, L("런처 데이터 폴더 (k2f.agent, insightjs 캐시, HSTS·네트워크 기록)", "Launcher data folder (k2f.agent, insightjs cache, HSTS and network records)")),
            (CheckId.Temp,         L("임시 폴더 k2f 파일", "k2f files in the temp folder")),
            (CheckId.FullScan,     L("전체 드라이브 파일 이름 검사 (k2f*, insight.bundle, tinyget*, platform_experience_helper.dll)", "File-name scan of all drives (k2f*, insight.bundle, tinyget*, platform_experience_helper.dll)")),
            (CheckId.InstallLogs,  L("니케 설치 폴더 로그 / 저장된 에이전트 파일", "NIKKE install folder logs / saved agent files")),
            (CheckId.Autostart,    L("9월 27일 이후 새로 생긴, 제작사 서명 없는 자동 실행 프로그램", "New unsigned autostart programs since Sep 27")),
            (CheckId.Extra,        L("추가 보안 점검 (해커 서버 연결·DNS 기록, 브라우저 원격 조종, Defender 제외, 원격 접속, 프록시, Winlogon·IFEO·AppInit)",
                                     "Extra checks (hacker server connections, DNS, browser remote control, Defender exclusions, remote access, proxy, Winlogon/IFEO/AppInit)")),
            (CheckId.Protection,   L("차단 상태 (hosts / 방화벽)", "Block status (hosts / firewall)")),
        };

        public ScanResult Run(ScanOptions opt)
        {
            _r = new ScanResult();
            var todo = Order.Where(o => opt.Checks.Contains(o.Id)).ToList();
            for (int i = 0; i < todo.Count; i++)
            {
                _ct.ThrowIfCancellationRequested();
                var (id, title) = todo[i];
                _log($"[{i + 1}/{todo.Count}] {title}", LogLevel.Header);
                opt.OnStepStart?.Invoke(id, i + 1, todo.Count);
                _r.Checked.Add(id);
                int before = _r.Findings.Count;
                switch (id)
                {
                    case CheckId.Clsid: CheckClsid(); break;
                    case CheckId.BrowserDll: CheckBrowserDll(); break;
                    case CheckId.Processes: CheckProcesses(); break;
                    case CheckId.LauncherData: CheckLauncherData(); break;
                    case CheckId.Temp: CheckTemp(); break;
                    case CheckId.FullScan: CheckFullScan(); break;
                    case CheckId.InstallLogs: CheckInstalls(opt.InstallPath); break;
                    case CheckId.Autostart: CheckAutostart(opt.AuditSystem); break;
                    case CheckId.Extra: CheckExtra(opt.AuditSystem); break;
                    case CheckId.Protection: CheckProtection(); break;
                }
                if (!_r.Findings.Skip(before).Any(f => f.Severity != Severity.Info) && !_r.Unknown.ContainsKey(id))
                    _log(L("  [-] 악성 흔적 없음", "  [-] No malicious traces"), LogLevel.Ok);
                opt.OnStepDone?.Invoke(id, StepSummary.Of(_r, id));
            }
            DedupeFullScan();
            // 실행 중인 런처는 같은 점검에서 다른 감염 흔적이 있을 때만 감염. 없으면 깨끗하거나 새로 설치한 런처라 참고로만 (MotherSphere 0.5.0)
            if (!_r.Findings.Any(f => f.Severity == Severity.Critical && !f.LauncherRunning && !f.Past))
                foreach (var f in _r.Findings.Where(f => f.LauncherRunning))
                {
                    f.Severity = Severity.Info; f.Fix = FixKind.None;
                    f.Title = L($"런처가 실행 중 ({f.Target}.exe, PID {f.Pid}) — 다른 감염 흔적이 없어 참고로만 표시", $"The NIKKE launcher is running ({f.Target}.exe, PID {f.Pid}) - no other sign of the agent, shown for reference");
                }
            if (_r.Unreadable.Count > 0)
                _log(L($"  ※ 읽지 못해 검사가 불완전한 파일 {_r.Unreadable.Count}개 (보고서 끝에 목록)", $"  * Files that could not be fully checked: {_r.Unreadable.Count} (listed at the end of the report)"), LogLevel.Warn);
            return _r;
        }

        private Finding Add(CheckId check, Severity sev, string title, IEnumerable<string> evidence = null,
            FixKind fix = FixKind.None, string target = null, int pid = 0, string browser = null, string hint = null)
        {
            var f = new Finding { Check = check, Severity = sev, Title = title, Fix = fix, Target = target, Pid = pid, Browser = browser, BrowserHint = hint };
            if (evidence != null) f.Evidence.AddRange(evidence);
            _r.Findings.Add(f);
            string tag = sev == Severity.Critical ? L("[!!] 감염", "[!!] INFECTED") : sev == Severity.Warning ? L("[!] 노출", "[!] EXPOSED")
                       : sev == Severity.Review ? L("[?] 확인 필요", "[?] CHECK") : "[i]";
            _log($"  {tag} {title}", sev == Severity.Critical ? LogLevel.Bad : sev == Severity.Warning || sev == Severity.Review ? LogLevel.Warn : LogLevel.Info);
            foreach (var e in f.Evidence) _log("        " + e, LogLevel.Detail);
            return f;
        }

        // ------------------------------------------------------------------
        // 1. HKCU CLSID {E77CC89B-...} (64비트 / WOW6432Node)
        // ------------------------------------------------------------------
        private void CheckClsid()
        {
            foreach (var key in Iocs.ClsidKeys)
            {
                using (var k = OpenHkcu(key))
                {
                    if (k == null) continue;
                    string val;
                    using (var s = k.OpenSubKey("InprocServer32")) val = s?.GetValue("") as string;
                    if (!string.IsNullOrWhiteSpace(val))
                    {
                        var expanded = Environment.ExpandEnvironmentVariables(val.Trim().Trim('"'));
                        _r.HkcuDllPath = _r.HkcuDllPath ?? expanded;
                        Add(CheckId.Clsid, Severity.Critical, L($"레지스트리 지속성 (CLSID 하이재킹): HKCU\\{key}", $"Registry persistence (CLSID hijack): HKCU\\{key}"),
                            new[] { "InprocServer32 = " + val }, FixKind.DeleteRegistryKey, key);
                        // 키가 가리키는 파일이 정확히 그 DLL 이름의 "파일"일 때만 삭제 대상 (다른 파일을 지우게 유도당하지 않도록)
                        var leaf = Path.GetFileName(expanded);
                        if ((leaf.Equals(Iocs.DllName, StringComparison.OrdinalIgnoreCase) || leaf.Equals(Iocs.DllName + ".old", StringComparison.OrdinalIgnoreCase))
                            && File.Exists(expanded))
                            Add(CheckId.Clsid, Severity.Critical, L($"레지스트리가 가리키는 지속성 DLL: {expanded}", $"Persistence DLL named by the registry: {expanded}"), null,
                                FileUtil.IsUnderUserProfile(expanded) ? FixKind.DeleteFile : FixKind.None, expanded, browser: "chrome");
                    }
                    else
                    {
                        Add(CheckId.Clsid, Severity.Critical, L($"지속성 잔여 키 (기본값 비어 있음): HKCU\\{key}", $"Leftover persistence key (empty default value): HKCU\\{key}"),
                            new[] { L("에이전트의 chrome_uninstall 은 값만 지우고 키를 남깁니다. DLL 이 디스크에 남아 있을 수 있습니다.", "The agent's chrome_uninstall clears only the value and leaves the key. The DLL may still be on disk.") },
                            FixKind.DeleteRegistryKey, key);
                    }
                }
            }

            // 변종: 같은 수법에 다른 CLSID 이름을 쓴 경우 (whykusanagi 분석, 햄찌 v4.2).
            // InprocServer32 가 브라우저 User Data 나 PlatformExperienceHelper 를 가리키면 같은 등록으로 본다
            foreach (var clsidRoot in new[] { Iocs.ClsidRoot, @"Software\Classes\WOW6432Node\CLSID" })
            {
                using (var root = OpenHkcu(clsidRoot))
                {
                    if (root == null) continue;
                    foreach (var name in root.GetSubKeyNames())
                    {
                        if (name.Equals(Iocs.BadClsid, StringComparison.OrdinalIgnoreCase)) continue;
                        string val;
                        try { using (var sk = root.OpenSubKey(name + "\\InprocServer32")) val = sk?.GetValue("") as string; }
                        catch { continue; }
                        if (string.IsNullOrEmpty(val)) continue;
                        var expanded = Environment.ExpandEnvironmentVariables(val.Trim().Trim('"'));
                        var key = clsidRoot + "\\" + name;
                        if (Regex.IsMatch(expanded, @"\\PlatformExperienceHelper\\|\\User Data\\", RegexOptions.IgnoreCase))
                        {
                            Add(CheckId.Clsid, Severity.Critical, L($"변종 CLSID 하이재킹 (다른 이름): HKCU\\{key}", $"Variant CLSID hijack (other name): HKCU\\{key}"),
                                new[] { "InprocServer32 = " + val }, FixKind.DeleteRegistryKey, key);
                            var leaf = Path.GetFileName(expanded);
                            if ((leaf.Equals(Iocs.DllName, StringComparison.OrdinalIgnoreCase) || leaf.Equals(Iocs.DllName + ".old", StringComparison.OrdinalIgnoreCase)) && File.Exists(expanded))
                                Add(CheckId.Clsid, Severity.Critical, L($"레지스트리가 가리키는 지속성 DLL: {expanded}", $"Persistence DLL named by the registry: {expanded}"), null,
                                    FileUtil.IsUnderUserProfile(expanded) ? FixKind.DeleteFile : FixKind.None, expanded, browser: "chrome");
                        }
                        else if (expanded.IndexOf(Iocs.DllName, StringComparison.OrdinalIgnoreCase) >= 0)
                            Add(CheckId.Clsid, Severity.Info, L($"확인 필요 (자동 삭제 안 함): HKCU\\{key}", $"Check manually (not deleted automatically): HKCU\\{key}"), new[] { "InprocServer32 = " + val });
                    }
                }
            }
        }

        private static RegistryKey OpenHkcu(string sub)
        {
            try { return RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64).OpenSubKey(sub); }
            catch { return null; }
        }

        // ------------------------------------------------------------------
        // 2. 브라우저 PlatformExperienceHelper + 구버전 지속성 파일
        // ------------------------------------------------------------------
        private void CheckBrowserDll()
        {
            foreach (var b in Iocs.Browsers)
            {
                var peh = Path.Combine(b.Path, "PlatformExperienceHelper");
                if (!Directory.Exists(peh)) continue;
                bool any = false;
                var hexDirs = FileUtil.Dirs(peh).Where(d => Iocs.Hex64.IsMatch(Path.GetFileName(d))).ToList();
                foreach (var d in hexDirs)
                {
                    any = true;
                    var dlls = FileUtil.Files(d, 8).Where(f => Path.GetFileName(f).Equals(Iocs.DllName, StringComparison.OrdinalIgnoreCase)).ToList();
                    var ev = new List<string>();
                    if (dlls.Count > 0) ev.AddRange(dlls.Select(f => $"{f} ({FileUtil.Size(f):N0} bytes, {L("생성", "created")} {FileUtil.Created(f):yyyy-MM-dd HH:mm:ss})"));
                    else ev.Add(L("DLL 은 없지만 64자리 폴더가 남아 있습니다 (DLL 이 이미 지워졌을 수 있음)", "No DLL, but the 64-character folder remains (the DLL may already have been removed)"));
                    Add(CheckId.BrowserDll, Severity.Critical, L($"{b.Name} 지속성 설치됨: {d}", $"{b.Name} persistence installed: {d}"), ev, FixKind.DeleteDirectory, d, browser: b.Process, hint: b.Hint);
                }
                // 64자리 폴더 밖에 있는 DLL
                foreach (var f in FileUtil.Files(peh, 8).Where(f => Path.GetFileName(f).Equals(Iocs.DllName, StringComparison.OrdinalIgnoreCase)))
                {
                    if (hexDirs.Any(d => f.StartsWith(d + "\\", StringComparison.OrdinalIgnoreCase))) continue;
                    any = true;
                    Add(CheckId.BrowserDll, Severity.Critical, L($"{b.Name} 지속성 DLL: {f}", $"{b.Name} persistence DLL: {f}"), null, FixKind.DeleteFile, f, browser: b.Process, hint: b.Hint);
                }
                if (!any) _log(L($"  [-] {b.Name}: PlatformExperienceHelper 정상 (브라우저 자체 파일만 있음)", $"  [-] {b.Name}: PlatformExperienceHelper OK (only the browser's own files)"), LogLevel.Detail);
            }

            // 구버전 지속성: Chrome Application\PlatformExperienceHelper 의 DLL / .dll.old / old-clsid.txt
            var bases = Paths.ProgramFilesDirs.Select(p => (Path.Combine(p, Iocs.OldPersistenceDir), true))
             .Concat(new[] { (Path.Combine(Iocs.LocalAppData, Iocs.OldPersistenceDir), false) })
             .GroupBy(x => x.Item1, StringComparer.OrdinalIgnoreCase).Select(g => g.First());

            foreach (var (dir, elevated) in bases)
            {
                foreach (var name in Iocs.OldPersistenceFiles)
                {
                    var f = Path.Combine(dir, name);
                    if (!File.Exists(f)) continue;
                    Add(CheckId.BrowserDll, Severity.Critical, L($"구버전 Chrome 지속성 파일: {f}", $"Older Chrome persistence file: {f}"), null,
                        elevated ? FixKind.DeleteFileElevated : FixKind.DeleteFile, f, browser: "chrome");
                }
            }
        }

        // ------------------------------------------------------------------
        // 3. 실행 중 프로세스: 런처, 악성 DLL 로드
        // ------------------------------------------------------------------
        private void CheckProcesses()
        {
            foreach (var p in Process.GetProcesses().Where(x => x.ProcessName.StartsWith("nikke_launcher", StringComparison.OrdinalIgnoreCase)))
            {
                {
                    using (p)
                        Add(CheckId.Processes, Severity.Critical, L($"런처가 실행 중: {p.ProcessName}.exe (PID {p.Id}) — 즉시 종료해야 합니다", $"The launcher is running: {p.ProcessName}.exe (PID {p.Id}) - close it now"),
                            null, FixKind.KillProcess, p.ProcessName, p.Id).LauncherRunning = true;
                }
            }

            int denied = 0;
            foreach (var p in Process.GetProcesses())
            {
                _ct.ThrowIfCancellationRequested();
                using (p)
                {
                    if (p.Id <= 4) continue;
                    var mods = Native.GetModulePaths(p.Id);
                    if (mods == null) { denied++; continue; }
                    foreach (var m in mods)
                    {
                        bool hit = Iocs.LoadedDllPath.IsMatch(m) ||
                                   Path.GetFileName(m).StartsWith("platform_experience_helper", StringComparison.OrdinalIgnoreCase) ||
                                   (_r.HkcuDllPath != null && string.Equals(m, _r.HkcuDllPath, StringComparison.OrdinalIgnoreCase));
                        if (!hit) continue;
                        bool isExplorer = p.ProcessName.Equals("explorer", StringComparison.OrdinalIgnoreCase);
                        Add(CheckId.Processes, Severity.Critical, L($"악성 DLL 이 현재 로드됨: {p.ProcessName}.exe (PID {p.Id})", $"The malicious DLL is loaded now: {p.ProcessName}.exe (PID {p.Id})"),
                            new[] { m, isExplorer ? L("explorer.exe 는 종료하지 않습니다. 레지스트리 키 삭제 후 재부팅하면 풀립니다.", "explorer.exe is not ended. Restart Windows after the registry key is removed.")
                                                  : L("프로세스를 종료하거나 재부팅해야 DLL 을 지울 수 있습니다.", "The DLL can be deleted only after the process ends or Windows restarts.") },
                            isExplorer ? FixKind.None : FixKind.KillProcess, p.ProcessName, p.Id);
                        break;
                    }
                }
            }
            if (denied > 0) _log(L($"  (권한이 없어 확인하지 못한 프로세스 {denied}개 — 대부분 시스템 프로세스)", $"  ({denied} processes could not be checked for lack of permission - mostly system processes)"), LogLevel.Detail);
        }

        // ------------------------------------------------------------------
        // 4. 런처 데이터 (%APPDATA%\nikke_launcher, nikke_launcher_hmt)
        // ------------------------------------------------------------------
        private void CheckLauncherData()
        {
            foreach (var dir in Iocs.LauncherDataDirs)
            {
                if (!Directory.Exists(dir)) continue;
                _r.LauncherDataDirs.Add(dir);
                ScanDataDir(dir, Path.Combine(dir, "tbs_cache"), false);
            }
            if (_r.LauncherDataDirs.Count == 0) _log(L("  [-] 런처 데이터 폴더 없음", "  [-] No launcher data folder"), LogLevel.Detail);

            // 런처 로그인 화면의 브라우저 프로필 (MotherSphere 0.5.0). 다른 CEF 프로그램도 쓰는 폴더라 흔적이 있을 때만 보고하고,
            // 런처 데이터로 세지 않는다. 지우면 런처가 새로 만들고 런처 로그인만 다시 하면 된다.
            var cef = Iocs.CefUserData;
            if (Directory.Exists(cef) && ScanDataDir(cef, cef, true)) _r.CefDirs.Add(cef);
        }

        /// <summary>런처 데이터(또는 CEF 프로필) 폴더 하나 검사. 흔적이 있으면 true.</summary>
        private bool ScanDataDir(string dir, string target, bool cef)
        {
            _log(L($"  {dir} 확인 중", $"  Checking {dir}"), LogLevel.Detail);
            int count = 0, before = _r.Findings.Count;
            var agent = new List<string>();
            var cacheHits = new List<string>();
            var otherHits = new List<string>();
            string where = cef ? L(" — 런처 로그인 브라우저 프로필(CEF)", " - launcher login browser profile (CEF)") : "";

            foreach (var f in FileUtil.Files(dir, 12))
            {
                _ct.ThrowIfCancellationRequested();
                var data = FileUtil.Read(f, MaxFileBytes);
                if (data == null) { _r.Unreadable.Add(f); continue; }
                count++;
                var name = Path.GetFileName(f);
                var rel = f.Substring(dir.Length).TrimStart('\\');

                // .ldb 테이블은 Snappy 압축·키 앞부분 공유 때문에 그냥 검색하면 놓칠 수 있어 풀어서도 본다 (MotherSphere 0.4.1)
                var expanded = name.EndsWith(".ldb", StringComparison.OrdinalIgnoreCase) ? LevelDb.ExpandTable(data) : null;
                if (FileUtil.Contains(data, "k2f_chan") || FileUtil.Contains(data, "k2f.agent") ||
                    (expanded != null && (FileUtil.Contains(expanded, "k2f_chan") || FileUtil.Contains(expanded, "k2f.agent"))))
                    agent.Add(rel);

                if (name == "TransportSecurity") { CheckHsts(dir, f, data, target, where); continue; }
                if (name == "Network Persistent State")
                {
                    if (FileUtil.Contains(data, "analytics.insightjs.com"))
                        Add(CheckId.LauncherData, Severity.Critical, L("런처가 에이전트 배포 서버(analytics.insightjs.com)에 접속한 기록", "The launcher contacted the agent server (analytics.insightjs.com)") + where,
                            new[] { rel }, FixKind.DeleteTbsCache, target);
                    else if (FileUtil.Contains(data, "insightjs"))
                        Add(CheckId.LauncherData, Severity.Warning, L("런처가 insightjs.com 에 접속한 기록", "The launcher connected to insightjs.com") + where, new[] { rel },
                            FixKind.DeleteTbsCache, target);
                    continue;
                }
                if (name == "Reporting and NEL")
                {
                    if (FileUtil.Contains(data, "insightjs"))
                        Add(CheckId.LauncherData, Severity.Warning, L("런처가 insightjs.com 에 접속한 기록", "The launcher connected to insightjs.com") + where, new[] { rel },
                            FixKind.DeleteTbsCache, target);
                    continue;
                }
                if (!FileUtil.Contains(data, "insightjs") && !(expanded != null && FileUtil.Contains(expanded, "insightjs"))) continue;
                var parts = rel.Split('\\');
                if (parts.Any(p => p.Equals("Cache", StringComparison.OrdinalIgnoreCase) || p.Equals("Code Cache", StringComparison.OrdinalIgnoreCase)))
                    cacheHits.Add($"{rel} ({L("생성", "created")} {FileUtil.Created(f):yyyy-MM-dd HH:mm:ss})");
                else otherHits.Add(rel);
            }

            if (agent.Count > 0)
                Add(CheckId.LauncherData, Severity.Critical, L("에이전트 실행 흔적 (k2f.agent.state / k2f_chan) — Local Storage", "Agent traces (k2f.agent.state / k2f_chan) in Local Storage") + where,
                    agent.Take(MaxEvidence), FixKind.DeleteTbsCache, target);
            if (cacheHits.Count > 0)
                Add(CheckId.LauncherData, Severity.Warning, L($"런처가 악성 스크립트(insightjs)를 불러온 캐시 {cacheHits.Count}개", $"The launcher loaded the malicious script (insightjs): {cacheHits.Count} cache files") + where,
                    cacheHits.Take(MaxEvidence), FixKind.DeleteTbsCache, target);
            if (otherHits.Count > 0)
                Add(CheckId.LauncherData, Severity.Warning, L($"insightjs 를 언급하는 파일 {otherHits.Count}개", $"Files that mention insightjs: {otherHits.Count}") + where,
                    otherHits.Take(MaxEvidence), FixKind.DeleteTbsCache, target);
            bool found = _r.Findings.Count > before;
            if (found && cef)
                _log(L("        이 폴더를 지우면 런처가 새로 만들고, 런처 로그인만 다시 하면 됩니다.", "        If deleted, the launcher creates a new one; you only sign in to the launcher again."), LogLevel.Detail);
            if (!found && !cef)
                _log(L($"  [-] {Path.GetFileName(dir)}: 파일 {count}개 확인, 흔적 없음", $"  [-] {Path.GetFileName(dir)}: {count} files checked, no traces"), LogLevel.Detail);
            return found;
        }

        private void CheckHsts(string dir, string file, byte[] data, string target, string where)
        {
            var text = Encoding.UTF8.GetString(data);
            var rel = file.Substring(dir.Length).TrimStart('\\');
            var seen = new List<(string Domain, DateTime? Observed)>();
            foreach (Match m in Regex.Matches(text, @"\{[^{}]*\}"))
            {
                foreach (var (domain, key) in Iocs.HstsKeys)
                {
                    if (m.Value.IndexOf("\"" + key + "\"", StringComparison.Ordinal) < 0) continue;
                    DateTime? t = null;
                    var o = Regex.Match(m.Value, "\"sts_observed\"\\s*:\\s*([0-9.]+)");
                    if (o.Success && double.TryParse(o.Groups[1].Value, System.Globalization.NumberStyles.Float,
                            System.Globalization.CultureInfo.InvariantCulture, out var sec))
                        t = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(sec).ToLocalTime();
                    seen.Add((domain, t));
                }
            }
            if (seen.Count == 0) return;
            var ev = seen.Select(s => L($"{s.Domain} HSTS 기록 (마지막 수신 {(s.Observed.HasValue ? s.Observed.Value.ToString("yyyy-MM-dd HH:mm:ss") : "알 수 없음")})", $"{s.Domain} HSTS entry (last received {(s.Observed.HasValue ? s.Observed.Value.ToString("yyyy-MM-dd HH:mm:ss") : "unknown")})")).ToList();
            ev.Insert(0, rel);
            if (seen.Any(s => s.Domain == "analytics.insightjs.com"))
                Add(CheckId.LauncherData, Severity.Critical, L("런처가 에이전트 배포 서버(analytics.insightjs.com)에 접속한 기록 (HSTS)", "The launcher contacted the agent server (analytics.insightjs.com) (HSTS)") + where, ev, FixKind.DeleteTbsCache, target);
            else
                Add(CheckId.LauncherData, Severity.Warning, L("런처가 insightjs 도메인에 접속한 기록 (HSTS)", "The launcher connected to an insightjs domain (HSTS)") + where, ev, FixKind.DeleteTbsCache, target);
        }

        // ------------------------------------------------------------------
        // 5. 임시 폴더: k2f-bcreds-*, k2f_screen_*.jpg
        // ------------------------------------------------------------------
        private void CheckTemp()
        {
            var dirs = new[] { Path.GetTempPath(), Path.Combine(Iocs.LocalAppData, "Temp") }
                .Select(d => d.TrimEnd('\\')).Distinct(StringComparer.OrdinalIgnoreCase).Where(Directory.Exists);
            var hexTmp = new List<string>();
            foreach (var dir in dirs)
            {
                foreach (var f in FileUtil.Files(dir, 0))
                {
                    var name = Path.GetFileName(f);
                    if (Iocs.IsK2fName(name))
                    {
                        string kind = name.StartsWith("k2f-bcreds", StringComparison.OrdinalIgnoreCase) ? L("수집된 브라우저 자격 증명", "collected browser credentials")
                                    : name.StartsWith("k2f-keyscan", StringComparison.OrdinalIgnoreCase) ? L("수집한 키·인증 파일", "collected keys and credential files")
                                    : name.StartsWith("k2f_screen", StringComparison.OrdinalIgnoreCase) ? L("화면 캡처", "screenshot") : L("에이전트 임시 파일", "agent temp file");
                        Add(CheckId.Temp, Severity.Critical, L($"에이전트 임시 파일 ({kind}): {f}", $"Agent temp file ({kind}): {f}"),
                            new[] { $"{FileUtil.Size(f):N0} bytes, {L("생성", "created")} {FileUtil.Created(f):yyyy-MM-dd HH:mm:ss}" }, FixKind.DeleteFile, f);
                    }
                    else if (name.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase) && FileUtil.Size(f) == 22)
                    {
                        var d = FileUtil.Read(f, 22);
                        if (d != null && Iocs.Hex22Tmp.IsMatch(Encoding.ASCII.GetString(d)))
                            hexTmp.Add($"{name} ({L("생성", "created")} {FileUtil.Created(f):yyyy-MM-dd HH:mm:ss})");
                    }
                }
            }
            if (hexTmp.Count > 0)
                Add(CheckId.Temp, Severity.Info, L($"22바이트 hex .tmp 파일 {hexTmp.Count}개 (다른 Tencent 소프트웨어도 만드는 파일, 판정에 영향 없음)", $"22-byte hex .tmp files: {hexTmp.Count} (other Tencent software writes them too; no effect on the verdict)"), hexTmp.Take(MaxEvidence));
        }

        // ------------------------------------------------------------------
        // 6. 니케 설치 폴더: debug.log, Launcher\log\** (tinyget, LuaJIT 에이전트)
        // ------------------------------------------------------------------
        private void CheckInstalls(string userPath)
        {
            var installs = InstallLocator.Find(userPath, _r.DiskLaunchers, _ct, m => _log("  " + m, LogLevel.Detail));
            if (installs.Count == 0)
            {
                _log(L("  [?] 니케 설치 폴더를 찾지 못했습니다. 경로를 직접 지정해 주세요.", "  [?] The NIKKE install folder was not found. Please enter its path."), LogLevel.Warn);
                _log(L("      (런처를 이미 지웠다면 지난 실행 기록도 함께 지워져, 그동안 감염됐었는지는 이 항목으로 알 수 없습니다)", "      (If you already deleted the launcher, its logs are gone too, so this item cannot show a past infection)"), LogLevel.Detail);
                _r.Unknown[CheckId.InstallLogs] = true;
                return;
            }
            foreach (var root in installs)
            {
                _r.Installs.Add(root);
                var debugLog = Path.Combine(root, @"Launcher\intl_service\debug.log");
                Add(CheckId.InstallLogs, Severity.Info, L($"니케 설치 폴더: {root}", $"NIKKE install folder: {root}"),
                    new[] { File.Exists(debugLog) ? L($"debug.log 마지막 기록 {FileUtil.Modified(debugLog):yyyy-MM-dd HH:mm:ss}", $"debug.log last written {FileUtil.Modified(debugLog):yyyy-MM-dd HH:mm:ss}") : L("debug.log 없음", "no debug.log") });
                if (File.Exists(debugLog)) CheckDebugLog(debugLog);
                var logDir = Path.Combine(root, @"Launcher\log");
                if (Directory.Exists(logDir)) CheckLauncherLogs(logDir);
            }
        }

        // 에이전트 등록 기록: "adopted <uuid>" / "resuming <uuid>"
        private static readonly Regex AgentIdLine = new Regex(@"(adopted|resuming) [0-9a-f]{8}-[0-9a-f]{4}-", RegexOptions.IgnoreCase);
        private static readonly Regex RunLine = new Regex(@"k2f_chan registered|adopted \S+|resuming \S+|agent started as|lua downloaded to", RegexOptions.IgnoreCase);

        private void CheckDebugLog(string path)
        {
            bool k2f = false, server = false, loader = false;
            var runs = new List<string>();
            var lines = FileUtil.ReadLines(path);
            if (lines == null)
            {
                Add(CheckId.InstallLogs, Severity.Info, L("debug.log 를 읽을 수 없습니다 (에이전트 실행 여부 확인 불가)", "Could not read debug.log (cannot tell whether the agent ran)"), new[] { path });
                _r.Unknown[CheckId.InstallLogs] = true;
                return;
            }
            int no = 0;
            foreach (var raw in lines)
            {
                no++;
                var line = raw.Length > 65536 ? raw.Substring(0, 65536) : raw;
                if (line.IndexOf("k2f_chan", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    line.IndexOf("agent started as", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    line.IndexOf("lua downloaded to", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    AgentIdLine.IsMatch(line)) k2f = true;
                if (line.IndexOf("analytics.insightjs.com", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    line.IndexOf("insight.bundle", StringComparison.OrdinalIgnoreCase) >= 0) server = true;
                else if (line.IndexOf("insightjs", StringComparison.OrdinalIgnoreCase) >= 0) loader = true;
                if (RunLine.IsMatch(line)) runs.Add($"[{L("행", "line")} {no}] {FileUtil.Trunc(line)}");
            }
            // debug.log 는 런처가 실행할 때마다 덧붙이는 기록이라, 지금 남은 해킹 파일이 아니라 「과거 기록」이다 (햄찌 v4.2)
            if (k2f) Add(CheckId.InstallLogs, Severity.Critical, L($"debug.log: 에이전트가 실행됨 (k2f_chan / adopted / agent started as) — 실행 기록 {runs.Count}줄", $"debug.log: the agent ran (k2f_chan / adopted / agent started as) - {runs.Count} run lines") + PastTag, runs.Take(50)).Past = true;
            if (server) Add(CheckId.InstallLogs, Severity.Critical, L("debug.log: 런처가 에이전트 배포 서버에 요청함 (analytics.insightjs.com / insight.bundle)", "debug.log: the launcher requested the agent server (analytics.insightjs.com / insight.bundle)") + PastTag).Past = true;
            if (loader && !server && !k2f) Add(CheckId.InstallLogs, Severity.Warning, L("debug.log: 악성 로더(insightjs)만 실행됨", "debug.log: only the malicious loader (insightjs) ran") + PastTag).Past = true;
            if (runs.Count > 50) _log(L($"        … 외 {runs.Count - 50}줄", $"        … {runs.Count - 50} more lines"), LogLevel.Detail);
        }

        private static string PastTag => L(" (과거 기록)", " (past record)");

        /// <summary>
        /// insight.bundle 다운로드가 실제로 끝났는지 (MotherSphere 0.4.1): OnDownloadResult 의 result=0 이고 total 이 0 보다 크거나,
        /// curl perform success 줄. 서버가 응답하지 않은 요청(curl_error=7, result=2, total=0)은 시도일 뿐이다.
        /// </summary>
        public static bool BundleDownloaded(string text)
        {
            foreach (var l in text.Split('\n'))
            {
                if (l.IndexOf("insight.bundle", StringComparison.Ordinal) < 0) continue;
                if (l.Contains("curl perform success")) return true;
                if (!l.Contains("OnDownloadResult")) continue;
                var r = Regex.Match(l, @"result=([^,\s;\t]+)"); var t = Regex.Match(l, @"total=([^,\s;\t]+)");
                if (r.Success && r.Groups[1].Value == "0" && t.Success && t.Groups[1].Value != "0") return true;
            }
            return false;
        }

        private static readonly Regex Etag = new Regex("ETag:\\s*\"([0-9a-fA-F]+)-([0-9a-fA-F]+)\"", RegexOptions.IgnoreCase);

        private void CheckLauncherLogs(string logDir)
        {
            var downloads = new List<string>();
            var attempts = new List<string>();
            var builds = new List<string>();
            foreach (var f in FileUtil.Files(logDir, 8))
            {
                _ct.ThrowIfCancellationRequested();
                var data = FileUtil.Read(f, MaxFileBytes);
                if (data == null) { _r.Unreadable.Add(f); continue; }
                var rel = f.Substring(logDir.Length).TrimStart('\\');

                if (FileUtil.IsLuaJit(data) || Iocs.IsK2fName(Path.GetFileName(f)))
                {
                    Add(CheckId.InstallLogs, Severity.Critical, L($"내려받은 에이전트 파일 ({(FileUtil.IsLuaJit(data) ? "LuaJIT 바이트코드" : "k2f 파일")}): {f}", $"Downloaded agent file ({(FileUtil.IsLuaJit(data) ? "LuaJIT bytecode" : "k2f file")}): {f}"),
                        new[] { $"{data.Length:N0} bytes" + (Iocs.KnownAgentSizes.Contains(data.Length) ? L(" (알려진 에이전트와 같은 크기)", " (same size as a known agent build)") : "") + $", {L("생성", "created")} {FileUtil.Created(f):yyyy-MM-dd HH:mm:ss}" },
                        FixKind.DeleteFile, f);
                    continue;
                }
                if (FileUtil.Contains(data, "insight.bundle"))
                {
                    var line = FileUtil.LinesWith(data, "insight.bundle").FirstOrDefault();
                    if (BundleDownloaded(Encoding.UTF8.GetString(data))) downloads.Add($"{rel}: {FileUtil.Trunc(line ?? "")}");
                    else attempts.Add($"{rel}: {FileUtil.Trunc(line ?? "")}");
                    if (Path.GetFileName(f).Equals("tinyget.mem.log", StringComparison.OrdinalIgnoreCase))
                    {
                        foreach (Match m in Etag.Matches(Encoding.UTF8.GetString(data)))
                        {
                            var mtime = Convert.ToInt64(m.Groups[1].Value, 16);
                            var size = Convert.ToInt64(m.Groups[2].Value, 16);
                            var when = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(mtime);
                            var known = Iocs.KnownBuildEtags.Contains(m.Groups[1].Value.ToLowerInvariant());
                            var s = $"ETag {m.Value.Substring(m.Value.IndexOf('"'))} → {L("업로드", "uploaded")} {when:yyyy-MM-dd HH:mm:ss} UTC, {size:N0} bytes{(known ? L(" (알려진 빌드)", " (known build)") : L(" (알려지지 않은 빌드)", " (unknown build)"))}";
                            if (!builds.Contains(s)) builds.Add(s);
                        }
                    }
                }
                else if (FileUtil.Contains(data, "analytics.insightjs.com"))
                    Add(CheckId.InstallLogs, Severity.Critical, L($"런처 로그: 에이전트 배포 서버 접속 기록 ({rel})", $"Launcher log: contact with the agent server ({rel})") + PastTag).Past = true;
                else if (FileUtil.Contains(data, "insightjs"))
                    Add(CheckId.InstallLogs, Severity.Warning, L($"런처 로그: insightjs 기록 ({rel})", $"Launcher log: insightjs record ({rel})") + PastTag).Past = true;
            }
            if (downloads.Count > 0)
                Add(CheckId.InstallLogs, Severity.Critical, L($"에이전트(insight.bundle) 다운로드 기록 {downloads.Count}건", $"Agent (insight.bundle) download records: {downloads.Count}") + PastTag, downloads.Take(20)).Past = true;
            if (attempts.Count > 0)
                Add(CheckId.InstallLogs, Severity.Warning, L($"에이전트(insight.bundle)를 요청했지만 받지 못한 기록 {attempts.Count}건 (서버 무응답 등)", $"Agent (insight.bundle) requested but not received: {attempts.Count} (e.g. the server did not answer)") + PastTag, attempts.Take(20)).Past = true;
            if (builds.Count > 0)
                Add(CheckId.InstallLogs, Severity.Info, L("내려받은 에이전트 빌드 (tinyget.mem.log)", "Downloaded agent build (tinyget.mem.log)"), builds);
        }

        // ------------------------------------------------------------------
        // 전체 드라이브 파일 이름 검사 (정해진 위치 밖에 남은 에이전트·지속성 파일)
        // ------------------------------------------------------------------
        private static readonly Regex CloudLabel = new Regex(@"Google Drive|OneDrive|Dropbox|pCloud|iCloud|MEGA|MYBOX|\bBox\b", RegexOptions.IgnoreCase);

        private void CheckFullScan()
        {
            var hits = new List<string>();
            foreach (var drive in DriveInfo.GetDrives())
            {
                _ct.ThrowIfCancellationRequested();
                string label = "";
                try
                {
                    if (!drive.IsReady || (drive.DriveType != DriveType.Fixed && drive.DriveType != DriveType.Removable)) continue;
                    label = drive.VolumeLabel ?? "";
                }
                catch { continue; }
                if (CloudLabel.IsMatch(label)) { _log(L($"  {drive.Name} 는 클라우드 드라이브({label})라 건너뜁니다", $"  Skipping {drive.Name}: cloud drive ({label})"), LogLevel.Detail); continue; }
                var sw = Stopwatch.StartNew();
                long last = 0;
                var root = drive.RootDirectory.FullName.TrimEnd('\\');
                long files = Native.WalkFileNames(root, new[] { root + "\\Windows" }, (dir, name) =>
                {
                    if (Iocs.IsDiskScanName(name)) lock (hits) hits.Add(dir + "\\" + name);
                }, _ct, n =>
                {
                    if (sw.ElapsedMilliseconds - last >= 5000) { last = sw.ElapsedMilliseconds; _log(L($"  {root}\\ 검사 중… 파일 {n:N0}개", $"  Scanning {root}\\ … {n:N0} files"), LogLevel.Detail); }
                });
                _log(L($"  {root}\\ 완료: 파일 {files:N0}개, {sw.Elapsed.TotalSeconds:N0}초", $"  {root}\\ done: {files:N0} files, {sw.Elapsed.TotalSeconds:N0} s"), LogLevel.Detail);
            }

            foreach (var h in hits.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                var leaf = Path.GetFileName(h);
                var lower = leaf.ToLowerInvariant();
                if (lower == "nikke_launcher.exe")
                {
                    var launcherDir = Path.GetDirectoryName(h);
                    if (launcherDir != null) _r.DiskLaunchers.Add(Path.GetDirectoryName(launcherDir) ?? launcherDir);
                    continue;
                }
                if (lower.StartsWith(Iocs.DllName) || (lower == "old-clsid.txt" && h.IndexOf("\\PlatformExperienceHelper\\", StringComparison.OrdinalIgnoreCase) >= 0))
                    Add(CheckId.FullScan, Severity.Critical, L($"지속성 DLL 파일 (다른 위치): {h}", $"Persistence DLL file (other location): {h}"), null, FileUtil.IsUnderUserProfile(h) ? FixKind.DeleteFile : FixKind.None, h);
                else if (lower == "insight.bundle" || leaf == "k2f.lua")
                {
                    // 이름만으로 지우지 않는다: 내용이 LuaJIT 바이트코드일 때만 에이전트로 보고 삭제 대상
                    var head = FileUtil.Read(h, 3);
                    if (head == null) { _r.Unreadable.Add(h); continue; }
                    if (FileUtil.IsLuaJit(head))
                        Add(CheckId.FullScan, Severity.Critical, L($"내려받은 에이전트 파일 ({leaf}, LuaJIT 바이트코드): {h}", $"Downloaded agent file ({leaf}, LuaJIT bytecode): {h}"), null, FixKind.DeleteFile, h);
                    else
                        Add(CheckId.FullScan, Severity.Info, L($"이름만 일치하는 파일 (내용은 에이전트가 아님, 직접 확인): {h}", $"Name-only match (content is not the agent; check it yourself): {h}"));
                }
                else if (lower.StartsWith("tinyget"))
                {
                    var head = FileUtil.Read(h, 3);
                    if (head == null) { _r.Unreadable.Add(h); continue; }
                    if (FileUtil.IsLuaJit(head))
                        Add(CheckId.FullScan, Severity.Critical, L($"에이전트 파일 (LuaJIT 바이트코드, 다른 위치): {h}", $"Agent file (LuaJIT bytecode, other location): {h}"), null, FixKind.DeleteFile, h);
                }
                else if (Regex.IsMatch(leaf, @"^k2f(-bcreds|-keyscan|_screen|\.agent)"))
                    // 임시 폴더 안의 것은 5번 항목이 삭제한다. 그 밖(연구용 샘플 폴더 등)은 보고만 하고 지우지 않는다.
                    Add(CheckId.FullScan, Severity.Critical, L($"에이전트 관련 파일 (임시 폴더 밖, 자동 삭제 안 함 — 직접 확인): {h}", $"Agent-related file (outside the temp folder, not deleted automatically - check it yourself): {h}"), null, FixKind.None, h);
            }
        }

        /// <summary>다른 항목이 이미 잡은 경로(또는 그 아래)는 전체 드라이브 검사 결과에서 뺀다.</summary>
        private void DedupeFullScan()
        {
            var others = _r.Findings.Where(f => f.Check != CheckId.FullScan && !string.IsNullOrEmpty(f.Target) &&
                                                f.Fix != FixKind.DeleteRegistryKey && f.Fix != FixKind.KillProcess)
                                    .Select(f => f.Target.TrimEnd('\\')).ToList();
            _r.Findings.RemoveAll(f => f.Check == CheckId.FullScan && f.Target != null &&
                others.Any(o => f.Target.Equals(o, StringComparison.OrdinalIgnoreCase) ||
                                f.Target.StartsWith(o + "\\", StringComparison.OrdinalIgnoreCase)));
        }

        // ------------------------------------------------------------------
        // 자동 실행 프로그램 (해커가 따로 깔았을 수 있는 것). 판정에 영향 없음, 사용자가 고른 것만 삭제
        // ------------------------------------------------------------------
        private List<AutostartItem> _sysItems;
        private bool _sysTried;

        /// <summary>PC 전체 범위 「확인 필요」 항목 (자동 실행 + 추가 점검). 관리자 권한이 필요해 한 번만 읽어 둔다. 못 읽으면 null.</summary>
        private List<AutostartItem> SystemItems(Func<List<AutostartItem>> auditSystem)
        {
            if (_sysTried) return _sysItems;
            _sysTried = true;
            if (Remediator.IsAdmin())
            {
                _sysItems = Autostart.AuditSystem(_ct, n => _log("  " + n, LogLevel.Detail));
                _sysItems.AddRange(Extra.AuditSystem(_ct, n => _log("  " + n, LogLevel.Detail)));
                Autostart.ScanWithDefender(_sysItems, _ct);
            }
            else
            {
                _log(L("  PC 전체 범위(서비스·작업 스케줄러·HKLM·Defender 설정 등)를 읽으려면 관리자 권한이 필요합니다 (UAC 창, 읽기만 함)",
                       "  Reading PC-wide entries (services, scheduled tasks, HKLM, Defender settings, etc.) needs administrator rights (UAC prompt, read-only)"), LogLevel.Detail);
                _sysItems = auditSystem?.Invoke();
            }
            return _sysItems;
        }

        private void CheckAutostart(Func<List<AutostartItem>> auditSystem)
        {
            var items = Autostart.AuditUser(_ct);
            Autostart.ScanWithDefender(items, _ct);
            var sys = SystemItems(auditSystem);
            if (sys == null)
            {
                _log(L("  [?] 관리자 권한을 받지 못해 현재 사용자 범위만 확인했습니다.", "  [?] No administrator rights: only the current user's entries were checked."), LogLevel.Warn);
                _r.Unknown[CheckId.Autostart] = true;
            }
            else items.AddRange(sys.Where(a => a.Group == "autostart"));
            foreach (var it in items)
            {
                var ev = new List<string> { $"{it.Display}  ({L("생긴 날", "created")} {it.Date})" };
                if (it.Hidden) ev.Add(L("위험 높음: 파일 없이 명령을 숨겨 실행하는 방식이라 정상 프로그램은 거의 쓰지 않습니다", "HIGH RISK: runs a hidden command without a file - normal programs almost never do this"));
                else ev.Add(Defender.VerdictText(it.Defender));
                var f = Add(CheckId.Autostart, Severity.Review, $"[{it.Where}] {it.Name}", ev, FixKind.None, it.File ?? it.Display);
                f.Auto = it;
            }
            if (items.Count > 0)
                _log(L("  ※ 직접 설치한 프로그램이면 괜찮습니다. [조치 실행] 에서 하나씩 골라 지울 수 있습니다.", "  * Programs you installed yourself are fine. You can pick which ones to delete in [Clean up]."), LogLevel.Info);
        }

        // ------------------------------------------------------------------
        // 추가 보안 점검 (햄찌 v4.1). 확실한 흔적(해커 서버 연결·DNS 기록)은 바로 정리 대상, 나머지는 「확인 필요」
        // ------------------------------------------------------------------
        private void CheckExtra(Func<List<AutostartItem>> auditSystem)
        {
            foreach (var c in Extra.C2Connections())
            {
                bool windowsProgram = c.Path != null && Paths.IsInside(c.Path, Paths.Windows);
                Add(CheckId.Extra, Severity.Critical, L($"지금 해커 서버와 연결 중인 프로그램: {c.Name} (PID {c.Pid}) -> {c.Remote}", $"Program connected to the hacker server right now: {c.Name} (PID {c.Pid}) -> {c.Remote}"),
                    new[] { c.Path ?? "", windowsProgram ? L("Windows 기본 프로그램이라 끄지 않습니다 — 방화벽 차단과 PC 재시작으로 끊깁니다", "A Windows program, so it is not closed - the firewall block and a restart cut it off") : "" }.Where(x => x.Length > 0),
                    windowsProgram ? FixKind.None : FixKind.KillProcess, c.Name, c.Pid);
            }
            var dns = Extra.DnsHits();
            if (dns.Count > 0)
                Add(CheckId.Extra, Severity.Warning, L($"최근 해커 주소를 찾아본 기록 (DNS 캐시) {dns.Count}건", $"Recent lookups of hacker addresses (DNS cache): {dns.Count}"), dns, FixKind.FlushDns, "dns");

            var items = Extra.AuditUser(_ct);
            Autostart.ScanWithDefender(items, _ct);
            var sys = SystemItems(auditSystem);
            if (sys == null)
            {
                _log(L("  [?] 관리자 권한을 받지 못해 PC 전체 범위(HKLM·Defender 제외 목록 등)는 확인하지 못했습니다.", "  [?] No administrator rights: PC-wide entries (HKLM, Defender exclusions, etc.) were not checked."), LogLevel.Warn);
                _r.Unknown[CheckId.Extra] = true;
            }
            else items.AddRange(sys.Where(a => a.Group == "extra"));
            foreach (var it in items)
            {
                var ev = new List<string> { it.Display };
                if (it.File != null) ev.Add(Defender.VerdictText(it.Defender));
                var f = Add(CheckId.Extra, Severity.Review, $"[{it.Where}] {it.Name}", ev, FixKind.None, it.File ?? it.Display);
                f.Auto = it;
            }
        }

        // ------------------------------------------------------------------
        // 7. 차단 상태 (판정에 영향 없음)
        // ------------------------------------------------------------------
        private void CheckProtection()
        {
            var hosts = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
            string text = null;
            try { text = File.Exists(hosts) ? File.ReadAllText(hosts) : ""; } catch { }
            var ev = new List<string>();
            foreach (var d in Iocs.BlockDomains)
                ev.Add($"hosts {d}: " + (text == null ? L("확인 불가", "unknown") : HostsFile.IsBlocked(text, d) ? L("차단됨", "blocked") : L("차단 안 됨", "not blocked")));
            bool fw = Firewall.RuleIsValid();
            ev.Add($"{L("방화벽", "firewall")} {string.Join(", ", Iocs.C2Ips)}: " + (fw ? L("차단됨", "blocked") : L("차단 안 됨", "not blocked")));
            Add(CheckId.Protection, Severity.Info, L("차단 상태 (조치 옵션의 'hosts·방화벽 차단'으로 등록 가능)", "Block status (the 'hosts + firewall block' option can add them)"), ev);
        }
    }

    // ----------------------------------------------------------------------
    public static class InstallLocator
    {
        private static readonly string[] SkipRootDirs = { "Windows", "$Recycle.Bin", "System Volume Information", "$WinREAgent", "Recovery" };

        public static bool IsInstall(string root) =>
            !string.IsNullOrEmpty(root) && (
            File.Exists(Path.Combine(root, @"Launcher\nikke_launcher.exe")) ||
            File.Exists(Path.Combine(root, @"Launcher\intl_service\debug.log")) ||
            File.Exists(Path.Combine(root, @"launcher\nikke_launcher_google.exe")));

        /// <summary>런처 실행 파일 경로가 들어 있는 문자열에서 설치 루트를 뽑는다.</summary>
        public static string RootFromValue(string value)
        {
            if (string.IsNullOrEmpty(value)) return null;
            var m = Regex.Match(value.Replace("\\\\", "\\"), @"([A-Za-z]:\\[^""\r\n]*?)\\Launcher\\nikke_launcher(_google)?\.exe", RegexOptions.IgnoreCase);
            return m.Success ? m.Groups[1].Value : null;
        }

        public static List<string> Find(string userPath, IEnumerable<string> diskCandidates, CancellationToken ct, Action<string> log)
        {
            var found = new List<string>();
            void Try(string root, string source)
            {
                if (string.IsNullOrWhiteSpace(root)) return;
                root = root.Trim().Trim('"').TrimEnd('\\');
                // Launcher 폴더 자체가 기록된 경우 상위 폴더가 설치 루트
                if (!IsInstall(root) && Path.GetFileName(root).Equals("Launcher", StringComparison.OrdinalIgnoreCase))
                    root = Path.GetDirectoryName(root);
                if (!IsInstall(root) || found.Contains(root, StringComparer.OrdinalIgnoreCase)) return;
                found.Add(root);
                log(L($"설치 폴더 확인 ({source}): {root}", $"Install folder found ({source}): {root}"));
            }

            Try(userPath, L("직접 지정", "entered"));
            if (!string.IsNullOrWhiteSpace(userPath) && found.Count == 0)
                log(L("지정한 경로에서 Launcher\\nikke_launcher.exe 또는 debug.log 를 찾지 못했습니다. 자동 탐색합니다.", "Launcher\\nikke_launcher.exe or debug.log was not found in that path. Searching automatically."));

            // 런처가 기록한 설치 경로: Uninstall 아래 이름에 nikke 가 들어가거나 표시 이름이 NIKKE 인 모든 키
            const string uninstallRoot = @"Software\Microsoft\Windows\CurrentVersion\Uninstall";
            foreach (var (hive, view) in new[] { (RegistryHive.CurrentUser, RegistryView.Default), (RegistryHive.LocalMachine, RegistryView.Registry64), (RegistryHive.LocalMachine, RegistryView.Registry32) })
            {
                try
                {
                    using (var b = RegistryKey.OpenBaseKey(hive, view))
                    using (var root = b.OpenSubKey(uninstallRoot))
                    {
                        if (root == null) continue;
                        foreach (var name in root.GetSubKeyNames())
                        {
                            using (var k = root.OpenSubKey(name))
                            {
                                if (k == null) continue;
                                var display = k.GetValue("DisplayName") as string ?? "";
                                if (name.IndexOf("nikke", StringComparison.OrdinalIgnoreCase) < 0 &&
                                    display.IndexOf("NIKKE", StringComparison.OrdinalIgnoreCase) < 0) continue;
                                Try(k.GetValue("GameInstallPath") as string, L("레지스트리 GameInstallPath", "registry GameInstallPath"));
                                Try(k.GetValue("InstallLocation") as string, L("레지스트리 InstallLocation", "registry InstallLocation"));
                                Try(RootFromValue(k.GetValue("DisplayIcon") as string), L("레지스트리 DisplayIcon", "registry DisplayIcon"));
                                var u = k.GetValue("UninstallString") as string;
                                if (!string.IsNullOrWhiteSpace(u)) Try(Path.GetDirectoryName(u.Trim().Trim('"')), L("레지스트리 UninstallString", "registry UninstallString"));
                            }
                        }
                    }
                }
                catch { }
            }
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Classes\nikkelauncher\DefaultIcon"))
                    Try(RootFromValue(k?.GetValue("") as string), L("nikkelauncher 프로토콜", "nikkelauncher protocol"));
            }
            catch { }
            foreach (var dir in Iocs.LauncherDataDirs)
            {
                var reg = Path.Combine(dir, "url_protocol.reg");
                if (!File.Exists(reg)) continue;
                try
                {
                    var bytes = File.ReadAllBytes(reg);
                    var text = bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE ? Encoding.Unicode.GetString(bytes) : Encoding.UTF8.GetString(bytes);
                    foreach (Match m in Regex.Matches(text.Replace("\\\\", "\\"), @"[A-Za-z]:\\[^""\r\n]*?\\Launcher\\nikke_launcher\.exe", RegexOptions.IgnoreCase))
                        Try(RootFromValue(m.Value), "url_protocol.reg");
                }
                catch { }
            }
            foreach (var c in diskCandidates ?? Enumerable.Empty<string>()) Try(c, L("전체 드라이브 검사", "all-drive scan"));
            if (found.Count > 0) return found;

            // 드라이브 탐색 (고정/이동식, 7단계, \Windows 제외, 정션 미추적)
            log(L("기록된 설치 경로가 없어 드라이브를 탐색합니다 (수 분 걸릴 수 있음)", "No recorded install path, searching the drives (this can take a few minutes)"));
            foreach (var drive in DriveInfo.GetDrives())
            {
                ct.ThrowIfCancellationRequested();
                try { if (!drive.IsReady || (drive.DriveType != DriveType.Fixed && drive.DriveType != DriveType.Removable)) continue; }
                catch { continue; }
                log(L($"{drive.Name} 드라이브 탐색 중…", $"Searching drive {drive.Name}…"));
                Walk(drive.RootDirectory.FullName, 0, ct, r => Try(r, L("드라이브 탐색", "drive search")));
            }
            return found;
        }

        private static void Walk(string dir, int depth, CancellationToken ct, Action<string> onFound)
        {
            ct.ThrowIfCancellationRequested();
            if (depth > 0 && Path.GetFileName(dir).Equals("Launcher", StringComparison.OrdinalIgnoreCase))
            {
                var parent = Path.GetDirectoryName(dir);
                if (IsInstall(parent)) { onFound(parent); return; }
            }
            if (depth >= 7) return;
            foreach (var sub in FileUtil.Dirs(dir))
            {
                if (depth == 0 && SkipRootDirs.Contains(Path.GetFileName(sub), StringComparer.OrdinalIgnoreCase)) continue;
                Walk(sub, depth + 1, ct, onFound);
            }
        }
    }

    // ----------------------------------------------------------------------
    public static class HostsFile
    {
        private static readonly string[] BlockAddrs = { "0.0.0.0", "127.0.0.1", "::1", "::" };

        public static bool IsBlocked(string hosts, string domain)
        {
            foreach (var raw in hosts.Split('\n'))
            {
                var line = raw;
                int hash = line.IndexOf('#');
                if (hash >= 0) line = line.Substring(0, hash);
                var parts = line.Trim().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2 && BlockAddrs.Contains(parts[0]) &&
                    parts.Skip(1).Any(p => p.Equals(domain, StringComparison.OrdinalIgnoreCase))) return true;
            }
            return false;
        }
    }

    // ----------------------------------------------------------------------
    public static class FileUtil
    {
        public static IEnumerable<string> Dirs(string dir)
        {
            string[] ds;
            try { ds = Directory.GetDirectories(dir); } catch { yield break; }
            foreach (var d in ds)
            {
                bool reparse;
                try { reparse = (new DirectoryInfo(d).Attributes & FileAttributes.ReparsePoint) != 0; } catch { continue; }
                if (!reparse) yield return d;
            }
        }

        /// <summary>maxDepth: 0 = 해당 폴더의 파일만.</summary>
        public static IEnumerable<string> Files(string dir, int maxDepth)
        {
            if (!Directory.Exists(dir)) yield break;
            string[] fs;
            try { fs = Directory.GetFiles(dir); } catch { fs = Array.Empty<string>(); }
            foreach (var f in fs) yield return f;
            if (maxDepth <= 0) yield break;
            foreach (var d in Dirs(dir))
                foreach (var f in Files(d, maxDepth - 1)) yield return f;
        }

        public static byte[] Read(string path, long max)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    var len = (int)Math.Min(fs.Length, max);
                    var buf = new byte[len];
                    int off = 0, n;
                    while (off < len && (n = fs.Read(buf, off, len - off)) > 0) off += n;
                    if (off < len) Array.Resize(ref buf, off);
                    return buf;
                }
            }
            catch { return null; }
        }

        public static List<string> ReadLines(string path)
        {
            var data = Read(path, long.MaxValue / 2);
            if (data == null) return null;
            return Encoding.UTF8.GetString(data).Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        }

        public static IEnumerable<string> LinesWith(byte[] data, string needle) =>
            Encoding.UTF8.GetString(data).Split('\n')
                .Where(l => l.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0)
                .Select(l => l.Trim('\r', '\0'));

        /// <summary>대소문자 무시 검색 (ASCII 및 UTF-16LE).</summary>
        public static bool Contains(byte[] data, string ascii)
        {
            var a = Encoding.ASCII.GetBytes(ascii.ToLowerInvariant());
            var u = Encoding.Unicode.GetBytes(ascii.ToLowerInvariant());
            return IndexOf(data, a) >= 0 || IndexOf(data, u) >= 0;
        }

        private static int IndexOf(byte[] data, byte[] p)
        {
            byte first = p[0];
            for (int i = 0; i <= data.Length - p.Length; i++)
            {
                if (Lower(data[i]) != first) continue;
                int j = 1;
                while (j < p.Length && Lower(data[i + j]) == p[j]) j++;
                if (j == p.Length) return i;
            }
            return -1;
        }

        private static byte Lower(byte b) => b >= (byte)'A' && b <= (byte)'Z' ? (byte)(b | 0x20) : b;

        public static string Trunc(string s, int max = 240)
        {
            // 에이전트 상태에 저장된 비밀번호는 출력하지 않는다
            int ap = s.IndexOf("agent_pass", StringComparison.OrdinalIgnoreCase);
            if (ap >= 0) s = s.Substring(0, ap) + "…";
            return s.Length > max ? s.Substring(0, max) + "…" : s;
        }

        public static bool IsLuaJit(byte[] d) => d != null && d.Length >= 3 && d[0] == 0x1B && d[1] == 0x4C && d[2] == 0x4A;

        public static bool IsUnderUserProfile(string p) =>
            p.StartsWith(Iocs.UserProfile.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);

        public static long Size(string p) { try { return new FileInfo(p).Length; } catch { return -1; } }
        public static DateTime Created(string p) { try { return File.GetCreationTime(p); } catch { return DateTime.MinValue; } }
        public static DateTime Modified(string p) { try { return File.GetLastWriteTime(p); } catch { return DateTime.MinValue; } }
    }
}
