using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;

namespace NikkeChecker
{
    public enum CheckId { LevelDb, TbsCache, Logs, BrowserDll, Clsid }

    public enum LogLevel { Info, Header, Ok, Warn, Bad, Action, Detail }

    public enum FixKind { None, DeleteTbsCache, DeleteDirectory, DeleteRegistryKey }

    public sealed class Finding
    {
        public CheckId Check;
        public FixKind Fix;
        public string Target;      // 삭제할 폴더 경로 / HKCU 기준 레지스트리 하위 키
        public string Browser;     // BrowserDll: 해당 브라우저 프로세스 이름
        public string Description;
    }

    public sealed class ScanOptions
    {
        public HashSet<CheckId> Checks = new HashSet<CheckId>();
        public string InstallPath;
    }

    public sealed class ScanResult
    {
        public List<Finding> Findings = new List<Finding>();
        public Dictionary<CheckId, bool?> Status = new Dictionary<CheckId, bool?>(); // true=감염, false=정상, null=확인 불가
        public string InstallPath;
        public bool Infected => Findings.Count > 0;
    }

    public delegate void Logger(string message, LogLevel level);

    public static class Iocs
    {
        public const string KnownBadClsid = "{E77CC89B-7401-4C04-8CED-149DB35ADD04}";
        public const string ClsidRoot = @"Software\Classes\CLSID";
        public const string DllName = "platform_experience_helper.dll";
        public static readonly string[] BlockDomains = { "insightjs.com", "analytics.insightjs.com", "insightjs.org" };
        public const string C2Ip = "89.127.233.127";
        public const string FirewallRuleName = "Block_Nikke_Malware_C2_89.127.233.127";
        public static readonly string[] LauncherProcesses = { "nikke_launcher", "intl_service", "tbs_browser" };

        public static readonly Regex Hex64 = new Regex("^[0-9a-fA-F]{64}$", RegexOptions.Compiled);
        public static readonly Regex DebugLogPattern = new Regex(
            @"k2f_chan|adopted|agent started|insight\.bundle|startup already in progress",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);
        public static readonly Regex TinygetPattern = new Regex(@"insight\.bundle|insightjs",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);
        public static readonly Regex HexDllPath = new Regex(
            @"\\PlatformExperienceHelper\\[0-9a-fA-F]{64}\\platform_experience_helper\.dll",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public static string AppData => Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        public static string LocalAppData => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        public static string[] TbsCacheDirs => new[]
        {
            Path.Combine(AppData, "nikke_launcher", "tbs_cache"),
            Path.Combine(AppData, "nikke_launcher_hmt", "tbs_cache"),
        };

        // (표시 이름, User Data 경로, 프로세스 이름)
        public static (string Name, string Path, string Process)[] Browsers => new[]
        {
            ("Google Chrome",  System.IO.Path.Combine(LocalAppData, @"Google\Chrome\User Data"), "chrome"),
            ("Microsoft Edge", System.IO.Path.Combine(LocalAppData, @"Microsoft\Edge\User Data"), "msedge"),
            ("Brave",          System.IO.Path.Combine(LocalAppData, @"BraveSoftware\Brave-Browser\User Data"), "brave"),
            ("Vivaldi",        System.IO.Path.Combine(LocalAppData, @"Vivaldi\User Data"), "vivaldi"),
            ("Opera",          System.IO.Path.Combine(AppData, @"Opera Software\Opera Stable"), "opera"),
            ("Opera GX",       System.IO.Path.Combine(AppData, @"Opera Software\Opera GX Stable"), "opera"),
        };
    }

    public sealed class Scanner
    {
        private readonly Logger _log;
        private readonly CancellationToken _ct;

        public Scanner(Logger log, CancellationToken ct) { _log = log; _ct = ct; }

        public ScanResult Run(ScanOptions opt)
        {
            var r = new ScanResult();
            int total = opt.Checks.Count, n = 0;

            if (opt.Checks.Contains(CheckId.BrowserDll)) { _ct.ThrowIfCancellationRequested(); CheckBrowserDll(r, ++n, total); }
            if (opt.Checks.Contains(CheckId.Clsid))      { _ct.ThrowIfCancellationRequested(); CheckClsid(r, ++n, total); }
            if (opt.Checks.Contains(CheckId.LevelDb))    { _ct.ThrowIfCancellationRequested(); CheckLevelDb(r, ++n, total); }
            if (opt.Checks.Contains(CheckId.TbsCache))   { _ct.ThrowIfCancellationRequested(); CheckTbsCache(r, ++n, total); }
            if (opt.Checks.Contains(CheckId.Logs))       { _ct.ThrowIfCancellationRequested(); CheckLogs(r, opt.InstallPath, ++n, total); }

            return r;
        }

        // ------------------------------------------------------------------
        // 브라우저 User Data\PlatformExperienceHelper\<64자리>\platform_experience_helper.dll
        // ------------------------------------------------------------------
        private void CheckBrowserDll(ScanResult r, int n, int total)
        {
            _log($"[{n}/{total}] 브라우저 User Data 내 악성 DLL(64자리 폴더) 검사", LogLevel.Header);
            bool found = false;
            foreach (var b in Iocs.Browsers)
            {
                var peh = Path.Combine(b.Path, "PlatformExperienceHelper");
                if (!Directory.Exists(peh)) continue;
                _log($"  [{b.Name}] {peh} 확인 중", LogLevel.Detail);
                foreach (var dir in SafeDirs(peh))
                {
                    if (!Iocs.Hex64.IsMatch(Path.GetFileName(dir))) continue;
                    var dll = Path.Combine(dir, Iocs.DllName);
                    if (!File.Exists(dll)) continue;
                    found = true;
                    var created = SafeCreationTime(dll);
                    _log($"  [!] [{b.Name}] 악성 DLL 발견: {dll} (생성: {created})", LogLevel.Bad);
                    r.Findings.Add(new Finding
                    {
                        Check = CheckId.BrowserDll, Fix = FixKind.DeleteDirectory, Target = dir, Browser = b.Process,
                        Description = $"[{b.Name}] 64자리 폴더 삭제: {dir}",
                    });
                }
            }
            if (!found) _log("  [-] 악성 DLL 없음", LogLevel.Ok);
            r.Status[CheckId.BrowserDll] = found;
        }

        // ------------------------------------------------------------------
        // HKCU\Software\Classes\CLSID 하이재킹
        // ------------------------------------------------------------------
        private void CheckClsid(ScanResult r, int n, int total)
        {
            _log($"[{n}/{total}] 레지스트리 HKCU CLSID 하이재킹 검사", LogLevel.Header);
            bool found = false;
            var knownKey = Iocs.ClsidRoot + "\\" + Iocs.KnownBadClsid;

            using (var k = Registry.CurrentUser.OpenSubKey(knownKey))
            {
                if (k != null)
                {
                    found = true;
                    _log($"  [!] 악성 CLSID 발견: HKCU\\{knownKey}", LogLevel.Bad);
                    LogServerValues(k);
                    r.Findings.Add(new Finding
                    {
                        Check = CheckId.Clsid, Fix = FixKind.DeleteRegistryKey, Target = knownKey,
                        Description = $"레지스트리 키 삭제: HKCU\\{knownKey}",
                    });
                }
            }

            // 변종: CLSID 가 달라도 서버 DLL 이 PlatformExperienceHelper\<64자리>\platform_experience_helper.dll 을 가리키면 악성으로 판정
            using (var root = Registry.CurrentUser.OpenSubKey(Iocs.ClsidRoot))
            {
                if (root != null)
                {
                    foreach (var name in root.GetSubKeyNames())
                    {
                        if (string.Equals(name, Iocs.KnownBadClsid, StringComparison.OrdinalIgnoreCase)) continue;
                        foreach (var server in new[] { "InprocServer32", "LocalServer32" })
                        {
                            string val = ReadDefault(Iocs.ClsidRoot + "\\" + name + "\\" + server);
                            if (val == null || val.IndexOf(Iocs.DllName, StringComparison.OrdinalIgnoreCase) < 0) continue;

                            var key = Iocs.ClsidRoot + "\\" + name;
                            if (Iocs.HexDllPath.IsMatch(val))
                            {
                                found = true;
                                _log($"  [!] 변종 CLSID 하이재킹 발견: HKCU\\{key}\\{server} -> {val}", LogLevel.Bad);
                                r.Findings.Add(new Finding
                                {
                                    Check = CheckId.Clsid, Fix = FixKind.DeleteRegistryKey, Target = key,
                                    Description = $"레지스트리 키 삭제: HKCU\\{key}",
                                });
                            }
                            else
                            {
                                _log($"  [?] 의심 항목(자동 삭제 안 함, 직접 확인 필요): HKCU\\{key}\\{server} -> {val}", LogLevel.Warn);
                            }
                            break;
                        }
                    }
                }
            }

            if (!found) _log("  [-] HKCU CLSID 변조 없음", LogLevel.Ok);
            r.Status[CheckId.Clsid] = found;
        }

        private void LogServerValues(RegistryKey clsidKey)
        {
            foreach (var server in new[] { "InprocServer32", "LocalServer32" })
            {
                using (var s = clsidKey.OpenSubKey(server))
                {
                    var v = s?.GetValue("") as string;
                    if (!string.IsNullOrEmpty(v)) _log($"      {server} = {v}", LogLevel.Detail);
                }
            }
        }

        private static string ReadDefault(string subKey)
        {
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(subKey))
                    return k?.GetValue("") is string s ? Environment.ExpandEnvironmentVariables(s) : null;
            }
            catch { return null; }
        }

        // ------------------------------------------------------------------
        // 런처 Local Storage(leveldb) 내 'k2f.agent'
        // ------------------------------------------------------------------
        private void CheckLevelDb(ScanResult r, int n, int total)
        {
            _log($"[{n}/{total}] 런처 Local Storage(leveldb) 내 'k2f.agent' 기록 검사", LogLevel.Header);
            var patterns = Patterns("k2f.agent");
            bool found = false, any = false;
            foreach (var dir in Iocs.TbsCacheDirs)
            {
                var ldb = Path.Combine(dir, "Local Storage", "leveldb");
                if (!Directory.Exists(ldb)) continue;
                any = true;
                foreach (var f in SafeFiles(ldb, false))
                {
                    _ct.ThrowIfCancellationRequested();
                    if (!FileContains(f, patterns)) continue;
                    found = true;
                    _log($"  [!] k2f.agent 발견: {f} (수정: {SafeWriteTime(f)})", LogLevel.Bad);
                    AddTbsFinding(r, CheckId.LevelDb, dir);
                }
            }
            if (!any) _log("  [-] 런처 Local Storage 폴더 없음", LogLevel.Ok);
            else if (!found) _log("  [-] 'k2f.agent' 흔적 없음", LogLevel.Ok);
            r.Status[CheckId.LevelDb] = found;
        }

        // ------------------------------------------------------------------
        // tbs_cache 내 insightjs.(com|org)
        // ------------------------------------------------------------------
        private void CheckTbsCache(ScanResult r, int n, int total)
        {
            _log($"[{n}/{total}] 런처 tbs_cache 내 악성 로더(insightjs) 캐시 검사", LogLevel.Header);
            var patterns = Patterns("insightjs.com").Concat(Patterns("insightjs.org")).ToArray();
            var hits = new List<(string Path, DateTime Created, DateTime Modified)>();
            bool any = false;
            foreach (var dir in Iocs.TbsCacheDirs)
            {
                if (!Directory.Exists(dir)) continue;
                any = true;
                _log($"  {dir} 확인 중", LogLevel.Detail);
                foreach (var f in SafeFiles(dir, true))
                {
                    _ct.ThrowIfCancellationRequested();
                    if (!FileContains(f, patterns)) continue;
                    hits.Add((f, SafeCreationTime(f), SafeWriteTime(f)));
                    AddTbsFinding(r, CheckId.TbsCache, dir);
                }
            }
            if (hits.Count > 0)
            {
                _log($"  [!] 악성 로더 흔적 {hits.Count}개 파일 발견 (생성 시각 = 최초 유입 시각):", LogLevel.Bad);
                foreach (var h in hits.OrderBy(h => h.Created).Take(100))
                    _log($"      생성 {h.Created:yyyy-MM-dd HH:mm:ss} | 수정 {h.Modified:yyyy-MM-dd HH:mm:ss} | {h.Path}", LogLevel.Warn);
                if (hits.Count > 100) _log($"      … 외 {hits.Count - 100}개", LogLevel.Warn);
            }
            else _log(any ? "  [-] 악성 도메인 흔적 없음" : "  [-] 런처 tbs_cache 폴더 없음", LogLevel.Ok);
            r.Status[CheckId.TbsCache] = hits.Count > 0;
        }

        private static void AddTbsFinding(ScanResult r, CheckId check, string dir)
        {
            if (r.Findings.Any(f => f.Fix == FixKind.DeleteTbsCache && f.Target == dir && f.Check == check)) return;
            r.Findings.Add(new Finding
            {
                Check = check, Fix = FixKind.DeleteTbsCache, Target = dir,
                Description = $"런처 캐시 폴더 삭제: {dir}",
            });
        }

        // ------------------------------------------------------------------
        // 런처 로그 (debug.log / tinyget.*.log) — 증거 확인용, 치료 대상 아님
        // ------------------------------------------------------------------
        private void CheckLogs(ScanResult r, string installPath, int n, int total)
        {
            _log($"[{n}/{total}] 런처 로그(debug.log / tinyget.*.log) 실행 이력 검사", LogLevel.Header);
            var path = string.IsNullOrWhiteSpace(installPath) ? null : installPath.Trim().Trim('"');
            if (path == null)
            {
                _log("  니케 설치 경로 자동 탐색 중… (레지스트리 → 드라이브 탐색, 수 분 걸릴 수 있음)", LogLevel.Info);
                path = InstallLocator.Find(_ct, msg => _log("  " + msg, LogLevel.Detail));
            }
            if (path == null || !Directory.Exists(path))
            {
                _log("  [?] 니케 설치 경로를 찾을 수 없습니다. 경로를 직접 지정해 주세요.", LogLevel.Warn);
                r.Status[CheckId.Logs] = null;
                return;
            }
            r.InstallPath = path;
            _log($"  [+] 니케 설치 폴더: {path}", LogLevel.Info);
            bool found = false;

            var debugLog = Path.Combine(path, "Launcher", "intl_service", "debug.log");
            if (File.Exists(debugLog))
            {
                var lines = new List<(int No, string Text)>();
                int no = 0;
                foreach (var line in SafeReadLines(debugLog))
                {
                    no++;
                    if (Iocs.DebugLogPattern.IsMatch(line)) lines.Add((no, line));
                }
                if (lines.Count > 0)
                {
                    found = true;
                    _log($"  [!] debug.log 에서 악성 에이전트 실행 기록 {lines.Count}줄 발견:", LogLevel.Bad);
                    foreach (var l in lines.Take(300)) _log($"      [Line {l.No}] {l.Text}", LogLevel.Warn);
                    if (lines.Count > 300) _log($"      … 외 {lines.Count - 300}줄", LogLevel.Warn);
                }
                else _log("  [-] debug.log 내 감염 키워드 없음", LogLevel.Ok);
            }
            else _log("  [-] debug.log 없음", LogLevel.Detail);

            var tinyDir = Path.Combine(path, "Launcher", "log", "tinyget");
            if (Directory.Exists(tinyDir))
            {
                var bad = SafeFiles(tinyDir, false)
                    .Where(f => Regex.IsMatch(Path.GetFileName(f), @"^tinyget\..*\.log$", RegexOptions.IgnoreCase))
                    .Where(f => SafeReadLines(f).Any(l => Iocs.TinygetPattern.IsMatch(l)))
                    .OrderBy(SafeCreationTime).ToList();
                if (bad.Count > 0)
                {
                    found = true;
                    _log($"  [!] tinyget 로그에서 악성 페이로드 다운로드 기록 {bad.Count}건 발견:", LogLevel.Bad);
                    foreach (var f in bad)
                        _log($"      생성 {SafeCreationTime(f):yyyy-MM-dd HH:mm:ss} | {Path.GetFileName(f)}", LogLevel.Warn);
                }
                else _log("  [-] tinyget 로그 내 다운로드 기록 없음", LogLevel.Ok);
            }
            else _log("  [-] tinyget 로그 폴더 없음", LogLevel.Detail);

            if (found) _log("  ※ 로그는 감염 이력 증거입니다. 로그 자체는 삭제하지 않습니다.", LogLevel.Info);
            r.Status[CheckId.Logs] = found;
        }

        // ------------------------------------------------------------------
        // 유틸리티
        // ------------------------------------------------------------------
        private static byte[][] Patterns(string ascii) => new[]
        {
            Encoding.ASCII.GetBytes(ascii.ToLowerInvariant()),
            Encoding.Unicode.GetBytes(ascii.ToLowerInvariant()), // UTF-16LE (leveldb 등)
        };

        /// <summary>대소문자 무시 ASCII 바이트 검색 (파일을 스트리밍으로 읽음).</summary>
        private bool FileContains(string path, byte[][] patterns)
        {
            int maxLen = patterns.Max(p => p.Length);
            var buf = new byte[1 << 20];
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete, 1 << 16))
                {
                    int carry = 0, read;
                    while ((read = fs.Read(buf, carry, buf.Length - carry)) > 0)
                    {
                        _ct.ThrowIfCancellationRequested();
                        int len = carry + read;
                        foreach (var p in patterns)
                            if (IndexOfIgnoreCase(buf, len, p) >= 0) return true;
                        carry = Math.Min(maxLen - 1, len);
                        Buffer.BlockCopy(buf, len - carry, buf, 0, carry);
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { /* 잠긴/권한 없는 파일은 건너뜀 */ }
            return false;
        }

        private static int IndexOfIgnoreCase(byte[] data, int len, byte[] p)
        {
            byte first = p[0];
            for (int i = 0; i <= len - p.Length; i++)
            {
                if (Lower(data[i]) != first) continue;
                int j = 1;
                while (j < p.Length && Lower(data[i + j]) == p[j]) j++;
                if (j == p.Length) return i;
            }
            return -1;
        }

        private static byte Lower(byte b) => (b >= (byte)'A' && b <= (byte)'Z') ? (byte)(b | 0x20) : b;

        internal static IEnumerable<string> SafeDirs(string dir)
        {
            try { return Directory.GetDirectories(dir); } catch { return Array.Empty<string>(); }
        }

        internal static IEnumerable<string> SafeFiles(string dir, bool recurse)
        {
            string[] files;
            try { files = Directory.GetFiles(dir); } catch { files = Array.Empty<string>(); }
            foreach (var f in files) yield return f;
            if (!recurse) yield break;
            foreach (var d in SafeDirs(dir))
            {
                try { if ((new DirectoryInfo(d).Attributes & FileAttributes.ReparsePoint) != 0) continue; } catch { continue; }
                foreach (var f in SafeFiles(d, true)) yield return f;
            }
        }

        private static IEnumerable<string> SafeReadLines(string path)
        {
            StreamReader sr;
            try
            {
                sr = new StreamReader(new FileStream(path, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete), Encoding.UTF8, true);
            }
            catch { yield break; }
            using (sr)
            {
                string line;
                while (true)
                {
                    try { line = sr.ReadLine(); } catch { yield break; }
                    if (line == null) yield break;
                    yield return line;
                }
            }
        }

        private static DateTime SafeCreationTime(string p) { try { return File.GetCreationTime(p); } catch { return DateTime.MinValue; } }
        private static DateTime SafeWriteTime(string p) { try { return File.GetLastWriteTime(p); } catch { return DateTime.MinValue; } }
    }

    public static class InstallLocator
    {
        private static readonly string[] SkipDirs = { "Windows", "$Recycle.Bin", "System Volume Information", "$WinREAgent", "Recovery" };

        public static string Find(CancellationToken ct, Action<string> log)
        {
            // 1. 레지스트리 Uninstall\nikke_launcher
            foreach (var (hive, view, sub) in new[]
            {
                (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\nikke_launcher"),
                (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\nikke_launcher"),
                (RegistryHive.CurrentUser,  RegistryView.Default,    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\nikke_launcher"),
            })
            {
                try
                {
                    using (var b = RegistryKey.OpenBaseKey(hive, view))
                    using (var k = b.OpenSubKey(sub))
                    {
                        var u = k?.GetValue("UninstallString") as string;
                        if (string.IsNullOrWhiteSpace(u)) continue;
                        var root = Path.GetDirectoryName(u.Trim().Trim('"'));
                        if (root != null && IsNikkeRoot(root)) { log($"레지스트리에서 설치 경로 확인: {root}"); return root; }
                    }
                }
                catch { }
            }

            // 2. 고정/이동식 드라이브 탐색 (최대 7단계)
            foreach (var drive in DriveInfo.GetDrives())
            {
                ct.ThrowIfCancellationRequested();
                try { if (!drive.IsReady || (drive.DriveType != DriveType.Fixed && drive.DriveType != DriveType.Removable)) continue; }
                catch { continue; }
                log($"{drive.Name} 드라이브 탐색 중…");
                var found = Search(drive.RootDirectory.FullName, 0, ct);
                if (found != null) { log($"드라이브 탐색으로 설치 경로 확인: {found}"); return found; }
            }
            return null;
        }

        private static bool IsNikkeRoot(string root) =>
            File.Exists(Path.Combine(root, "Launcher", "nikke_launcher.exe")) ||
            File.Exists(Path.Combine(root, "launcher", "nikke_launcher_google.exe"));

        private static string Search(string dir, int depth, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            if (depth > 0 && string.Equals(Path.GetFileName(dir), "Launcher", StringComparison.OrdinalIgnoreCase))
            {
                var parent = Path.GetDirectoryName(dir);
                if (parent != null && IsNikkeRoot(parent)) return parent;
            }
            if (depth >= 7) return null;
            foreach (var sub in Scanner.SafeDirs(dir))
            {
                if (depth == 0 && SkipDirs.Contains(Path.GetFileName(sub), StringComparer.OrdinalIgnoreCase)) continue;
                try { if ((new DirectoryInfo(sub).Attributes & FileAttributes.ReparsePoint) != 0) continue; } catch { continue; }
                var r = Search(sub, depth + 1, ct);
                if (r != null) return r;
            }
            return null;
        }
    }
}
