using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using static NikkeChecker.I18n;

namespace NikkeChecker
{
    public enum CheckId { BrowserDll, Clsid, Processes, LauncherData, Temp, InstallLogs, FullScan, Autostart, Protection }

    // Review = 「확인 필요」(자동 실행 프로그램). 판정에는 영향이 없고, 사용자가 고른 것만 지운다.
    public enum Severity { Info, Review, Warning, Critical }

    public enum LogLevel { Info, Header, Ok, Warn, Bad, Action, Detail }

    public enum FixKind
    {
        None,
        DeleteDirectory,     // 브라우저 64자리 폴더
        DeleteFile,          // 사용자 영역 파일 (Temp k2f 파일, 에이전트 파일, PEH 루트의 DLL 등)
        DeleteFileElevated,  // Program Files 아래 구버전 지속성 파일 (관리자 권한)
        DeleteRegistryKey,   // HKCU 하위 키
        DeleteTbsCache,      // 런처 tbs_cache 폴더
        KillProcess,         // PID
    }

    public enum Verdict { Infected, Exposed, Clean, NotFound }

    public sealed class Finding
    {
        public CheckId Check;
        public Severity Severity;
        public string Title;
        public List<string> Evidence = new List<string>();
        public FixKind Fix;
        public string Target;     // 경로 또는 HKCU 기준 레지스트리 키
        public int Pid;           // KillProcess
        public string Browser;    // DeleteDirectory: 종료할 브라우저 프로세스 이름
        public string BrowserHint; // 프로세스 이름이 흔할 때(browser.exe) 실행 파일 경로에 들어 있어야 하는 문자열
        public AutostartItem Auto;  // Autostart 항목

        public string FixDescription
        {
            get
            {
                switch (Fix)
                {
                    case FixKind.DeleteDirectory: return L("폴더 삭제: ", "Delete folder: ") + Target;
                    case FixKind.DeleteFile: return L("파일 삭제: ", "Delete file: ") + Target;
                    case FixKind.DeleteFileElevated: return L("파일 삭제(관리자): ", "Delete file (admin): ") + Target;
                    case FixKind.DeleteRegistryKey: return L("레지스트리 키 삭제: HKCU\\", "Delete registry key: HKCU\\") + Target;
                    case FixKind.DeleteTbsCache: return L("런처 캐시 삭제: ", "Delete launcher cache: ") + Target;
                    case FixKind.KillProcess: return L($"프로세스 종료: {Target} (PID {Pid})", $"End process: {Target} (PID {Pid})");
                    default: return null;
                }
            }
        }
    }

    public sealed class ScanOptions
    {
        public HashSet<CheckId> Checks = new HashSet<CheckId>();
        public string InstallPath;
        public Func<List<AutostartItem>> AuditSystem;   // 관리자 권한으로 PC 전체 자동 실행을 읽는 함수 (null 이면 건너뜀)
    }

    public sealed class ScanResult
    {
        public List<Finding> Findings = new List<Finding>();
        public Dictionary<CheckId, bool> Unknown = new Dictionary<CheckId, bool>();
        public HashSet<CheckId> Checked = new HashSet<CheckId>();
        public List<string> Installs = new List<string>();
        public List<string> LauncherDataDirs = new List<string>();
        public List<string> DiskLaunchers = new List<string>();   // 전체 드라이브 검사에서 찾은 설치 루트 후보
        public List<string> Unreadable = new List<string>();      // 읽지 못해 검사가 불완전한 파일
        public string HkcuDllPath;

        public Severity? Worst(CheckId id)
        {
            var f = Findings.Where(x => x.Check == id).ToList();
            return f.Count == 0 ? (Severity?)null : f.Max(x => x.Severity);
        }

        public Verdict Verdict
        {
            get
            {
                if (Findings.Any(f => f.Severity == Severity.Critical)) return Verdict.Infected;
                if (Findings.Any(f => f.Severity == Severity.Warning)) return Verdict.Exposed;
                bool lookedForNikke = Checked.Contains(CheckId.InstallLogs) || Checked.Contains(CheckId.LauncherData);
                if (lookedForNikke && Installs.Count == 0 && LauncherDataDirs.Count == 0) return Verdict.NotFound;
                return Verdict.Clean;
            }
        }

        public IEnumerable<Finding> Fixable => Findings.Where(f => f.Fix != FixKind.None && (f.Severity == Severity.Warning || f.Severity == Severity.Critical));
        public IEnumerable<AutostartItem> Review => Findings.Where(f => f.Auto != null).Select(f => f.Auto);
    }

    public delegate void Logger(string message, LogLevel level);

    public static class Iocs
    {
        public const string BadClsid = "{E77CC89B-7401-4C04-8CED-149DB35ADD04}";
        public static readonly string[] ClsidKeys =
        {
            @"Software\Classes\CLSID\" + BadClsid,
            @"Software\Classes\WOW6432Node\CLSID\" + BadClsid,
        };
        public const string ClsidRoot = @"Software\Classes\CLSID";
        public const string DllName = "platform_experience_helper.dll";
        public static readonly string[] OldPersistenceFiles = { "platform_experience_helper.dll", "platform_experience_helper.dll.old", "old-clsid.txt" };
        public const string OldPersistenceDir = @"Google\Chrome\Application\PlatformExperienceHelper";

        public static readonly string[] BlockDomains = { "insightjs.com", "analytics.insightjs.com", "insightjs.org" };
        public static readonly string[] C2Ips = { "89.127.233.127", "89.126.250.172" };
        public const string FirewallRuleName = "Block_Nikke_Malware_C2";
        public const string LegacyFirewallRuleName = "Block_Nikke_Malware_C2_89.127.233.127";

        public static readonly string[] LauncherProcesses = { "nikke_launcher", "nikke_launcher_google", "tbs_browser", "intl_service" };

        // HSTS 키 = base64(SHA-256(DNS wire format 호스트 이름)) — TransportSecurity 에는 도메인 문자열이 남지 않음
        public static readonly (string Domain, string Key)[] HstsKeys =
        {
            ("insightjs.com", "JeFWywdZy+3jPC93e3P7ACdJ8liQHB7rH+9VHn7kswg="),
            ("analytics.insightjs.com", "wxL1BeG57AG6frvPqS7txqpE3NyN0/fSUZHCbEn9NSw="),
            ("insightjs.org", "+EQMCXxbp1N4L3mxYGR66hSUD0cvdir6DDtJBLH3wPk="),
        };

        public const long KnownAgentSize = 205135;
        // insight.bundle 빌드 (ETag "<mtime hex>-3214f")
        public static readonly string[] KnownBuildEtags = { "6ae78037", "6ae8ccff", "6ae90538", "6ae9d408", "6ae9f628" };

        public static readonly Regex Hex64 = new Regex("^[0-9a-fA-F]{64}$", RegexOptions.Compiled);
        public static readonly Regex Hex22Tmp = new Regex("^[0-9a-f]{22}$", RegexOptions.Compiled);
        public static readonly Regex LoadedDllPath = new Regex(
            @"\\PlatformExperienceHelper\\([0-9a-fA-F]{64}\\)?platform_experience_helper\.dll$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);
        public static readonly Regex HexDllPath = new Regex(
            @"\\PlatformExperienceHelper\\[0-9a-fA-F]{64}\\platform_experience_helper\.dll",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public static string AppData => Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        public static string LocalAppData => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        public static string UserProfile => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        /// <summary>에이전트가 만드는 이름 형식(k2f-, k2f_, k2f.)만. 대소문자 구분 — K2F3A.tmp 같은 임의 이름 오탐 방지.</summary>
        public static bool IsK2fName(string n) =>
            n.StartsWith("k2f-", StringComparison.Ordinal) || n.StartsWith("k2f_", StringComparison.Ordinal) || n.StartsWith("k2f.", StringComparison.Ordinal);

        /// <summary>전체 드라이브 검사에서 이름으로 모을 파일.</summary>
        public static bool IsDiskScanName(string n)
        {
            if (IsK2fName(n)) return true;
            var s = n.ToLowerInvariant();
            return s.StartsWith("tinyget") || s == "nikke_launcher.exe" || s.StartsWith(DllName) || s == "old-clsid.txt" || s == "insight.bundle";
        }

        public static string[] LauncherDataDirs => new[]
        {
            Path.Combine(AppData, "nikke_launcher"),
            Path.Combine(AppData, "nikke_launcher_hmt"),
        };

        // (표시 이름, User Data 경로, 프로세스 이름) — PlatformExperienceHelper 지속성 점검 대상
        // Chromium 계열 브라우저: (표시 이름, User Data 경로, 프로세스 이름, 실행 파일 경로 힌트)
        // 프로세스 이름이 browser.exe 처럼 흔한 브라우저는 힌트가 경로에 들어 있는 프로세스만 종료한다.
        public static List<(string Name, string Path, string Process, string Hint)> Browsers
        {
            get
            {
                var list = new List<(string, string, string, string)>
                {
                    ("Chrome",        System.IO.Path.Combine(LocalAppData, @"Google\Chrome\User Data"), "chrome", null),
                    ("Edge",          System.IO.Path.Combine(LocalAppData, @"Microsoft\Edge\User Data"), "msedge", null),
                    ("Brave",         System.IO.Path.Combine(LocalAppData, @"BraveSoftware\Brave-Browser\User Data"), "brave", null),
                    ("Vivaldi",       System.IO.Path.Combine(LocalAppData, @"Vivaldi\User Data"), "vivaldi", null),
                    ("Opera",         System.IO.Path.Combine(AppData, @"Opera Software\Opera Stable"), "opera", null),
                    ("Opera GX",      System.IO.Path.Combine(AppData, @"Opera Software\Opera GX Stable"), "opera", null),
                    ("Chromium",      System.IO.Path.Combine(LocalAppData, @"Chromium\User Data"), "chromium", null),
                    (L("네이버 웨일", "Naver Whale"), System.IO.Path.Combine(LocalAppData, @"Naver\Naver Whale\User Data"), "whale", null),
                    ("Yandex",        System.IO.Path.Combine(LocalAppData, @"Yandex\YandexBrowser\User Data"), "browser", @"\Yandex\"),
                    ("Cốc Cốc",       System.IO.Path.Combine(LocalAppData, @"CocCoc\Browser\User Data"), "browser", @"\CocCoc\"),
                    ("Comodo Dragon", System.IO.Path.Combine(LocalAppData, @"Comodo\Dragon\User Data"), "dragon", null),
                    ("Thorium",       System.IO.Path.Combine(LocalAppData, @"Thorium\User Data"), "thorium", null),
                    ("Epic",          System.IO.Path.Combine(LocalAppData, @"Epic Privacy Browser\User Data"), "epic", null),
                };
                // Arc 는 MSIX 패키지라 패키지 폴더 아래에 User Data 가 있다
                try
                {
                    var packages = System.IO.Path.Combine(LocalAppData, "Packages");
                    if (Directory.Exists(packages))
                        foreach (var pkg in Directory.GetDirectories(packages, "TheBrowserCompany.Arc_*"))
                            list.Add(("Arc", System.IO.Path.Combine(pkg, @"LocalCache\Local\Arc\User Data"), "arc", null));
                }
                catch { }
                return list;
            }
        }
    }
}
