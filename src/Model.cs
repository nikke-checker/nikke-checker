using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace NikkeChecker
{
    public enum CheckId { BrowserDll, Clsid, Processes, LauncherData, Temp, InstallLogs, Exposure, Protection }

    public enum Severity { Info, Warning, Critical }

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

        public string FixDescription
        {
            get
            {
                switch (Fix)
                {
                    case FixKind.DeleteDirectory: return "폴더 삭제: " + Target;
                    case FixKind.DeleteFile: return "파일 삭제: " + Target;
                    case FixKind.DeleteFileElevated: return "파일 삭제(관리자): " + Target;
                    case FixKind.DeleteRegistryKey: return "레지스트리 키 삭제: HKCU\\" + Target;
                    case FixKind.DeleteTbsCache: return "런처 캐시 삭제: " + Target;
                    case FixKind.KillProcess: return $"프로세스 종료: {Target} (PID {Pid})";
                    default: return null;
                }
            }
        }
    }

    public sealed class ScanOptions
    {
        public HashSet<CheckId> Checks = new HashSet<CheckId>();
        public string InstallPath;
    }

    public sealed class ScanResult
    {
        public List<Finding> Findings = new List<Finding>();
        public Dictionary<CheckId, bool> Unknown = new Dictionary<CheckId, bool>();
        public HashSet<CheckId> Checked = new HashSet<CheckId>();
        public List<string> Installs = new List<string>();
        public List<string> LauncherDataDirs = new List<string>();
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

        public IEnumerable<Finding> Fixable => Findings.Where(f => f.Fix != FixKind.None && f.Severity != Severity.Info);
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

        public static string[] LauncherDataDirs => new[]
        {
            Path.Combine(AppData, "nikke_launcher"),
            Path.Combine(AppData, "nikke_launcher_hmt"),
        };

        // (표시 이름, User Data 경로, 프로세스 이름) — 에이전트의 browserscan 대상과 동일
        public static (string Name, string Path, string Process)[] Browsers => new[]
        {
            ("Chrome",   System.IO.Path.Combine(LocalAppData, @"Google\Chrome\User Data"), "chrome"),
            ("Edge",     System.IO.Path.Combine(LocalAppData, @"Microsoft\Edge\User Data"), "msedge"),
            ("Brave",    System.IO.Path.Combine(LocalAppData, @"BraveSoftware\Brave-Browser\User Data"), "brave"),
            ("Vivaldi",  System.IO.Path.Combine(LocalAppData, @"Vivaldi\User Data"), "vivaldi"),
            ("Opera",    System.IO.Path.Combine(AppData, @"Opera Software\Opera Stable"), "opera"),
            ("Opera GX", System.IO.Path.Combine(AppData, @"Opera Software\Opera GX Stable"), "opera"),
            ("Chromium", System.IO.Path.Combine(LocalAppData, @"Chromium\User Data"), "chromium"),
        };

        // 에이전트 wallet_files 명령이 노리는 지갑 확장 ID
        public static readonly (string Id, string Name)[] Wallets =
        {
            ("acmacodkjbdgmoleebolmdjonilkdbch", "Rabby"), ("aflkmfhebedbjioipglgcbcmnbpgliof", "Backpack"),
            ("bfnaelmomeimhlpmgjnjophhpkkoljpa", "Phantom"), ("bhhhlbepdkbapadjdnnojkbgioiodbic", "Solflare"),
            ("cadiboklkpojfamcoggejbbdjcoiljjk", "Binance Wallet"), ("dmkamcknogkgcdfhhbddcghachkejeap", "Keplr"),
            ("egjidjbpglichdcondbcbdnbeeppgdph", "Trust Wallet"), ("fnjhmkhhmkbjkkabndcnnogagogbneec", "Ronin Wallet"),
            ("hnfanknocfeofbddgcijnmhnfnkdnaad", "Coinbase Wallet"), ("ibnejdfjmmkpcnlpebklmnkoeoihofec", "TronLink"),
            ("jiidiaalihmmhddjgbnbgdfflelocpak", "Bitget Wallet"), ("mcohilncbfahbmgdjkbpemcciiolgcge", "OKX Wallet"),
            ("nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask"), ("omaabbefbmiijedngplfjmnooppbclkk", "Tonkeeper"),
            ("opcgpfmipidbgpenhmajoajpbobppdil", "Slush"), ("pdliaogehgdbhbnmkklieghmmjkpigpa", "Bybit Wallet"),
            ("jblndlipeogpafnldhgmapagcccfchpi", "Kaia Wallet"), ("aiifbnbfobpmeekipheeijimdpnlpgpp", "Station"),
            ("ppbibelpcjmhbdihakflkdcoccbgbkpo", "UniSat"), ("idnnbdplmphpflfnlkomgpfbpcgelopg", "Xverse"),
            ("mkpegjkblkkefacfnmkajcjmabijhclg", "Magic Eden"), ("ejjladinnckdgjemekebdpeokbikhfci", "Petra"),
            ("dlcobpjiigpikoobohmabehhmhfoodbb", "Ready"), ("gjagmgiddbbciopjhllkdnddhcglnemk", "HashPack"),
            ("onhogfjeacnfoofkfgppdlbmlmnplgbn", "SubWallet"), ("opfgelmcmbiajamepnmloijbpoleiama", "Rainbow"),
            ("jnlgamecbpmbajjfhmmmlhejkemejdma", "Braavos"), ("phkbamefinggmakgklpkljjmgibohnba", "Pontem"),
        };

        // 에이전트 keyscan 명령이 노리는 인증 파일 (사용자 프로필 기준, Windows 에서 의미 있는 것만)
        public static readonly (string Name, string Rel)[] Secrets =
        {
            ("AWS 자격 증명", @".aws\credentials"),
            ("GitHub CLI 토큰", @".config\gh\hosts.yml"), ("GitHub CLI 토큰", @"AppData\Roaming\GitHub CLI\hosts.yml"),
            ("Git 자격 증명", ".git-credentials"), ("Git 자격 증명", @".config\git\credentials"),
            ("npm 설정(토큰 포함 가능)", ".npmrc"), ("Docker 레지스트리 로그인", @".docker\config.json"),
            ("Kubernetes 설정", @".kube\config"),
            ("Google Cloud 자격 증명", @"AppData\Roaming\gcloud\credentials.db"),
            ("Google Cloud 자격 증명", @"AppData\Roaming\gcloud\application_default_credentials.json"),
            ("Azure CLI 토큰", @".azure\msal_token_cache.bin"), ("Azure CLI 토큰", @".azure\msal_token_cache.json"),
            ("Azure CLI 토큰", @".azure\accessTokens.json"),
            ("Claude Code 자격 증명", @".claude\.credentials.json"), ("Codex CLI 자격 증명", @".codex\auth.json"),
            ("Gemini CLI 자격 증명", @".gemini\oauth_creds.json"), ("GitHub Copilot CLI MCP 설정", @".copilot\mcp-config.json"),
            ("opencode 자격 증명", @".local\share\opencode\auth.json"),
            ("FileZilla 저장 서버", @"AppData\Roaming\FileZilla\sitemanager.xml"),
            ("FileZilla 저장 서버", @"AppData\Roaming\FileZilla\recentservers.xml"),
            ("netrc 로그인", ".netrc"), ("netrc 로그인", "_netrc"), ("PyPI 토큰", ".pypirc"),
            ("crates.io 토큰", @".cargo\credentials.toml"), ("crates.io 토큰", @".cargo\credentials"),
            ("HashiCorp Vault 토큰", ".vault-token"),
            ("Terraform 토큰", @"AppData\Roaming\terraform.d\credentials.tfrc.json"),
            ("Pulumi 자격 증명", @".pulumi\credentials.json"), ("Kaggle API 키", @".kaggle\kaggle.json"),
            ("Hugging Face 토큰", @".cache\huggingface\token"),
            ("rclone 설정", @"AppData\Roaming\rclone\rclone.conf"), ("s3cmd 설정", ".s3cfg"),
            ("Databricks 설정", ".databrickscfg"), ("Oracle Cloud 설정", @".oci\config"),
            ("GnuPG 개인 키", @"AppData\Roaming\gnupg\private-keys-v1.d"), (".env 파일", ".env"),
        };
    }
}
