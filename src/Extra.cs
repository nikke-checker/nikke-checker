using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;
using static NikkeChecker.I18n;

namespace NikkeChecker
{
    /// <summary>
    /// 추가 보안 점검 (햄찌 NIKKE_k2f_cleaner v4.1, Cloudflare security-audit-skill 방식으로 찾은 빈틈).
    /// 확실한 흔적(해커 서버 연결·DNS 기록)은 Finding 으로, 정상일 수도 있는 설정은 「확인 필요」 항목으로 돌려준다.
    /// 정상 파일을 지우지 않는다: 브라우저는 끄기만, 바로가기는 옵션만 지움, 설정은 끄거나 Windows 기본값으로 되돌림,
    /// 원격 접속 프로그램은 설치된 것이면 공식 제거 프로그램만 띄운다.
    /// </summary>
    public static class Extra
    {
        public static readonly string[] BrowserExes = { "chrome.exe", "msedge.exe", "brave.exe", "vivaldi.exe", "opera.exe", "whale.exe" };
        private static readonly Regex BadFlags = new Regex(@"--remote-debugging-(port|pipe|address)|--load-extension|--disable-extensions-except", RegexOptions.IgnoreCase);
        private static readonly Regex StripFlags = new Regex(@"\s*--(remote-debugging-(port|pipe|address)|load-extension|disable-extensions-except|remote-allow-origins)(=(""[^""]*""|\S+))?", RegexOptions.IgnoreCase);
        private static readonly string[] PolicyBrowsers = { @"Google\Chrome", @"Microsoft\Edge", @"BraveSoftware\Brave", "Chromium" };
        private static readonly Regex RatName = new Regex(@"AnyDesk|TeamViewer|RustDesk|ScreenConnect|ConnectWise Control|Splashtop|Atera|ngrok|AeroAdmin|UltraViewer|Supremo|RemotePC|NetSupport|Radmin|DWAgent|MeshAgent|TightVNC|UltraVNC|RealVNC|Ammyy|LogMeIn|Chrome Remote Desktop", RegexOptions.IgnoreCase);
        private static readonly string[] RatProcs =
        {
            "AnyDesk", "TeamViewer", "TeamViewer_Service", "rustdesk", "ScreenConnect.ClientService", "ScreenConnect.WindowsClient", "SRService", "SRManager",
            "AteraAgent", "ngrok", "AeroAdmin", "UltraViewer_Service", "UltraViewer_Desktop", "Supremo", "SupremoService", "RemotePCService", "client32",
            "rserver3", "dwagent", "MeshAgent", "tvnserver", "winvnc", "vncserver", "AA_v3", "LMIGuardianSvc", "remoting_host",
        };

        private static string MakeId(params string[] parts)
        {
            using (var sha = SHA256.Create())
                return string.Concat(sha.ComputeHash(Encoding.UTF8.GetBytes(string.Join("|", parts).ToLowerInvariant())).Take(10).Select(b => b.ToString("x2")));
        }

        private static AutostartItem Item(string kind, string scope, string where, string name, string display, string file = null) =>
            new AutostartItem { Kind = kind, Group = "extra", Scope = scope, Where = where, Name = name, Display = display, File = file, Date = "-" };

        // ------------------------------------------------------------------
        // 확실한 흔적: 지금 해커 서버와 연결 중인 프로그램 (netstat -ano)
        // ------------------------------------------------------------------
        public static List<(int Pid, string Remote, string Name, string Path)> C2Connections()
        {
            var list = new List<(int, string, string, string)>();
            var output = RunCapture(Paths.Sys("netstat.exe"), "-ano -p TCP");
            if (output == null) return list;
            foreach (var line in output.Split('\n'))
            {
                var parts = line.Trim().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 5 || !parts[0].Equals("TCP", StringComparison.OrdinalIgnoreCase)) continue;
                var remote = parts[2];
                var ip = remote.Contains(":") ? remote.Substring(0, remote.LastIndexOf(':')) : remote;
                if (!Iocs.C2Ips.Contains(ip) || !int.TryParse(parts[parts.Length - 1], out var pid)) continue;
                string name = "PID " + pid, path = null;
                try { using (var p = Process.GetProcessById(pid)) { name = p.ProcessName; try { path = p.MainModule?.FileName; } catch { } } } catch { }
                list.Add((pid, remote, name, path));
            }
            return list;
        }

        // 최근 해커 주소를 찾아본 기록 (DNS 캐시, 재부팅 전까지 남음). hosts 차단으로 생긴 0.0.0.0 등은 제외
        public static List<string> DnsHits()
        {
            var hits = new List<string>();
            try
            {
                using (var s = new ManagementObjectSearcher(@"root\StandardCimv2", "SELECT Entry, Data FROM MSFT_DNSClientCache"))
                    foreach (ManagementObject o in s.Get())
                    {
                        var entry = o["Entry"] as string ?? ""; var data = o["Data"] as string ?? "";
                        if (!Regex.IsMatch(entry, @"(^|\.)insightjs\.(com|org)$", RegexOptions.IgnoreCase)) continue;
                        if (data.Length == 0 || new[] { "0.0.0.0", "127.0.0.1", "::", "::1" }.Contains(data)) continue;
                        var h = $"{entry} -> {data}";
                        if (!hits.Contains(h)) hits.Add(h);
                    }
            }
            catch { }
            return hits;
        }

        // ------------------------------------------------------------------
        // 확인 필요 항목 — 현재 사용자 범위
        // ------------------------------------------------------------------
        public static List<AutostartItem> AuditUser(CancellationToken ct)
        {
            var list = new List<AutostartItem>();
            // 원격 조종 모드로 켜진 브라우저 (정보 탈취 프로그램이 쿠키를 빼 가는 흔한 방식)
            try
            {
                using (var s = new ManagementObjectSearcher("SELECT ProcessId, Name, CommandLine, ExecutablePath FROM Win32_Process"))
                    foreach (ManagementObject o in s.Get())
                    {
                        var name = o["Name"] as string ?? "";
                        if (!BrowserExes.Contains(name, StringComparer.OrdinalIgnoreCase)) continue;
                        var m = BadFlags.Match(o["CommandLine"] as string ?? "");
                        if (!m.Success) continue;
                        var pid = Convert.ToInt32(o["ProcessId"]);
                        if (list.Any(x => x.Kind == "BrowserProc" && x.Name == name && x.Display.EndsWith(m.Value))) continue;
                        var it = Item("BrowserProc", "user", L("브라우저 원격 조종 모드 (개발 도구가 아니면 쿠키를 빼 가는 방식)", "Browser in remote-control mode (unless a developer tool: cookie theft)"),
                            name, $"{name} (PID {pid})  {m.Value}");
                        it.Pid = pid; it.ProcName = Path.GetFileNameWithoutExtension(name);
                        it.Id = MakeId("BrowserProc", o["ExecutablePath"] as string ?? name, m.Value);
                        list.Add(it);
                    }
            }
            catch { }
            ct.ThrowIfCancellationRequested();
            var ad = Iocs.AppData;
            AuditShortcuts(list, "user", new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Path.Combine(ad, @"Microsoft\Windows\Start Menu\Programs"),
                Path.Combine(ad, @"Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"),
            });
            AuditPolicies(list, RegistryHive.CurrentUser, "user");

            // 인터넷 통신 가로채기 (프록시·자동 설정 주소)
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings"))
                {
                    if (k != null)
                    {
                        var where = L("인터넷 통신 가로채기 (직접 한 게 아니면 통신을 엿봄)", "Internet traffic redirection (if you did not set it, traffic may be intercepted)");
                        var server = k.GetValue("ProxyServer") as string;
                        if (Convert.ToInt32(k.GetValue("ProxyEnable") ?? 0) == 1 && !string.IsNullOrEmpty(server))
                        {
                            var it = Item("Proxy", "user", where, "ProxyServer", "ProxyServer = " + server);
                            it.Hive = RegistryHive.CurrentUser; it.View = RegistryView.Default; it.Key = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
                            it.Id = MakeId("Proxy", server); list.Add(it);
                        }
                        var pac = k.GetValue("AutoConfigURL") as string;
                        if (!string.IsNullOrEmpty(pac))
                        {
                            var it = Item("RegValue", "user", where, "AutoConfigURL", "AutoConfigURL = " + pac);
                            it.Hive = RegistryHive.CurrentUser; it.View = RegistryView.Default; it.Key = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings"; it.Value = "AutoConfigURL";
                            it.Id = MakeId("Pac", pac); list.Add(it);
                        }
                    }
                }
            }
            catch { }

            // 이 사용자만 바뀐 Windows 시작 프로그램(Shell)
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"))
                {
                    var shell = k?.GetValue("Shell") as string;
                    if (!string.IsNullOrEmpty(shell))
                    {
                        var it = Item("RegValue", "user", L("이 사용자만 Windows 시작 프로그램(Shell)이 바뀌어 있음", "Windows startup shell changed for this user"), "Shell", "Shell = " + shell, Autostart.RunTarget(shell));
                        it.Hive = RegistryHive.CurrentUser; it.View = RegistryView.Default; it.Key = @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"; it.Value = "Shell";
                        it.Id = MakeId("UserShell", shell); list.Add(it);
                    }
                }
            }
            catch { }

            // 실행 중인 원격 접속 프로그램
            foreach (var n in RatProcs)
                foreach (var p in Process.GetProcessesByName(n))
                    using (p)
                    {
                        string path = null; try { path = p.MainModule?.FileName; } catch { }
                        var it = Item("RatProc", "user", L("실행 중인 원격 접속 프로그램 (직접 쓰는 게 아니면 해커가 조종 중일 수 있음)", "Remote-access app running now (if you are not using it, a hacker may be in control)"),
                            p.ProcessName, $"{p.ProcessName}  {path}", path);
                        it.Pid = p.Id; it.ProcName = p.ProcessName;
                        it.Id = MakeId("RatProc", p.ProcessName, path ?? "");
                        if (!list.Any(x => x.Id == it.Id)) list.Add(it);
                    }
            AuditRatApps(list, RegistryHive.CurrentUser, RegistryView.Default, "user");
            return list;
        }

        // ------------------------------------------------------------------
        // 확인 필요 항목 — PC 전체 범위 (관리자)
        // ------------------------------------------------------------------
        public static List<AutostartItem> AuditSystem(CancellationToken ct, Action<string> note = null)
        {
            var list = new List<AutostartItem>();
            AuditShortcuts(list, "system", new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms),
            });
            AuditPolicies(list, RegistryHive.LocalMachine, "system");
            try { AuditExclusions(list); } catch (Exception ex) { note?.Invoke(L("Defender 제외 목록을 읽지 못함 (다른 백신 사용 등): ", "Could not read the Defender exclusions (another antivirus?): ") + ex.Message); }
            AuditRatApps(list, RegistryHive.LocalMachine, RegistryView.Registry64, "system");
            AuditRatApps(list, RegistryHive.LocalMachine, RegistryView.Registry32, "system");
            ct.ThrowIfCancellationRequested();
            AuditWinlogon(list);
            return list;
        }

        private static void AuditShortcuts(List<AutostartItem> list, string scope, IEnumerable<string> dirs)
        {
            foreach (var dir in dirs.Where(d => !string.IsNullOrEmpty(d) && Directory.Exists(d)).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                IEnumerable<string> lnks;
                try { lnks = Directory.EnumerateFiles(dir, "*.lnk", SearchOption.AllDirectories).ToList(); } catch { continue; }
                foreach (var lnk in lnks)
                {
                    var (target, args) = Shortcut.Read(lnk);
                    if (target == null || !BrowserExes.Contains(Path.GetFileName(target), StringComparer.OrdinalIgnoreCase)) continue;
                    var m = BadFlags.Match(args ?? "");
                    if (!m.Success) continue;
                    var it = Item("Shortcut", scope, L("바로가기가 브라우저를 원격 조종·확장 강제 설치 모드로 켬", "Shortcut starts the browser in remote-control / forced-extension mode"),
                        Path.GetFileName(lnk), $"{lnk}  [{m.Value}]");
                    it.Item = lnk; it.Id = MakeId("Shortcut", lnk, m.Value);
                    list.Add(it);
                }
            }
        }

        private static void AuditPolicies(List<AutostartItem> list, RegistryHive hive, string scope)
        {
            foreach (var br in PolicyBrowsers)
            {
                var sub = $@"SOFTWARE\Policies\{br}\ExtensionInstallForcelist";
                try
                {
                    using (var b = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64))
                    using (var k = b.OpenSubKey(sub))
                    {
                        if (k == null) continue;
                        foreach (var name in k.GetValueNames())
                        {
                            var val = k.GetValue(name) as string ?? "";
                            var it = Item("RegValue", scope, L("브라우저에 강제로 설치되는 확장 프로그램 (회사 PC가 아니면 의심)", "Browser extension force-installed by policy (suspicious unless this is a work PC)"),
                                $"{br} #{name}", $"{(hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM")}\\{sub} : {val}");
                            it.Hive = hive; it.View = RegistryView.Registry64; it.Key = sub; it.Value = name;
                            it.Id = MakeId("Policy", hive.ToString(), sub, name, val);
                            list.Add(it);
                        }
                    }
                }
                catch { }
            }
        }

        private static void AuditExclusions(List<AutostartItem> list)
        {
            using (var s = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpPreference"))
                foreach (ManagementObject o in s.Get())
                    foreach (var lt in new[] { "Path", "Process", "Extension" })
                    {
                        if (!(o["Exclusion" + lt] is string[] values)) continue;
                        foreach (var xs in values.Where(v => !string.IsNullOrEmpty(v) && !v.StartsWith("N/A")))
                        {
                            bool risky = Regex.IsMatch(xs, @"^[A-Za-z]:\\?$") ||
                                         Regex.IsMatch(xs, @"\\(AppData|Temp|Downloads|Desktop|Public|ProgramData|NIKKE)(\\|$)", RegexOptions.IgnoreCase) ||
                                         Regex.IsMatch(xs, @"^\.?(exe|dll|lua|ps1|bat|cmd|vbs|js|scr)$", RegexOptions.IgnoreCase) ||
                                         Regex.IsMatch(xs, @"(^|\\)(powershell|pwsh|cmd|wscript|cscript|rundll32|regsvr32|mshta)\.exe$", RegexOptions.IgnoreCase);
                            if (!risky) continue;
                            var it = Item("Exclusion", "system", L("Windows Defender 검사에서 빠진 곳 (직접 넣은 게 아니면 해커가 숨으려고 넣었을 수 있음)", "Excluded from Windows Defender scans (if you did not add it, a hacker may be hiding there)"),
                                $"Exclusion{lt}", xs);
                            it.ExclList = lt; it.SetValue = xs; it.Id = MakeId("Exclusion", lt, xs);
                            list.Add(it);
                        }
                    }
        }

        private static void AuditRatApps(List<AutostartItem> list, RegistryHive hive, RegistryView view, string scope)
        {
            var since = Autostart.Since.ToString("yyyyMMdd");
            try
            {
                using (var b = RegistryKey.OpenBaseKey(hive, view))
                using (var root = b.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall"))
                {
                    if (root == null) return;
                    foreach (var sub in root.GetSubKeyNames())
                        using (var k = root.OpenSubKey(sub))
                        {
                            var name = k?.GetValue("DisplayName") as string ?? "";
                            var date = k?.GetValue("InstallDate") as string ?? "";
                            if (!RatName.IsMatch(name) || !Regex.IsMatch(date, @"^\d{8}$") || string.CompareOrdinal(date, since) < 0) continue;
                            var it = Item("RatApp", scope, L("9/27 이후 설치된 원격 접속 프로그램 (직접 깐 게 아니면 해커가 조종하려고 깐 것일 수 있음)", "Remote-access app installed since Sep 27 (if you did not install it, a hacker may use it)"),
                                name, $"{name} ({date})");
                            it.UninstallCmd = (k.GetValue("QuietUninstallString") as string) ?? (k.GetValue("UninstallString") as string);
                            it.Machine = hive == RegistryHive.LocalMachine;
                            it.Id = MakeId("RatApp", hive.ToString(), view.ToString(), sub);
                            if (!list.Any(x => x.Id == it.Id)) list.Add(it);
                        }
                }
            }
            catch { }
        }

        private static void AuditWinlogon(List<AutostartItem> list)
        {
            var win = Paths.Windows;
            using (var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            {
                try
                {
                    using (var k = b.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"))
                    {
                        var shell = (k?.GetValue("Shell") as string ?? "").Trim();
                        if (shell.Length > 0 && !shell.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
                        {
                            var it = Item("RegSet", "system", L("Windows 시작 프로그램(Shell)이 바뀌어 있음", "Windows startup shell was changed"), "Shell", "Winlogon Shell = " + shell, Autostart.RunTarget(shell));
                            it.Hive = RegistryHive.LocalMachine; it.View = RegistryView.Registry64; it.Key = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; it.Value = "Shell"; it.SetValue = "explorer.exe";
                            it.Id = MakeId("Shell", shell); list.Add(it);
                        }
                        var ui = (k?.GetValue("Userinit") as string ?? "").Trim().TrimEnd(',').Trim();
                        if (ui.Length > 0 && !Regex.IsMatch(ui, "^((" + Regex.Escape(win) + @"|C:\\Windows)\\system32\\)?userinit\.exe$", RegexOptions.IgnoreCase))
                        {
                            var it = Item("RegSet", "system", L("Windows 로그인 때 실행되는 프로그램(Userinit)이 바뀌어 있음", "The program run at Windows sign-in (Userinit) was changed"), "Userinit", "Winlogon Userinit = " + ui);
                            it.Hive = RegistryHive.LocalMachine; it.View = RegistryView.Registry64; it.Key = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; it.Value = "Userinit"; it.SetValue = win + @"\system32\userinit.exe,";
                            it.Id = MakeId("Userinit", ui); list.Add(it);
                        }
                    }
                }
                catch { }
                try
                {
                    using (var root = b.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"))
                        if (root != null)
                            foreach (var sub in root.GetSubKeyNames())
                                using (var k = root.OpenSubKey(sub))
                                {
                                    var dbg = k?.GetValue("Debugger") as string;
                                    if (string.IsNullOrEmpty(dbg)) continue;
                                    var it = Item("RegValue", "system", L("프로그램을 켤 때 다른 프로그램이 대신 실행되게 바뀌어 있음 (IFEO)", "A program is set to launch something else instead (IFEO debugger)"), sub, $"{sub} -> {dbg}", Autostart.RunTarget(dbg));
                                    it.Hive = RegistryHive.LocalMachine; it.View = RegistryView.Registry64;
                                    it.Key = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\" + sub; it.Value = "Debugger";
                                    it.Id = MakeId("IFEO", sub, dbg); list.Add(it);
                                }
                }
                catch { }
                try
                {
                    using (var k = b.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"))
                    {
                        var dlls = k?.GetValue("AppInit_DLLs") as string;
                        if (Convert.ToInt32(k?.GetValue("LoadAppInit_DLLs") ?? 0) == 1 && !string.IsNullOrWhiteSpace(dlls))
                        {
                            var it = Item("AppInit", "system", L("모든 프로그램에 끼어드는 DLL 설정 (AppInit_DLLs)", "A DLL is injected into every program (AppInit_DLLs)"), "AppInit_DLLs", "AppInit_DLLs = " + dlls, Autostart.RunTarget(dlls));
                            it.Hive = RegistryHive.LocalMachine; it.View = RegistryView.Registry64; it.Key = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
                            it.Id = MakeId("AppInit", dlls); list.Add(it);
                        }
                    }
                }
                catch { }
            }
        }

        // ------------------------------------------------------------------
        // 정리
        // ------------------------------------------------------------------
        public static bool Remove(AutostartItem it, Logger log)
        {
            try
            {
                switch (it.Kind)
                {
                    case "BrowserProc":
                        using (var p = Process.GetProcessById(it.Pid))
                            if (p.ProcessName.Equals(it.ProcName, StringComparison.OrdinalIgnoreCase)) { p.Kill(); p.WaitForExit(5000); }
                        log(L($"[+] 원격 조종 모드로 켜진 브라우저를 껐습니다 (다시 켜면 보통 모드): {it.Display}", $"[+] Closed the browser running in remote-control mode (reopen it normally): {it.Display}"), LogLevel.Action);
                        return true;
                    case "Shortcut":
                        Shortcut.StripArgs(it.Item, StripFlags);
                        log(L($"[+] 바로가기에서 원격 조종·확장 강제 설치 옵션만 지웠습니다 (바로가기는 그대로): {it.Item}", $"[+] Removed only the remote-control / forced-extension options (shortcut kept): {it.Item}"), LogLevel.Action);
                        return true;
                    case "RegValue":
                        using (var b = RegistryKey.OpenBaseKey(it.Hive, it.View))
                        using (var k = b.OpenSubKey(it.Key, true)) k?.DeleteValue(it.Value, false);
                        log(L($"[+] 설정을 지웠습니다: {it.Display}", $"[+] Removed the setting: {it.Display}"), LogLevel.Action);
                        return true;
                    case "RegSet":
                        using (var b = RegistryKey.OpenBaseKey(it.Hive, it.View))
                        using (var k = b.OpenSubKey(it.Key, true)) k?.SetValue(it.Value, it.SetValue, RegistryValueKind.String);
                        log(L($"[+] Windows 기본값으로 되돌렸습니다: {it.Value} = {it.SetValue}", $"[+] Restored the Windows default: {it.Value} = {it.SetValue}"), LogLevel.Action);
                        return true;
                    case "Proxy":
                        using (var b = RegistryKey.OpenBaseKey(it.Hive, it.View))
                        using (var k = b.OpenSubKey(it.Key, true)) k?.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                        log(L($"[+] 프록시를 껐습니다: {it.Display}", $"[+] Turned off the proxy: {it.Display}"), LogLevel.Action);
                        return true;
                    case "AppInit":
                        using (var b = RegistryKey.OpenBaseKey(it.Hive, it.View))
                        using (var k = b.OpenSubKey(it.Key, true))
                        {
                            k?.SetValue("AppInit_DLLs", "", RegistryValueKind.String);
                            k?.SetValue("LoadAppInit_DLLs", 0, RegistryValueKind.DWord);
                        }
                        log(L("[+] 모든 프로그램에 끼어드는 DLL 설정을 껐습니다", "[+] Turned off the DLL injected into every program"), LogLevel.Action);
                        return true;
                    case "Exclusion":
                        using (var cls = new ManagementClass(@"root\Microsoft\Windows\Defender", "MSFT_MpPreference", null))
                        {
                            var inParams = cls.GetMethodParameters("Remove");
                            inParams["Exclusion" + it.ExclList] = new[] { it.SetValue };
                            cls.InvokeMethod("Remove", inParams, null);
                        }
                        log(L($"[+] Windows Defender 검사 제외에서 뺐습니다 (이제 검사됨): {it.SetValue}", $"[+] Removed from the Windows Defender exclusions (scanned again): {it.SetValue}"), LogLevel.Action);
                        return true;
                    case "RatProc":
                        try { using (var p = Process.GetProcessById(it.Pid)) if (p.ProcessName.Equals(it.ProcName, StringComparison.OrdinalIgnoreCase)) p.Kill(); } catch { }
                        if (it.File != null && System.IO.File.Exists(it.File) && !Paths.IsProtected(it.File))
                        {
                            if (!Remediator.DeleteFile(it.File, log)) return false;
                            log(L($"[+] 원격 접속 프로그램을 끄고, 설치 없이 실행되던 파일을 지웠습니다: {it.Name}", $"[+] Closed the remote-access app and deleted its file: {it.Name}"), LogLevel.Action);
                        }
                        else log(L($"[+] 원격 접속 프로그램을 껐습니다. 설치된 것이면 「설정 → 앱」에서 지워 주세요: {it.Name}", $"[+] Closed the remote-access app. If it is installed, remove it in Settings -> Apps: {it.Name}"), LogLevel.Action);
                        return true;
                    case "RatApp":
                        foreach (var n in RatProcs) foreach (var p in Process.GetProcessesByName(n)) using (p) try { p.Kill(); } catch { }
                        if (StartUninstaller(it))
                            log(L($"[+] 제거 프로그램을 띄웠습니다. 창이 뜨면 「제거」를 눌러 주세요: {it.Name}", $"[+] Opened its uninstaller. Click Uninstall in its window: {it.Name}"), LogLevel.Action);
                        else
                            log(L($"[!] 프로그램을 껐습니다. 「설정 → 앱」에서 {it.Name} 을(를) 찾아 제거해 주세요", $"[!] Closed it. Remove {it.Name} in Settings -> Apps"), LogLevel.Warn);
                        return true;
                }
            }
            catch (Exception ex)
            {
                log(L($"[X] 정리하지 못했습니다: {it.Display} ({ex.Message})", $"[X] Could not fix: {it.Display} ({ex.Message})"), LogLevel.Bad);
                return false;
            }
            return true;
        }

        /// <summary>PC 전체(HKLM) 등록의 공식 제거 프로그램만 띄운다. 사용자 영역 등록의 제거 명령은 해커가 바꿔 넣을 수 있어 실행하지 않는다.</summary>
        private static bool StartUninstaller(AutostartItem it)
        {
            var us = it.UninstallCmd ?? "";
            if (!it.Machine || us.Length == 0) return false;
            var msi = Regex.Match(us, @"^\s*""?MsiExec(\.exe)?""?\s+/[IX]\s*(\{[0-9A-Fa-f-]{36}\})", RegexOptions.IgnoreCase);
            if (msi.Success) { Process.Start(new ProcessStartInfo(Paths.Sys("msiexec.exe"), "/x " + msi.Groups[2].Value) { UseShellExecute = false }); return true; }
            var m = Regex.Match(us, @"^\s*""([^""]+)""\s*(.*)$");
            if (!m.Success) m = Regex.Match(us, @"^\s*(\S+\.exe)\s*(.*)$", RegexOptions.IgnoreCase);
            if (!m.Success) return false;
            var exe = m.Groups[1].Value;
            if (!System.IO.File.Exists(exe) || Paths.IsInside(exe, Paths.Windows) || !Paths.ProgramFilesDirs.Any(r => Paths.IsInside(exe, r))) return false;
            Process.Start(new ProcessStartInfo(exe, m.Groups[2].Value) { UseShellExecute = false });
            return true;
        }

        private static string RunCapture(string exe, string args)
        {
            try
            {
                var psi = new ProcessStartInfo(exe, args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                using (var p = Process.Start(psi))
                {
                    var o = p.StandardOutput.ReadToEnd(); p.StandardError.ReadToEnd();
                    p.WaitForExit(30000);
                    return o;
                }
            }
            catch { return null; }
        }
    }

    /// <summary>바로가기(.lnk) 읽기·인자 고치기 (WScript.Shell).</summary>
    public static class Shortcut
    {
        private static object Shell() => Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell", true));

        public static (string Target, string Args) Read(string lnk)
        {
            try
            {
                var sh = Shell();
                var sc = sh.GetType().InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, sh, new object[] { lnk });
                var target = sc.GetType().InvokeMember("TargetPath", BindingFlags.GetProperty, null, sc, null) as string;
                var args = sc.GetType().InvokeMember("Arguments", BindingFlags.GetProperty, null, sc, null) as string;
                return (string.IsNullOrEmpty(target) ? null : target, args ?? "");
            }
            catch { return (null, null); }
        }

        public static void StripArgs(string lnk, Regex strip)
        {
            var sh = Shell();
            var sc = sh.GetType().InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, sh, new object[] { lnk });
            var args = sc.GetType().InvokeMember("Arguments", BindingFlags.GetProperty, null, sc, null) as string ?? "";
            sc.GetType().InvokeMember("Arguments", BindingFlags.SetProperty, null, sc, new object[] { strip.Replace(args, "").Trim() });
            sc.GetType().InvokeMember("Save", BindingFlags.InvokeMethod, null, sc, null);
        }
    }
}
