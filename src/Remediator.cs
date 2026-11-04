using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;

namespace NikkeChecker
{
    public static class Remediator
    {
        /// <summary>발견 항목 치료. 일반 사용자 권한으로 현재 사용자 영역(HKCU / AppData)만 수정한다.</summary>
        public static int Fix(IList<Finding> findings, Logger log)
        {
            int failed = 0;

            // 1. 레지스트리 (먼저 끊어 두어야 브라우저가 DLL 을 다시 로드하지 않음)
            foreach (var f in findings.Where(f => f.Fix == FixKind.DeleteRegistryKey).GroupBy(f => f.Target).Select(g => g.First()))
            {
                try
                {
                    Registry.CurrentUser.DeleteSubKeyTree(f.Target, false);
                    if (Registry.CurrentUser.OpenSubKey(f.Target) == null) log($"[+] 레지스트리 키 삭제 완료: HKCU\\{f.Target}", LogLevel.Action);
                    else { failed++; log($"[X] 레지스트리 키 삭제 실패: HKCU\\{f.Target}", LogLevel.Bad); }
                }
                catch (Exception ex) { failed++; log($"[X] 레지스트리 키 삭제 실패: HKCU\\{f.Target} ({ex.Message})", LogLevel.Bad); }
            }

            // 2. 브라우저 DLL 폴더 (DLL 이 로드돼 있을 수 있으므로 해당 브라우저 종료 후 삭제)
            var dllFindings = findings.Where(f => f.Fix == FixKind.DeleteDirectory).ToList();
            if (dllFindings.Count > 0)
            {
                KillProcesses(dllFindings.Select(f => f.Browser).Distinct(), log);
                foreach (var f in dllFindings) failed += DeleteDir(f.Target, "악성 64자리 폴더", log) ? 0 : 1;
            }

            // 3. 런처 tbs_cache (Local Storage 의 k2f.agent, 악성 로더 캐시 동시 제거)
            var tbs = findings.Where(f => f.Fix == FixKind.DeleteTbsCache).Select(f => f.Target).Distinct().ToList();
            if (tbs.Count > 0)
            {
                KillProcesses(Iocs.LauncherProcesses, log);
                foreach (var d in tbs) failed += DeleteDir(d, "런처 캐시(tbs_cache)", log) ? 0 : 1;
            }

            return failed;
        }

        public static void ClearBrowserCookies(Logger log)
        {
            log("[*] 브라우저 종료 후 쿠키 DB 를 삭제합니다 (모든 사이트에서 로그아웃됩니다)", LogLevel.Info);
            var procs = Iocs.Browsers.Select(b => b.Process).Concat(new[] { "firefox" }).Distinct();
            KillProcesses(procs, log);
            Thread.Sleep(1000);

            foreach (var b in Iocs.Browsers)
            {
                if (!Directory.Exists(b.Path)) continue;
                int n = 0;
                foreach (var f in Scanner.SafeFiles(b.Path, true))
                {
                    var name = Path.GetFileName(f);
                    if (!name.Equals("Cookies", StringComparison.OrdinalIgnoreCase) &&
                        !name.Equals("Cookies-journal", StringComparison.OrdinalIgnoreCase)) continue;
                    if (TryDeleteFile(f)) n++;
                    else log($"  [X] 삭제 실패: {f}", LogLevel.Bad);
                }
                log($"[+] [{b.Name}] 쿠키 DB {n}개 삭제", LogLevel.Action);
            }

            var ff = Path.Combine(Iocs.AppData, @"Mozilla\Firefox\Profiles");
            if (Directory.Exists(ff))
            {
                int n = Scanner.SafeFiles(ff, true).Where(f => Path.GetFileName(f).StartsWith("cookies.sqlite", StringComparison.OrdinalIgnoreCase))
                    .Count(TryDeleteFile);
                log($"[+] [Firefox] 쿠키 DB {n}개 삭제", LogLevel.Action);
            }
        }

        private static bool TryDeleteFile(string f)
        {
            try { File.SetAttributes(f, FileAttributes.Normal); File.Delete(f); return !File.Exists(f); } catch { return false; }
        }

        private static bool DeleteDir(string dir, string label, Logger log)
        {
            if (!Directory.Exists(dir)) { log($"[-] 이미 없음: {dir}", LogLevel.Detail); return true; }
            for (int attempt = 0; attempt < 3; attempt++)
            {
                try
                {
                    foreach (var f in Scanner.SafeFiles(dir, true))
                        try { File.SetAttributes(f, FileAttributes.Normal); } catch { }
                    Directory.Delete(dir, true);
                }
                catch { Thread.Sleep(800); }
                if (!Directory.Exists(dir)) { log($"[+] {label} 삭제 완료: {dir}", LogLevel.Action); return true; }
            }
            log($"[X] {label} 삭제 실패: {dir}", LogLevel.Bad);
            log("    → 관련 프로그램을 모두 종료하거나 PC 재부팅 후 다시 시도해 주세요.", LogLevel.Warn);
            return false;
        }

        private static void KillProcesses(IEnumerable<string> names, Logger log)
        {
            foreach (var name in names)
            {
                foreach (var p in Process.GetProcessesByName(name))
                {
                    try
                    {
                        int pid = p.Id;
                        p.Kill();
                        p.WaitForExit(5000);
                        log($"[+] 프로세스 종료: {name} (PID {pid})", LogLevel.Action);
                    }
                    catch (Exception ex) { log($"[X] 프로세스 종료 실패: {name} ({ex.Message})", LogLevel.Bad); }
                    finally { p.Dispose(); }
                }
            }
        }

        // ------------------------------------------------------------------
        // hosts / 방화벽 차단 (관리자 권한 필요)
        // ------------------------------------------------------------------
        public static bool IsAdmin()
        {
            using (var id = WindowsIdentity.GetCurrent())
                return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }

        /// <summary>관리자 권한이면 직접, 아니면 자신을 UAC 승격 실행하여 차단을 적용한다.</summary>
        public static void ApplyBlockElevated(Logger log)
        {
            if (IsAdmin()) { ApplyBlock(log); return; }

            var logFile = Path.Combine(Path.GetTempPath(), $"NikkeChecker_block_{Guid.NewGuid():N}.log");
            var psi = new ProcessStartInfo(System.Windows.Forms.Application.ExecutablePath, $"--apply-block \"{logFile}\"")
            {
                UseShellExecute = true,
                Verb = "runas",
            };
            try
            {
                log("[*] hosts·방화벽 차단을 위해 관리자 권한을 요청합니다 (UAC 창 확인)", LogLevel.Info);
                using (var p = Process.Start(psi))
                {
                    p.WaitForExit();
                }
                if (File.Exists(logFile))
                {
                    foreach (var line in File.ReadAllLines(logFile, Encoding.UTF8))
                    {
                        int tab = line.IndexOf('\t');
                        var lvl = tab > 0 && Enum.TryParse(line.Substring(0, tab), out LogLevel l) ? l : LogLevel.Info;
                        log(tab > 0 ? line.Substring(tab + 1) : line, lvl);
                    }
                    File.Delete(logFile);
                }
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
            {
                log("[!] 관리자 권한 요청이 취소되어 hosts·방화벽 차단을 건너뛰었습니다.", LogLevel.Warn);
            }
            catch (Exception ex) { log($"[X] 차단 작업 실행 실패: {ex.Message}", LogLevel.Bad); }
        }

        /// <summary>--apply-block 모드 진입점 (승격된 프로세스).</summary>
        public static int RunBlockMode(string logFile)
        {
            var sb = new StringBuilder();
            ApplyBlock((m, l) => sb.AppendLine(l + "\t" + m));
            try { File.WriteAllText(logFile, sb.ToString(), Encoding.UTF8); } catch { return 2; }
            return 0;
        }

        public static void ApplyBlock(Logger log)
        {
            // hosts
            var hosts = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
            try
            {
                var text = File.Exists(hosts) ? File.ReadAllText(hosts) : "";
                var toAdd = Iocs.BlockDomains.Where(d => !HostsHas(text, d)).ToList();
                if (toAdd.Count == 0) log("[-] hosts 파일에 차단 도메인이 이미 등록되어 있습니다", LogLevel.Detail);
                else
                {
                    var attr = File.Exists(hosts) ? File.GetAttributes(hosts) : FileAttributes.Normal;
                    if ((attr & FileAttributes.ReadOnly) != 0) File.SetAttributes(hosts, attr & ~FileAttributes.ReadOnly);
                    var sb = new StringBuilder();
                    if (text.Length > 0 && !text.EndsWith("\n")) sb.Append("\r\n");
                    sb.Append("# NIKKE launcher malware C2 block\r\n");
                    foreach (var d in toAdd) sb.Append($"0.0.0.0        {d}\r\n");
                    File.AppendAllText(hosts, sb.ToString(), new UTF8Encoding(false));
                    if ((attr & FileAttributes.ReadOnly) != 0) File.SetAttributes(hosts, attr);
                    foreach (var d in toAdd) log($"[+] hosts 도메인 차단 등록: 0.0.0.0 {d}", LogLevel.Action);
                }
                Run("ipconfig", "/flushdns");
            }
            catch (Exception ex)
            {
                log($"[X] hosts 파일 수정 실패: {ex.Message}", LogLevel.Bad);
                log("    → 백신이 hosts 파일 변경을 막았을 수 있습니다. 백신 알림을 확인해 주세요.", LogLevel.Warn);
            }

            // 방화벽 (hosts 파일은 IP 를 차단할 수 없으므로 C2 IP 는 방화벽으로 차단)
            try
            {
                if (Run("netsh", $"advfirewall firewall show rule name=\"{Iocs.FirewallRuleName}\"") == 0)
                    log($"[-] 방화벽 C2 IP 차단 규칙이 이미 있습니다 ({Iocs.C2Ip})", LogLevel.Detail);
                else if (Run("netsh", $"advfirewall firewall add rule name=\"{Iocs.FirewallRuleName}\" dir=out action=block remoteip={Iocs.C2Ip} enable=yes profile=any") == 0)
                    log($"[+] Windows 방화벽 C2 IP 차단 등록: {Iocs.C2Ip}", LogLevel.Action);
                else
                    log("[X] 방화벽 규칙 등록 실패 (Windows 방화벽 서비스 상태를 확인해 주세요)", LogLevel.Bad);
            }
            catch (Exception ex) { log($"[X] 방화벽 규칙 등록 실패: {ex.Message}", LogLevel.Bad); }
        }

        private static bool HostsHas(string hosts, string domain)
        {
            foreach (var raw in hosts.Split('\n'))
            {
                var line = raw;
                int hash = line.IndexOf('#');
                if (hash >= 0) line = line.Substring(0, hash);
                var parts = line.Trim().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2 && parts.Skip(1).Any(p => p.Equals(domain, StringComparison.OrdinalIgnoreCase))) return true;
            }
            return false;
        }

        private static int Run(string exe, string args)
        {
            var psi = new ProcessStartInfo(exe, args)
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            using (var p = Process.Start(psi))
            {
                p.StandardOutput.ReadToEnd();
                p.StandardError.ReadToEnd();
                p.WaitForExit(30000);
                return p.ExitCode;
            }
        }
    }
}
