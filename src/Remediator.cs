using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace NikkeChecker
{
    public sealed class FixOptions
    {
        public bool DeleteFindings;
        public bool AlwaysDeleteTbsCache;
        public bool Block;
    }

    public sealed class FixOutcome
    {
        public int Failed;
        public bool NeedsReboot;
    }

    /// <summary>
    /// 조치 순서 (참조: MotherSphere/NIKKE-Launcher-Check what-to-do)
    /// 런처 종료 → 레지스트리 키 삭제 → DLL 로드 프로세스 종료 → DLL 폴더/파일 삭제 → 런처 캐시 → Temp/에이전트 파일
    /// → (관리자) Program Files 구버전 파일 + hosts/방화벽.  DLL 이 잠겨 있으면 재부팅 후 다시 실행.
    /// </summary>
    public static class Remediator
    {
        public static FixOutcome Fix(IList<Finding> findings, FixOptions opt, Logger log)
        {
            var o = new FixOutcome();
            var fixes = opt.DeleteFindings ? findings.Where(f => f.Fix != FixKind.None && f.Severity != Severity.Info).ToList() : new List<Finding>();

            // 1. 런처 종료
            var tbsDirs = fixes.Where(f => f.Fix == FixKind.DeleteTbsCache).Select(f => f.Target).ToList();
            if (opt.AlwaysDeleteTbsCache)
                tbsDirs.AddRange(Iocs.LauncherDataDirs.Select(d => Path.Combine(d, "tbs_cache")).Where(Directory.Exists));
            tbsDirs = tbsDirs.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (tbsDirs.Count > 0 || fixes.Any(f => f.Fix == FixKind.KillProcess || f.Check == CheckId.InstallLogs))
                KillByName(Iocs.LauncherProcesses, log);

            // 2. 레지스트리 키 (먼저 끊어야 브라우저가 DLL 을 다시 로드하지 않음)
            foreach (var key in fixes.Where(f => f.Fix == FixKind.DeleteRegistryKey).Select(f => f.Target).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                try
                {
                    using (var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64))
                    {
                        hkcu.DeleteSubKeyTree(key, false);
                        using (var k = hkcu.OpenSubKey(key))
                        {
                            if (k == null) log($"[+] 레지스트리 키 삭제: HKCU\\{key}", LogLevel.Action);
                            else { o.Failed++; log($"[X] 레지스트리 키 삭제 실패: HKCU\\{key}", LogLevel.Bad); }
                        }
                    }
                }
                catch (Exception ex) { o.Failed++; log($"[X] 레지스트리 키 삭제 실패: HKCU\\{key} ({ex.Message})", LogLevel.Bad); }
            }

            // 3. DLL 을 로드한 프로세스 + 해당 브라우저 종료
            foreach (var f in fixes.Where(f => f.Fix == FixKind.KillProcess))
                KillPid(f.Pid, f.Target, log);
            var browsers = fixes.Where(f => (f.Fix == FixKind.DeleteDirectory || f.Fix == FixKind.DeleteFile) && f.Browser != null)
                                .Select(f => f.Browser).Distinct().ToList();
            if (browsers.Count > 0) KillByName(browsers, log);

            // 4. DLL 폴더 / 파일
            foreach (var f in fixes.Where(f => f.Fix == FixKind.DeleteDirectory))
                if (!DeleteDir(f.Target, "악성 64자리 폴더", log)) { o.Failed++; o.NeedsReboot = true; }
            foreach (var f in fixes.Where(f => f.Fix == FixKind.DeleteFile).GroupBy(f => f.Target, StringComparer.OrdinalIgnoreCase).Select(g => g.First()))
            {
                if (DeleteFile(f.Target, log)) continue;
                o.Failed++;
                if (f.Check == CheckId.BrowserDll) o.NeedsReboot = true;
            }

            // 5. 런처 캐시
            foreach (var d in tbsDirs)
                if (!DeleteDir(d, "런처 캐시(tbs_cache)", log)) o.Failed++;

            // 6. 관리자 작업
            var elevatedFiles = fixes.Where(f => f.Fix == FixKind.DeleteFileElevated).Select(f => f.Target).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (elevatedFiles.Count > 0 || opt.Block)
            {
                if (elevatedFiles.Count > 0) KillByName(new[] { "chrome" }, log);
                o.Failed += RunElevated(elevatedFiles, opt.Block, log);
                if (elevatedFiles.Any(File.Exists)) o.NeedsReboot = true;
            }
            return o;
        }

        // ------------------------------------------------------------------
        private static bool DeleteFile(string f, Logger log)
        {
            if (!File.Exists(f)) { log($"[-] 이미 없음: {f}", LogLevel.Detail); return true; }
            for (int i = 0; i < 3; i++)
            {
                try { File.SetAttributes(f, FileAttributes.Normal); File.Delete(f); } catch { Thread.Sleep(600); }
                if (!File.Exists(f)) { log($"[+] 파일 삭제: {f}", LogLevel.Action); return true; }
            }
            log($"[X] 파일 삭제 실패 (사용 중): {f}", LogLevel.Bad);
            return false;
        }

        private static bool DeleteDir(string dir, string label, Logger log)
        {
            if (!Directory.Exists(dir)) { log($"[-] 이미 없음: {dir}", LogLevel.Detail); return true; }
            for (int i = 0; i < 3; i++)
            {
                try
                {
                    foreach (var f in FileUtil.Files(dir, 64)) try { File.SetAttributes(f, FileAttributes.Normal); } catch { }
                    Directory.Delete(dir, true);
                }
                catch { Thread.Sleep(800); }
                if (!Directory.Exists(dir)) { log($"[+] {label} 삭제: {dir}", LogLevel.Action); return true; }
            }
            log($"[X] {label} 삭제 실패 (사용 중): {dir}", LogLevel.Bad);
            return false;
        }

        private static void KillByName(IEnumerable<string> names, Logger log)
        {
            foreach (var name in names)
                foreach (var p in Process.GetProcessesByName(name))
                    using (p) Kill(p, log);
        }

        private static void KillPid(int pid, string expectedName, Logger log)
        {
            try
            {
                using (var p = Process.GetProcessById(pid))
                {
                    if (!p.ProcessName.Equals(expectedName, StringComparison.OrdinalIgnoreCase)) return; // PID 재사용 방지
                    if (p.ProcessName.Equals("explorer", StringComparison.OrdinalIgnoreCase)) return;
                    Kill(p, log);
                }
            }
            catch (ArgumentException) { /* 이미 종료됨 */ }
        }

        private static void Kill(Process p, Logger log)
        {
            try
            {
                int pid = p.Id; string name = p.ProcessName;
                p.Kill();
                p.WaitForExit(5000);
                log($"[+] 프로세스 종료: {name} (PID {pid})", LogLevel.Action);
            }
            catch (Exception ex) { log($"[X] 프로세스 종료 실패: {p.ProcessName} ({ex.Message})", LogLevel.Bad); }
        }

        // ------------------------------------------------------------------
        // 관리자 작업: 승격된 자기 자신(--elevated <요청파일> <로그파일>)에서 실행
        // ------------------------------------------------------------------
        public static bool IsAdmin()
        {
            using (var id = WindowsIdentity.GetCurrent())
                return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }

        private static int RunElevated(List<string> files, bool block, Logger log)
        {
            var req = new List<string>();
            if (block) req.Add("BLOCK");
            req.AddRange(files.Select(f => "DEL\t" + f));

            if (IsAdmin()) return ExecuteRequests(req, log);

            var tmp = Path.GetTempPath();
            var reqFile = Path.Combine(tmp, $"NikkeChecker_req_{Guid.NewGuid():N}.txt");
            var logFile = Path.Combine(tmp, $"NikkeChecker_log_{Guid.NewGuid():N}.txt");
            File.WriteAllLines(reqFile, req, Encoding.UTF8);
            try
            {
                log("[*] 관리자 권한이 필요한 작업을 위해 UAC 승인을 요청합니다", LogLevel.Info);
                var psi = new ProcessStartInfo(System.Windows.Forms.Application.ExecutablePath, $"--elevated \"{reqFile}\" \"{logFile}\"")
                { UseShellExecute = true, Verb = "runas" };
                int code;
                using (var p = Process.Start(psi)) { p.WaitForExit(); code = p.ExitCode; }
                if (File.Exists(logFile))
                {
                    foreach (var line in File.ReadAllLines(logFile, Encoding.UTF8))
                    {
                        int tab = line.IndexOf('\t');
                        var lvl = tab > 0 && Enum.TryParse(line.Substring(0, tab), out LogLevel l) ? l : LogLevel.Info;
                        log(tab > 0 ? line.Substring(tab + 1) : line, lvl);
                    }
                }
                return code;
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
            {
                log("[!] 관리자 권한 요청이 취소되어 관리자 작업(hosts·방화벽 차단, Program Files 파일 삭제)을 건너뛰었습니다.", LogLevel.Warn);
                return files.Count;
            }
            catch (Exception ex) { log($"[X] 관리자 작업 실행 실패: {ex.Message}", LogLevel.Bad); return 1; }
            finally
            {
                try { File.Delete(reqFile); } catch { }
                try { File.Delete(logFile); } catch { }
            }
        }

        /// <summary>--elevated 모드 진입점.</summary>
        public static int RunElevatedMode(string reqFile, string logFile)
        {
            var sb = new StringBuilder();
            int failed;
            try { failed = ExecuteRequests(File.ReadAllLines(reqFile, Encoding.UTF8), (m, l) => sb.AppendLine(l + "\t" + m)); }
            catch (Exception ex) { sb.AppendLine(LogLevel.Bad + "\t[X] 요청 처리 실패: " + ex.Message); failed = 1; }
            try { File.WriteAllText(logFile, sb.ToString(), Encoding.UTF8); } catch { }
            return failed;
        }

        private static int ExecuteRequests(IEnumerable<string> req, Logger log)
        {
            int failed = 0;
            foreach (var line in req)
            {
                if (line == "BLOCK") failed += ApplyBlock(log);
                else if (line.StartsWith("DEL\t"))
                {
                    var path = line.Substring(4);
                    // 요청 파일은 사용자 쓰기 가능 위치에 있으므로, 관리자 권한으로 지울 수 있는 대상을 엄격히 제한한다
                    if (!IsAllowedElevatedDelete(path)) { log($"[X] 허용되지 않은 삭제 요청 무시: {path}", LogLevel.Bad); failed++; continue; }
                    if (!DeleteFile(path, log)) failed++;
                }
            }
            return failed;
        }

        private static bool IsAllowedElevatedDelete(string path)
        {
            try
            {
                var full = Path.GetFullPath(path);
                if (!string.Equals(full, path, StringComparison.OrdinalIgnoreCase)) return false;
                var name = Path.GetFileName(full);
                var dir = Path.GetDirectoryName(full) ?? "";
                if (!Iocs.OldPersistenceFiles.Contains(name, StringComparer.OrdinalIgnoreCase)) return false;
                if (!dir.EndsWith("\\" + Iocs.OldPersistenceDir, StringComparison.OrdinalIgnoreCase)) return false;
                var roots = new[] { "ProgramW6432", "ProgramFiles", "ProgramFiles(x86)" }
                    .Select(Environment.GetEnvironmentVariable).Where(r => !string.IsNullOrEmpty(r));
                return roots.Any(r => string.Equals(dir, Path.Combine(r, Iocs.OldPersistenceDir), StringComparison.OrdinalIgnoreCase));
            }
            catch { return false; }
        }

        // ------------------------------------------------------------------
        public static int ApplyBlock(Logger log)
        {
            int failed = 0;
            var hosts = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
            try
            {
                var text = File.Exists(hosts) ? File.ReadAllText(hosts) : "";
                var toAdd = Iocs.BlockDomains.Where(d => !HostsFile.IsBlocked(text, d)).ToList();
                if (toAdd.Count == 0) log("[-] hosts: 세 도메인이 이미 차단되어 있습니다", LogLevel.Detail);
                else
                {
                    var attr = File.Exists(hosts) ? File.GetAttributes(hosts) : FileAttributes.Normal;
                    if ((attr & FileAttributes.ReadOnly) != 0) File.SetAttributes(hosts, attr & ~FileAttributes.ReadOnly);
                    var sb = new StringBuilder();
                    if (text.Length > 0 && !text.EndsWith("\n")) sb.Append("\r\n");
                    sb.Append("# NIKKE launcher malware block\r\n");
                    foreach (var d in toAdd) sb.Append($"0.0.0.0        {d}\r\n");
                    File.AppendAllText(hosts, sb.ToString(), new UTF8Encoding(false));
                    if ((attr & FileAttributes.ReadOnly) != 0) File.SetAttributes(hosts, attr);
                    foreach (var d in toAdd) log($"[+] hosts 차단 등록: 0.0.0.0 {d}", LogLevel.Action);
                }
                Run("ipconfig", "/flushdns");
            }
            catch (Exception ex)
            {
                failed++;
                log($"[X] hosts 파일 수정 실패: {ex.Message}", LogLevel.Bad);
                log("    → 백신이 hosts 변경을 막았을 수 있습니다. 백신 알림을 확인해 주세요.", LogLevel.Warn);
            }

            // hosts 는 IP 를 막을 수 없으므로 공격자 IP 는 방화벽으로 차단
            var ips = string.Join(",", Iocs.C2Ips);
            try
            {
                if (FirewallRuleExists(Iocs.FirewallRuleName))
                    log($"[-] 방화벽: 차단 규칙이 이미 있습니다 ({ips})", LogLevel.Detail);
                else if (Run("netsh", $"advfirewall firewall add rule name=\"{Iocs.FirewallRuleName}\" dir=out action=block remoteip={ips} enable=yes profile=any") == 0)
                    log($"[+] 방화벽 아웃바운드 차단 등록: {ips}", LogLevel.Action);
                else { failed++; log("[X] 방화벽 규칙 등록 실패 (Windows 방화벽 서비스 상태를 확인해 주세요)", LogLevel.Bad); }
            }
            catch (Exception ex) { failed++; log($"[X] 방화벽 규칙 등록 실패: {ex.Message}", LogLevel.Bad); }
            return failed;
        }

        public static bool FirewallRuleExists(string name)
        {
            try { return Run("netsh", $"advfirewall firewall show rule name=\"{name}\"") == 0; } catch { return false; }
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
