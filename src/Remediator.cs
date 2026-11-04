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
using static NikkeChecker.I18n;

namespace NikkeChecker
{
    public sealed class FixOptions
    {
        public bool DeleteFindings;
        public bool AlwaysDeleteTbsCache;
        public bool Block;
        public List<AutostartItem> RemoveAutostart = new List<AutostartItem>();   // 사용자가 고른 「확인 필요」 항목
    }

    public sealed class FixOutcome
    {
        public int Failed;
        public bool NeedsReboot;
    }

    /// <summary>
    /// 조치 순서 (참조: MotherSphere/NIKKE-Launcher-Check what-to-do, 햄찌 NIKKE_k2f_cleaner)
    /// 런처 종료 → 레지스트리 키 삭제 → DLL 로드 프로세스 종료 → DLL 폴더/파일 삭제 → 런처 캐시 → Temp/에이전트 파일
    /// → 고른 자동 실행 항목 → (관리자) Program Files 구버전 파일, PC 전체 자동 실행 항목, hosts/방화벽.
    /// DLL 이 잠겨 있으면 재부팅 후 다시 실행.
    /// </summary>
    public static class Remediator
    {
        public static FixOutcome Fix(IList<Finding> findings, FixOptions opt, Logger log)
        {
            var o = new FixOutcome();
            var fixes = opt.DeleteFindings ? findings.Where(f => f.Fix != FixKind.None && (f.Severity == Severity.Warning || f.Severity == Severity.Critical)).ToList() : new List<Finding>();

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
                            if (k == null) log(L($"[+] 레지스트리 키 삭제: HKCU\\{key}", $"[+] Deleted registry key: HKCU\\{key}"), LogLevel.Action);
                            else { o.Failed++; log(L($"[X] 레지스트리 키 삭제 실패: HKCU\\{key}", $"[X] Could not delete registry key: HKCU\\{key}"), LogLevel.Bad); }
                        }
                    }
                }
                catch (Exception ex) { o.Failed++; log(L($"[X] 레지스트리 키 삭제 실패: HKCU\\{key} ({ex.Message})", $"[X] Could not delete registry key: HKCU\\{key} ({ex.Message})"), LogLevel.Bad); }
            }

            // 3. DLL 을 로드한 프로세스 + 해당 브라우저 종료
            foreach (var f in fixes.Where(f => f.Fix == FixKind.KillProcess))
                KillPid(f.Pid, f.Target, log);
            foreach (var b in fixes.Where(f => (f.Fix == FixKind.DeleteDirectory || f.Fix == FixKind.DeleteFile) && f.Browser != null)
                                   .Select(f => (f.Browser, f.BrowserHint)).Distinct())
                KillBrowser(b.Browser, b.BrowserHint, log);

            // 4. DLL 폴더 / 파일
            foreach (var f in fixes.Where(f => f.Fix == FixKind.DeleteDirectory))
                if (!DeleteDir(f.Target, L("악성 64자리 폴더", "malicious 64-character folder"), log)) { o.Failed++; o.NeedsReboot = true; }
            foreach (var f in fixes.Where(f => f.Fix == FixKind.DeleteFile).GroupBy(f => f.Target, StringComparer.OrdinalIgnoreCase).Select(g => g.First()))
            {
                if (DeleteFile(f.Target, log)) continue;
                o.Failed++;
                if (f.Check == CheckId.BrowserDll) o.NeedsReboot = true;
            }

            // 5. 런처 캐시 (흔적이 있던 런처 로그인 브라우저 프로필(CEF)도 같은 방식으로)
            foreach (var d in tbsDirs)
                if (!DeleteDir(d, L("런처 캐시", "launcher cache"), log)) o.Failed++;

            // 5-1. 해커 주소 DNS 기록
            if (fixes.Any(f => f.Fix == FixKind.FlushDns))
            {
                RunQuiet(Paths.Sys("ipconfig.exe"), "/flushdns");
                log(L("[+] 해커 주소 DNS 기록을 지웠습니다 (DNS 캐시 비움)", "[+] Cleared the DNS records of hacker addresses (DNS cache flushed)"), LogLevel.Action);
            }

            // 6. 사용자가 고른 자동 실행 항목 — 현재 사용자 범위는 여기서, PC 전체 범위는 관리자 프로세스에서.
            //    어느 쪽이든 다시 찾아본 뒤 같은 Id 인 항목만 지운다.
            var userIds = new HashSet<string>(opt.RemoveAutostart.Where(a => a.Scope == "user").Select(a => a.Id));
            if (userIds.Count > 0)
            {
                foreach (var it in Autostart.AuditUser(CancellationToken.None).Concat(Extra.AuditUser(CancellationToken.None)).Where(a => userIds.Contains(a.Id)))
                    if (!Autostart.Remove(it, log)) { o.Failed++; o.NeedsReboot = true; }
            }
            var sysIds = opt.RemoveAutostart.Where(a => a.Scope == "system").Select(a => a.Id).Distinct().ToList();

            // 7. 관리자 작업
            var elevatedFiles = fixes.Where(f => f.Fix == FixKind.DeleteFileElevated).Select(f => f.Target).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var req = new List<string>();
            req.AddRange(elevatedFiles.Select(f => "DEL\t" + f));
            req.AddRange(sysIds.Select(id => "RMAUTO\t" + id));
            if (opt.Block) req.Add("BLOCK");
            if (req.Count > 0)
            {
                if (elevatedFiles.Count > 0) KillByName(new[] { "chrome" }, log);
                var rc = RunElevated(req, log, out _);
                o.Failed += rc;
                if (elevatedFiles.Any(File.Exists)) o.NeedsReboot = true;
                if (rc > 0 && sysIds.Count > 0) o.NeedsReboot = true;
            }
            return o;
        }

        // ------------------------------------------------------------------
        /// <summary>상위 폴더 중 정션·심볼릭 링크가 있으면 엉뚱한 곳을 지울 수 있으므로 삭제를 거부한다.</summary>
        private static bool ParentIsLink(string path, Logger log)
        {
            try
            {
                var parent = Path.GetDirectoryName(path);
                while (!string.IsNullOrEmpty(parent) && Path.GetPathRoot(parent) != parent)
                {
                    if ((new DirectoryInfo(parent).Attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        log(L($"[!] 건너뜀 (상위 폴더가 연결 폴더라 직접 확인 필요: {parent}): {path}", $"[!] Skipped (a parent folder is a link, check it yourself: {parent}): {path}"), LogLevel.Warn);
                        return true;
                    }
                    parent = Path.GetDirectoryName(parent);
                }
                return false;
            }
            catch { log(L($"[!] 건너뜀 (상위 폴더 확인 실패): {path}", $"[!] Skipped (could not check the parent folder): {path}"), LogLevel.Warn); return true; }
        }

        internal static bool DeleteDirPublic(string dir, string label, Logger log) => DeleteDir(dir, label, log);

        internal static bool DeleteFile(string f, Logger log)
        {
            if (!File.Exists(f)) { log(L($"[-] 이미 없음: {f}", $"[-] Already gone: {f}"), LogLevel.Detail); return true; }
            if (ParentIsLink(f, log)) return false;
            for (int i = 0; i < 3; i++)
            {
                try { File.SetAttributes(f, FileAttributes.Normal); File.Delete(f); } catch { Thread.Sleep(600); }
                if (!File.Exists(f)) { log(L($"[+] 파일 삭제: {f}", $"[+] Deleted file: {f}"), LogLevel.Action); return true; }
            }
            log(L($"[X] 파일 삭제 실패 (사용 중): {f}", $"[X] Could not delete file (in use): {f}"), LogLevel.Bad);
            return false;
        }

        private static bool DeleteDir(string dir, string label, Logger log)
        {
            if (!Directory.Exists(dir)) { log(L($"[-] 이미 없음: {dir}", $"[-] Already gone: {dir}"), LogLevel.Detail); return true; }
            if (ParentIsLink(dir, log)) return false;
            for (int i = 0; i < 3; i++)
            {
                try
                {
                    foreach (var f in FileUtil.Files(dir, 64)) try { File.SetAttributes(f, FileAttributes.Normal); } catch { }
                    Directory.Delete(dir, true);
                }
                catch { Thread.Sleep(800); }
                if (!Directory.Exists(dir)) { log(L($"[+] {label} 삭제: {dir}", $"[+] Deleted {label}: {dir}"), LogLevel.Action); return true; }
            }
            log(L($"[X] {label} 삭제 실패 (사용 중): {dir}", $"[X] Could not delete {label} (in use): {dir}"), LogLevel.Bad);
            return false;
        }

        /// <summary>브라우저 종료. hint 가 있으면 실행 파일 경로에 hint 가 들어 있는 프로세스만 (browser.exe 같은 흔한 이름 대비).</summary>
        private static void KillBrowser(string name, string hint, Logger log)
        {
            foreach (var p in Process.GetProcessesByName(name))
            {
                using (p)
                {
                    if (hint != null)
                    {
                        string path = null;
                        try { path = p.MainModule?.FileName; } catch { }
                        if (path == null || path.IndexOf(hint, StringComparison.OrdinalIgnoreCase) < 0) continue;
                    }
                    Kill(p, log);
                }
            }
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
                log(L($"[+] 프로세스 종료: {name} (PID {pid})", $"[+] Ended process: {name} (PID {pid})"), LogLevel.Action);
            }
            catch (Exception ex) { log(L($"[X] 프로세스 종료 실패: {p.ProcessName} ({ex.Message})", $"[X] Could not end process: {p.ProcessName} ({ex.Message})"), LogLevel.Bad); }
        }

        // ------------------------------------------------------------------
        // 관리자 작업: 승격된 자기 자신에서 실행
        //   --elevated <요청파일> <로그파일> --lang xx : DEL / RMAUTO / BLOCK / WDO
        //   --audit <결과파일> <로그파일> --lang xx     : PC 전체 자동 실행 점검 (읽기만)
        // ------------------------------------------------------------------
        public static bool IsAdmin()
        {
            using (var id = WindowsIdentity.GetCurrent())
                return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }

        /// <summary>요청을 관리자 권한으로 실행. 반환값: 실패 수. canceled: UAC 를 거절했는지.</summary>
        public static int RunElevated(List<string> req, Logger log, out bool canceled)
        {
            canceled = false;
            if (IsAdmin()) return ExecuteRequests(req, log);

            var tmp = Path.GetTempPath();
            var reqFile = Path.Combine(tmp, $"NikkeChecker_req_{Guid.NewGuid():N}.txt");
            var logFile = Path.Combine(tmp, $"NikkeChecker_log_{Guid.NewGuid():N}.txt");
            File.WriteAllLines(reqFile, req, Encoding.UTF8);
            try
            {
                log(L("[*] 관리자 권한이 필요한 작업을 위해 UAC 승인을 요청합니다", "[*] Requesting administrator rights (UAC) for the admin tasks"), LogLevel.Info);
                int code = StartSelfElevated($"--elevated \"{reqFile}\" \"{logFile}\" --lang {Code}");
                RelayLog(logFile, log);
                return code;
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
            {
                canceled = true;
                log(L("[!] 관리자 권한 요청이 취소되어 관리자 작업(hosts·방화벽 차단, PC 전체 자동 실행·Program Files 파일 삭제)을 건너뛰었습니다.",
                      "[!] Administrator rights were declined, so the admin tasks (hosts/firewall block, PC-wide autostarts, Program Files files) were skipped."), LogLevel.Warn);
                return req.Count(r => !r.StartsWith("BLOCK") && !r.StartsWith("WDO"));
            }
            catch (Exception ex) { log(L($"[X] 관리자 작업 실행 실패: {ex.Message}", $"[X] Could not run the admin tasks: {ex.Message}"), LogLevel.Bad); return 1; }
            finally
            {
                try { File.Delete(reqFile); } catch { }
                try { File.Delete(logFile); } catch { }
            }
        }

        /// <summary>PC 전체 자동 실행 점검을 관리자 권한으로 실행. UAC 를 거절하면 null.</summary>
        public static List<AutostartItem> RunAudit(Logger log)
        {
            var tmp = Path.GetTempPath();
            var outFile = Path.Combine(tmp, $"NikkeChecker_audit_{Guid.NewGuid():N}.txt");
            var logFile = Path.Combine(tmp, $"NikkeChecker_log_{Guid.NewGuid():N}.txt");
            try
            {
                StartSelfElevated($"--audit \"{outFile}\" \"{logFile}\" --lang {Code}");
                RelayLog(logFile, log);
                if (!File.Exists(outFile)) return null;
                return File.ReadAllLines(outFile, Encoding.UTF8).Select(AutostartItem.FromLine).Where(a => a != null).ToList();
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) { return null; }
            catch (Exception ex) { log(L($"[X] 자동 실행 점검 실패: {ex.Message}", $"[X] Autostart check failed: {ex.Message}"), LogLevel.Bad); return null; }
            finally
            {
                try { File.Delete(outFile); } catch { }
                try { File.Delete(logFile); } catch { }
            }
        }

        private static int StartSelfElevated(string args)
        {
            var psi = new ProcessStartInfo(System.Windows.Forms.Application.ExecutablePath, args) { UseShellExecute = true, Verb = "runas" };
            using (var p = Process.Start(psi)) { p.WaitForExit(); return p.ExitCode; }
        }

        private static void RelayLog(string logFile, Logger log)
        {
            if (!File.Exists(logFile)) return;
            foreach (var line in File.ReadAllLines(logFile, Encoding.UTF8))
            {
                int tab = line.IndexOf('\t');
                var lvl = tab > 0 && Enum.TryParse(line.Substring(0, tab), out LogLevel l) ? l : LogLevel.Info;
                log(tab > 0 ? line.Substring(tab + 1) : line, lvl);
            }
        }

        /// <summary>--elevated 모드 진입점.</summary>
        public static int RunElevatedMode(string reqFile, string logFile)
        {
            var sb = new StringBuilder();
            int failed;
            try { failed = ExecuteRequests(File.ReadAllLines(reqFile, Encoding.UTF8), (m, l) => sb.AppendLine(l + "\t" + m)); }
            catch (Exception ex) { sb.AppendLine(LogLevel.Bad + "\t" + L("[X] 요청 처리 실패: ", "[X] Request failed: ") + ex.Message); failed = 1; }
            try { File.WriteAllText(logFile, sb.ToString(), Encoding.UTF8); } catch { }
            return failed;
        }

        /// <summary>--audit 모드 진입점: PC 전체 자동 실행 점검 결과를 파일로.</summary>
        public static int RunAuditMode(string outFile, string logFile)
        {
            var sb = new StringBuilder();
            try
            {
                var items = Autostart.AuditSystem(CancellationToken.None, n => sb.AppendLine(LogLevel.Detail + "\t  " + n));
                items.AddRange(Extra.AuditSystem(CancellationToken.None, n => sb.AppendLine(LogLevel.Detail + "\t  " + n)));
                Autostart.ScanWithDefender(items, CancellationToken.None);
                File.WriteAllLines(outFile, items.Select(i => i.ToLine()), Encoding.UTF8);
            }
            catch (Exception ex) { sb.AppendLine(LogLevel.Bad + "\t" + L("[X] 자동 실행 점검 실패: ", "[X] Autostart check failed: ") + ex.Message); }
            try { File.WriteAllText(logFile, sb.ToString(), Encoding.UTF8); } catch { }
            return 0;
        }

        private static int ExecuteRequests(IEnumerable<string> req, Logger log)
        {
            int failed = 0;
            List<AutostartItem> sysItems = null;
            foreach (var line in req)
            {
                if (line == "BLOCK") failed += ApplyBlock(log);
                else if (line == "WDO") { if (!Defender.StartOffline(log)) failed++; }
                else if (line.StartsWith("DEL\t"))
                {
                    var path = line.Substring(4);
                    // 요청 파일은 사용자 쓰기 가능 위치에 있으므로, 관리자 권한으로 지울 수 있는 대상을 엄격히 제한한다
                    if (!IsAllowedElevatedDelete(path)) { log(L($"[X] 허용되지 않은 삭제 요청 무시: {path}", $"[X] Ignored a delete request that is not allowed: {path}"), LogLevel.Bad); failed++; continue; }
                    if (!DeleteFile(path, log)) failed++;
                }
                else if (line.StartsWith("RMAUTO\t"))
                {
                    // 요청에는 Id 만 있다. 관리자 프로세스가 직접 다시 점검해 같은 Id 인 「확인 필요」 항목만 지운다
                    var id = line.Substring(7);
                    sysItems = sysItems ?? Autostart.AuditSystem(CancellationToken.None).Concat(Extra.AuditSystem(CancellationToken.None)).ToList();
                    var it = sysItems.FirstOrDefault(a => a.Id == id);
                    if (it == null) { log(L($"[!] 다시 점검했을 때 찾을 수 없는 항목이라 건너뜀 ({id})", $"[!] Skipped: the item was not found when checked again ({id})"), LogLevel.Warn); continue; }
                    if (!Autostart.Remove(it, log)) failed++;
                }
                else if (line.StartsWith("UNDIR\t") || line.StartsWith("UNFILE\t") || line.StartsWith("UNREG\t"))
                    failed += Uninstaller.ExecuteElevated(line, log);
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
                return Paths.ProgramFilesDirs.Any(r => string.Equals(dir, Path.Combine(r, Iocs.OldPersistenceDir), StringComparison.OrdinalIgnoreCase));
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
                if (toAdd.Count == 0) log(L("[-] hosts: 세 도메인이 이미 차단되어 있습니다", "[-] hosts: the three domains are already blocked"), LogLevel.Detail);
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
                    foreach (var d in toAdd) log(L($"[+] hosts 차단 등록: 0.0.0.0 {d}", $"[+] hosts block added: 0.0.0.0 {d}"), LogLevel.Action);
                }
                RunQuiet(Paths.Sys("ipconfig.exe"), "/flushdns");
            }
            catch (Exception ex)
            {
                failed++;
                log(L($"[X] hosts 파일 수정 실패: {ex.Message}", $"[X] Could not edit the hosts file: {ex.Message}"), LogLevel.Bad);
                log(L("    → 백신이 hosts 변경을 막았을 수 있습니다. 백신 알림을 확인해 주세요.", "    → Your antivirus may have blocked the change. Check its notifications."), LogLevel.Warn);
            }

            // hosts 는 IP 를 막을 수 없으므로 공격자 IP 는 방화벽으로 차단 (규칙 내용까지 확인, 다르면 다시 만듦)
            failed += Firewall.Ensure(log);
            return failed;
        }

        internal static int RunQuiet(string exe, string args)
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
