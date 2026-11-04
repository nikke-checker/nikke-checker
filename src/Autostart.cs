using System;
using System.Collections;
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
    /// <summary>자동 실행 항목 하나 ("확인 필요").</summary>
    public sealed class AutostartItem
    {
        public string Id;        // 종류·위치·이름·대상으로 만든 값. 관리자 프로세스가 다시 찾아 같은 항목만 지우는 데 쓴다
        public string Kind;      // Run / Startup / Task / Service / Wmi
        public string Scope;     // user (현재 사용자 권한으로 처리) / system (관리자 권한으로 처리)
        public string Where;     // 화면 표시용 위치
        public string Name;
        public string Display;   // 대상 파일 또는 숨겨진 명령
        public string File;      // 실행되는 파일 (없으면 null)
        public string Date;      // MM-dd 또는 ?
        public string Defender;  // malware / clean / null
        public bool Hidden;      // 파일 없이 명령을 숨겨 실행

        // 삭제에 필요한 정보 (같은 프로세스 안에서만 쓰임)
        internal RegistryHive Hive; internal RegistryView View; internal string Key; internal string Value;
        internal string Item; internal string TaskPath; internal string TaskName; internal string Service; internal string Consumer;

        public string ToLine() => string.Join("\t", new[] { Id, Kind, Scope, Where, Name, Display, File, Date, Defender, Hidden ? "1" : "0" }
            .Select(s => (s ?? "").Replace("\t", " ").Replace("\r", " ").Replace("\n", " ")));

        public static AutostartItem FromLine(string line)
        {
            var p = line.Split('\t');
            if (p.Length < 10) return null;
            string N(string s) => s.Length == 0 ? null : s;
            return new AutostartItem { Id = p[0], Kind = p[1], Scope = p[2], Where = p[3], Name = p[4], Display = p[5], File = N(p[6]), Date = p[7], Defender = N(p[8]), Hidden = p[9] == "1" };
        }
    }

    /// <summary>
    /// 해커가 따로 깔았을 수 있는 프로그램 점검 (햄찌 NIKKE_k2f_cleaner v3.2~v4 규칙).
    /// PC 를 켤 때마다 다시 살아나려면 자동 실행에 등록해야 하므로, 감염 기간(9/27 이후)에 새로 생긴 자동 실행 대상 중
    /// 제작사 서명이 없는 것을 「확인 필요」로 보여 준다. 판정에는 영향이 없고, 지우는 것은 사용자가 고른 것만.
    /// </summary>
    public static class Autostart
    {
        public static readonly DateTime Since = new DateTime(2026, 9, 27);
        private static readonly string[] ScriptHosts = { "rundll32", "regsvr32", "wscript", "cscript", "mshta", "powershell", "pwsh", "cmd" };
        private static readonly Regex ExeExt = new Regex(@"\.(exe|com|bat|cmd|vbs|vbe|js|jse|ps1|dll|scr|hta)$", RegexOptions.IgnoreCase);
        private static readonly Regex ExeInText = new Regex(@"^(.+?\.(exe|com|bat|cmd|vbs|vbe|js|jse|ps1|dll|scr|hta))(?=\s|,|$)", RegexOptions.IgnoreCase);
        private static readonly Regex ScriptInArgs = new Regex(@"([A-Za-z]:\\[^""]+?\.(dll|vbs|vbe|js|jse|ps1|bat|cmd|hta|exe))(?=[""\s,]|$)", RegexOptions.IgnoreCase);
        private static readonly Regex HiddenCmd = new Regex(@"(^|\s)-e(nc|ncodedcommand)?\s|https?://|frombase64|iex\b|invoke-expression|downloadstring", RegexOptions.IgnoreCase);

        // ------------------------------------------------------------------
        /// <summary>명령줄에서 실제로 실행되는 파일. 스크립트 실행기(powershell 등)는 실행되는 스크립트를 본다. 숨겨진 명령은 "INLINE:" 으로.</summary>
        public static string RunTarget(string cmd)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(cmd)) return null;
                var c = Environment.ExpandEnvironmentVariables(cmd.Trim());
                if (c.StartsWith(@"\??\")) c = c.Substring(4);
                if (c.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
                    c = Environment.GetFolderPath(Environment.SpecialFolder.Windows) + c.Substring(11);
                else if (c.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase))
                    c = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), c);

                string exe, rest;
                if (c.StartsWith("\""))
                {
                    int e = c.IndexOf('"', 1);
                    if (e < 0) return null;
                    exe = c.Substring(1, e - 1); rest = c.Substring(e + 1).Trim();
                }
                else
                {
                    var parts = c.Split(new[] { ' ', '\t' }, 2, StringSplitOptions.RemoveEmptyEntries);
                    string tok = parts[0], tokRest = parts.Length > 1 ? parts[1] : "";
                    var tokNoExt = Path.GetFileNameWithoutExtension(tok).ToLowerInvariant();
                    if (ExeExt.IsMatch(tok) || ScriptHosts.Contains(tokNoExt) || System.IO.File.Exists(tok)) { exe = tok; rest = tokRest; }
                    else
                    {
                        // 따옴표 없이 띄어쓰기가 든 경로 (C:\Program Files\A\x.exe --flag)
                        var m = ExeInText.Match(c);
                        if (m.Success) { exe = m.Groups[1].Value; rest = c.Substring(exe.Length).Trim(); }
                        else { exe = tok; rest = tokRest; }
                    }
                }
                var leafNoExt = Path.GetFileNameWithoutExtension(exe).ToLowerInvariant();
                if (ScriptHosts.Contains(leafNoExt))
                {
                    var m2 = ScriptInArgs.Match(rest);
                    if (m2.Success) return m2.Groups[1].Value;
                    if ((leafNoExt == "powershell" || leafNoExt == "pwsh" || leafNoExt == "mshta") && HiddenCmd.IsMatch(rest)) return "INLINE:" + c;
                    return null;
                }
                if (!Path.IsPathRooted(exe)) exe = FindOnPath(exe) ?? exe;
                return exe;
            }
            catch { return null; }
        }

        private static string FindOnPath(string exe)
        {
            var names = Path.HasExtension(exe) ? new[] { exe } : new[] { exe + ".exe", exe };
            var dirs = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';').Where(d => d.Length > 0)
                .Prepend(Environment.GetFolderPath(Environment.SpecialFolder.System));
            foreach (var d in dirs)
                foreach (var n in names)
                {
                    try { var p = Path.Combine(d.Trim('"'), n); if (System.IO.File.Exists(p)) return p; } catch { }
                }
            return null;
        }

        private static string MakeId(string kind, string where, string name, string target)
        {
            using (var sha = SHA256.Create())
            {
                var h = sha.ComputeHash(Encoding.UTF8.GetBytes($"{kind}|{where}|{name}|{target}".ToLowerInvariant()));
                return string.Concat(h.Take(10).Select(b => b.ToString("x2")));
            }
        }

        /// <summary>대상이 9/27 이후 생겼고 제작사 서명이 없으면 확인 필요 항목으로 추가.</summary>
        private static void Consider(List<AutostartItem> list, HashSet<string> seen, AutostartItem proto, string target, DateTime entryTime, string idWhere)
        {
            if (string.IsNullOrEmpty(target)) return;
            if (target.StartsWith("INLINE:"))
            {
                var key = proto.Kind + "|" + proto.Name;
                if (!seen.Add(key)) return;
                proto.Hidden = true; proto.File = null;
                proto.Display = L("숨겨진 명령: ", "Hidden command: ") + target.Substring(7);
                proto.Date = entryTime > DateTime.MinValue ? entryTime.ToString("MM-dd") : "?";
                proto.Id = MakeId(proto.Kind, idWhere, proto.Name, target);
                list.Add(proto);
                return;
            }
            if (!System.IO.File.Exists(target)) return;   // 파일이 없으면 실행도 안 됨
            FileInfo fi;
            try { fi = new FileInfo(target); var _ = fi.Length; }
            catch
            {
                // 파일은 있는데 열 수 없음(권한·잠금) — 조용히 넘기지 않고 확인 대상으로
                if (!seen.Add(target.ToLowerInvariant())) return;
                proto.File = target; proto.Display = target + L(" (열 수 없음)", " (cannot open)"); proto.Date = "?";
                proto.Id = MakeId(proto.Kind, idWhere, proto.Name, target);
                list.Add(proto);
                return;
            }
            var newest = new[] { fi.CreationTime, fi.LastWriteTime, entryTime }.Max();
            if (newest < Since) return;
            var sig = Signature.Check(fi.FullName);
            if (sig == SigStatus.Valid) return;   // 제작사 서명이 확인된 프로그램은 제외
            if (sig == SigStatus.Unknown && fi.FullName.IndexOf(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase) >= 0) return;   // 스토어 앱 실행 별칭
            if (sig == SigStatus.Unknown && fi.FullName.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows) + "\\", StringComparison.OrdinalIgnoreCase)) return;   // 서명 확인 자체가 안 된 Windows 폴더 파일은 오탐 방지로 제외
            if (!seen.Add(fi.FullName.ToLowerInvariant())) return;
            proto.File = fi.FullName;
            proto.Display = fi.FullName + (sig == SigStatus.Unknown ? L(" (서명 확인 못 함)", " (signature not checked)") :
                                           sig == SigStatus.Invalid ? L(" (서명이 올바르지 않음)", " (invalid signature)") : "");
            proto.Date = newest.ToString("MM-dd");
            proto.Id = MakeId(proto.Kind, idWhere, proto.Name, fi.FullName);
            list.Add(proto);
        }

        // ------------------------------------------------------------------
        // 현재 사용자 범위: HKCU Run/RunOnce, 사용자 시작 프로그램 폴더
        // ------------------------------------------------------------------
        public static List<AutostartItem> AuditUser(CancellationToken ct)
        {
            var list = new List<AutostartItem>(); var seen = new HashSet<string>();
            foreach (var sub in new[] { @"Software\Microsoft\Windows\CurrentVersion\Run", @"Software\Microsoft\Windows\CurrentVersion\RunOnce" })
                AuditRunKey(list, seen, RegistryHive.CurrentUser, RegistryView.Default, sub, "user");
            AuditStartupDir(list, seen, Environment.GetFolderPath(Environment.SpecialFolder.Startup), "user", ct);
            return list;
        }

        // ------------------------------------------------------------------
        // PC 전체 범위 (관리자): HKLM Run, 공용 시작 폴더, 작업 스케줄러, 서비스, WMI 이벤트
        // ------------------------------------------------------------------
        public static List<AutostartItem> AuditSystem(CancellationToken ct, Action<string> note = null)
        {
            var list = new List<AutostartItem>(); var seen = new HashSet<string>();
            AuditRunKey(list, seen, RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "system");
            AuditRunKey(list, seen, RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "system");
            AuditRunKey(list, seen, RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "system");
            AuditStartupDir(list, seen, Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "system", ct);
            try { AuditTasks(list, seen, ct); } catch (Exception ex) { note?.Invoke(L("작업 스케줄러를 읽지 못함: ", "Could not read Task Scheduler: ") + ex.Message); }
            try { AuditServices(list, seen, ct); } catch (Exception ex) { note?.Invoke(L("서비스 목록을 읽지 못함: ", "Could not read services: ") + ex.Message); }
            try { AuditWmi(list, seen); } catch (Exception ex) { note?.Invoke(L("WMI 이벤트를 읽지 못함: ", "Could not read WMI events: ") + ex.Message); }
            return list;
        }

        private static void AuditRunKey(List<AutostartItem> list, HashSet<string> seen, RegistryHive hive, RegistryView view, string sub, string scope)
        {
            try
            {
                using (var b = RegistryKey.OpenBaseKey(hive, view))
                using (var k = b.OpenSubKey(sub))
                {
                    if (k == null) return;
                    var where = L("자동 실행 목록", "Run key") + $" ({(hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM")}{(view == RegistryView.Registry32 ? " 32bit" : "")}\\{Path.GetFileName(sub)})";
                    foreach (var name in k.GetValueNames())
                    {
                        var val = k.GetValue(name) as string;
                        var proto = new AutostartItem { Kind = "Run", Scope = scope, Where = where, Name = name, Hive = hive, View = view, Key = sub, Value = name };
                        Consider(list, seen, proto, RunTarget(val), DateTime.MinValue, $"{hive}|{view}|{sub}");
                    }
                }
            }
            catch { }
        }

        private static void AuditStartupDir(List<AutostartItem> list, HashSet<string> seen, string dir, string scope, CancellationToken ct)
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return;
            var where = L("시작 프로그램 폴더", "Startup folder");
            foreach (var f in FileUtil.Files(dir, 0))
            {
                ct.ThrowIfCancellationRequested();
                var name = Path.GetFileName(f);
                if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                var proto = new AutostartItem { Kind = "Startup", Scope = scope, Where = where, Name = name, Item = f };
                if (name.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                {
                    if (FileUtil.Created(f) < Since && FileUtil.Modified(f) < Since) continue;
                    var (target, args) = ResolveShortcut(f);
                    if (target == null) continue;
                    Consider(list, seen, proto, RunTarget(("\"" + target + "\" " + args).Trim()), FileUtil.Modified(f), dir);
                }
                else Consider(list, seen, proto, f, DateTime.MinValue, dir);
            }
        }

        private static (string, string) ResolveShortcut(string lnk)
        {
            try
            {
                var t = Type.GetTypeFromProgID("WScript.Shell");
                var shell = Activator.CreateInstance(t);
                var sc = t.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { lnk });
                var target = sc.GetType().InvokeMember("TargetPath", BindingFlags.GetProperty, null, sc, null) as string;
                var args = sc.GetType().InvokeMember("Arguments", BindingFlags.GetProperty, null, sc, null) as string;
                return (string.IsNullOrEmpty(target) ? null : target, args ?? "");
            }
            catch { return (null, null); }
        }

        private static object Com(object o, string name, params object[] args) =>
            o.GetType().InvokeMember(name, args.Length == 0 ? BindingFlags.GetProperty : BindingFlags.InvokeMethod, null, o, args);

        private static object ConnectScheduler()
        {
            var svc = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service", true));
            svc.GetType().InvokeMember("Connect", BindingFlags.InvokeMethod, null, svc, new object[0]);
            return svc;
        }

        private static void AuditTasks(List<AutostartItem> list, HashSet<string> seen, CancellationToken ct)
        {
            var svc = ConnectScheduler();
            var where = L("작업 스케줄러", "Scheduled task");
            var tasksDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");
            var stack = new Stack<object>();
            stack.Push(svc.GetType().InvokeMember("GetFolder", BindingFlags.InvokeMethod, null, svc, new object[] { "\\" }));
            while (stack.Count > 0)
            {
                ct.ThrowIfCancellationRequested();
                var folder = stack.Pop();
                var folderPath = Com(folder, "Path") as string ?? "\\";
                try { foreach (var sub in (IEnumerable)folder.GetType().InvokeMember("GetFolders", BindingFlags.InvokeMethod, null, folder, new object[] { 0 })) stack.Push(sub); } catch { }
                IEnumerable tasks;
                try { tasks = (IEnumerable)folder.GetType().InvokeMember("GetTasks", BindingFlags.InvokeMethod, null, folder, new object[] { 1 /*TASK_ENUM_HIDDEN*/ }); }
                catch { continue; }
                foreach (var task in tasks)
                {
                    try
                    {
                        var name = Com(task, "Name") as string;
                        var path = Com(task, "Path") as string ?? (folderPath.TrimEnd('\\') + "\\" + name);
                        var def = Com(task, "Definition");
                        // 등록 시각: 작업 파일 시각, 없으면 등록 정보의 날짜
                        var entry = FileUtil.Modified(Path.Combine(tasksDir, path.TrimStart('\\')));
                        if (entry == DateTime.MinValue && DateTime.TryParse(Com(Com(def, "RegistrationInfo"), "Date") as string, out var regDate)) entry = regDate;
                        foreach (var action in (IEnumerable)Com(def, "Actions"))
                        {
                            if (Convert.ToInt32(Com(action, "Type")) != 0) continue;   // 0 = 프로그램 실행
                            var exe = (Com(action, "Path") as string ?? "").Trim('"');
                            if (exe.Length == 0) continue;
                            var target = RunTarget(("\"" + exe + "\" " + (Com(action, "Arguments") as string ?? "")).Trim());
                            if (target != null && target.StartsWith("INLINE:") && entry < Since) continue;   // 오래된 작업의 숨은 명령은 제외
                            var proto = new AutostartItem
                            {
                                Kind = "Task", Scope = "system", Where = where, Name = path,
                                TaskPath = folderPath, TaskName = name,
                            };
                            Consider(list, seen, proto, target, entry, "task");
                        }
                    }
                    catch { }
                }
            }
        }

        private static void AuditServices(List<AutostartItem> list, HashSet<string> seen, CancellationToken ct)
        {
            var where = L("서비스", "Service");
            using (var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            using (var root = b.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
            {
                if (root == null) return;
                foreach (var name in root.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using (var k = root.OpenSubKey(name))
                        {
                            if (k == null) continue;
                            var type = k.GetValue("Type") is int t ? t : 0;
                            if ((type & 0x30) == 0) continue;   // Win32 서비스만 (드라이버 제외)
                            var target = RunTarget(k.GetValue("ImagePath") as string);
                            if (target != null && Path.GetFileName(target).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
                            {
                                // svchost 로 도는 서비스는 실제 DLL 을 본다
                                using (var pk = k.OpenSubKey("Parameters"))
                                {
                                    var dll = pk?.GetValue("ServiceDll") as string;
                                    if (string.IsNullOrEmpty(dll)) continue;
                                    target = Environment.ExpandEnvironmentVariables(dll);
                                }
                            }
                            var proto = new AutostartItem { Kind = "Service", Scope = "system", Where = where, Name = name, Service = name };
                            Consider(list, seen, proto, target, DateTime.MinValue, "service");
                        }
                    }
                    catch { }
                }
            }
        }

        private static void AuditWmi(List<AutostartItem> list, HashSet<string> seen)
        {
            // 정상 프로그램은 거의 쓰지 않는 숨는 방법이라 날짜·서명과 상관없이 보여 준다 (이벤트 로그 기록용 소비자는 제외)
            var where = L("Windows 내부 예약 실행(WMI)", "Windows hidden trigger (WMI)");
            using (var s = new ManagementObjectSearcher(@"root\subscription", "SELECT * FROM __EventConsumer"))
            {
                foreach (ManagementObject c in s.Get())
                {
                    var cls = c.ClassPath.ClassName;
                    if (cls == "NTEventLogEventConsumer") continue;
                    var name = c["Name"] as string ?? "";
                    if (!seen.Add("wmi|" + name)) continue;
                    string cmd = null;
                    try { cmd = c["CommandLineTemplate"] as string; } catch { }
                    if (string.IsNullOrEmpty(cmd)) try { cmd = c["ScriptFileName"] as string; } catch { }
                    list.Add(new AutostartItem
                    {
                        Kind = "Wmi", Scope = "system", Where = where, Name = name, Date = "?", Hidden = string.IsNullOrEmpty(cmd),
                        Display = string.IsNullOrEmpty(cmd) ? cls + L(" (스크립트)", " (script)") : cmd,
                        Consumer = name, Id = MakeId("Wmi", "wmi", name, cmd ?? cls),
                    });
                }
            }
        }

        // ------------------------------------------------------------------
        // 삭제: 자동 실행 등록을 끊고, 실행되던 파일도 지운다 (Windows 폴더 안 파일은 등록만 끊음)
        // ------------------------------------------------------------------
        public static bool Remove(AutostartItem it, Logger log)
        {
            bool ok = true;
            try
            {
                switch (it.Kind)
                {
                    case "Run":
                        using (var b = RegistryKey.OpenBaseKey(it.Hive, it.View))
                        using (var k = b.OpenSubKey(it.Key, true))
                        {
                            k?.DeleteValue(it.Value, false);
                            if (k?.GetValue(it.Value) != null) ok = false;
                        }
                        break;
                    case "Startup":
                        if (!Remediator.DeleteFile(it.Item, log)) ok = false;
                        break;
                    case "Task":
                        var svc = ConnectScheduler();
                        var folder = svc.GetType().InvokeMember("GetFolder", BindingFlags.InvokeMethod, null, svc, new object[] { it.TaskPath });
                        folder.GetType().InvokeMember("DeleteTask", BindingFlags.InvokeMethod, null, folder, new object[] { it.TaskName, 0 });
                        break;
                    case "Service":
                        Remediator.RunQuiet("sc.exe", $"stop \"{it.Service}\"");
                        if (Remediator.RunQuiet("sc.exe", $"delete \"{it.Service}\"") != 0) ok = false;
                        break;
                    case "Wmi":
                        using (var s = new ManagementObjectSearcher(@"root\subscription", "SELECT * FROM __FilterToConsumerBinding"))
                            foreach (ManagementObject bind in s.Get())
                                if ((bind["Consumer"] as string ?? "").IndexOf("\"" + it.Consumer + "\"", StringComparison.Ordinal) >= 0) bind.Delete();
                        using (var s = new ManagementObjectSearcher(@"root\subscription", "SELECT * FROM __EventConsumer"))
                            foreach (ManagementObject c in s.Get())
                                if ((c["Name"] as string) == it.Consumer) c.Delete();
                        break;
                }
            }
            catch (Exception ex) { ok = false; log(L($"[X] 자동 실행 등록 삭제 실패: {it.Name} ({ex.Message})", $"[X] Could not remove the autostart entry: {it.Name} ({ex.Message})"), LogLevel.Bad); }

            var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (it.File != null && System.IO.File.Exists(it.File) && !it.File.StartsWith(win + "\\", StringComparison.OrdinalIgnoreCase))
                if (!Remediator.DeleteFile(it.File, log)) ok = false;
            if (ok) log(L($"[+] 자동 실행 항목 삭제: [{it.Where}] {it.Name}", $"[+] Removed autostart item: [{it.Where}] {it.Name}"), LogLevel.Action);
            return ok;
        }

        /// <summary>찾은 항목을 Defender 로 검사해 결과를 채운다.</summary>
        public static void ScanWithDefender(IEnumerable<AutostartItem> items, CancellationToken ct)
        {
            foreach (var it in items)
            {
                ct.ThrowIfCancellationRequested();
                if (it.File != null && it.Defender == null) it.Defender = Defender.ScanFile(it.File);
            }
        }
    }
}
