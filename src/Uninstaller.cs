using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using static NikkeChecker.I18n;

namespace NikkeChecker
{
    /// <summary>
    /// NIKKE 완전 삭제 (선택, 두 번 동의). 햄찌 v4.4 기능과 v4.5 긴급 수정의 안전장치를 따른다.
    ///  - 지울 런처 폴더 = nikke_launcher.exe 가 있고 이름이 Launcher 이거나 nikke 가 들어간 폴더만 (상위가 NIKKE 이면 그 폴더)
    ///  - 바탕 화면·문서·다운로드 등 사용자 폴더 바로 아래 폴더는 이름에 nikke 가 없으면 절대 제외
    ///  - 같은 회사(com.proximabeta)의 다른 게임 데이터·설정은 건드리지 않고 이름에 nikke 가 든 하위 폴더·키만
    ///  - 런처가 깔아 둔 실행 파일(제거 프로그램 등)은 실행하지 않는다
    /// </summary>
    public sealed class UninstallPlan
    {
        public List<string> Folders = new List<string>();
        public List<string> Files = new List<string>();      // 내려받은 설치 파일
        public List<string> Links = new List<string>();      // 바로가기
        public List<string> UserKeys = new List<string>();   // HKCU 하위 키
        public List<string> MachineKeys = new List<string>(); // HKLM 하위 키 (64:..., 32:...)
        public int Count => Folders.Count + Files.Count + Links.Count + UserKeys.Count + MachineKeys.Count;
    }

    public static class Uninstaller
    {
        private const string UninstallRoot = @"Software\Microsoft\Windows\CurrentVersion\Uninstall";

        // ------------------------------------------------------------------
        public static bool IsSafeFolder(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path) || !Regex.IsMatch(path, @"^[A-Za-z]:\\")) return false;
                var p = Path.GetFullPath(path).TrimEnd('\\');
                if (p.Equals(Path.GetPathRoot(p).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) return false;   // 드라이브 전체 금지
                var profile = Iocs.UserProfile;
                var usersRoot = Path.GetDirectoryName(profile.TrimEnd('\\'));
                var protectedRoots = new List<string> { Paths.Windows, Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), profile };
                protectedRoots.AddRange(Paths.ProgramFilesDirs);
                if (usersRoot != null) try { protectedRoots.AddRange(Directory.GetDirectories(usersRoot)); } catch { }
                foreach (var r in protectedRoots)
                    if (!string.IsNullOrEmpty(r) && Paths.IsInside(r, p)) return false;   // 보호 폴더를 품는 상위 폴더 금지
                if (Paths.IsInside(p, Paths.Windows)) return false;
                if (Regex.IsMatch(p, @"^[A-Za-z]:\\Users(\\[^\\]+)?$", RegexOptions.IgnoreCase)) return false;
                var leaf = Path.GetFileName(p);
                var parent = Path.GetDirectoryName(p) ?? "";
                if (leaf.IndexOf("nikke", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    // 사용자 폴더·OneDrive 바로 아래, 또는 이름이 바탕 화면·문서 같은 폴더는 이름에 nikke 가 없으면 지우지 않음
                    if (protectedRoots.Any(r => !string.IsNullOrEmpty(r) && parent.TrimEnd('\\').Equals(r.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))) return false;
                    if (Regex.IsMatch(parent, @"\\OneDrive[^\\]*$", RegexOptions.IgnoreCase)) return false;
                    if (Regex.IsMatch(leaf, @"^(Desktop|Documents|Downloads|Pictures|Music|Videos|OneDrive.*|AppData|Local|LocalLow|Roaming|Public)$", RegexOptions.IgnoreCase)) return false;
                }
                return true;
            }
            catch { return false; }
        }

        /// <summary>설치 루트(Launcher 폴더의 상위)에서 지울 폴더. 니케 런처 폴더가 확실할 때만.</summary>
        public static string FolderForInstall(string root)
        {
            foreach (var name in new[] { "Launcher", "launcher" })
            {
                var launcher = Path.Combine(root, name);
                if (!File.Exists(Path.Combine(launcher, "nikke_launcher.exe")) && !File.Exists(Path.Combine(launcher, "nikke_launcher_google.exe"))) continue;
                return Path.GetFileName(root.TrimEnd('\\')).Equals("NIKKE", StringComparison.OrdinalIgnoreCase) ? root.TrimEnd('\\') : launcher;
            }
            return null;
        }

        private static IEnumerable<string> NikkeUninstallKeys(RegistryHive hive, RegistryView view)
        {
            var keys = new List<string>();
            try
            {
                using (var b = RegistryKey.OpenBaseKey(hive, view))
                using (var root = b.OpenSubKey(UninstallRoot))
                    if (root != null)
                        foreach (var name in root.GetSubKeyNames())
                            using (var k = root.OpenSubKey(name))
                            {
                                var display = k?.GetValue("DisplayName") as string ?? "";
                                if (name.IndexOf("nikke", StringComparison.OrdinalIgnoreCase) >= 0 || display.IndexOf("NIKKE", StringComparison.OrdinalIgnoreCase) >= 0)
                                    keys.Add(UninstallRoot + "\\" + name);
                            }
            }
            catch { }
            return keys;
        }

        public static UninstallPlan Plan(IEnumerable<string> installRoots)
        {
            var plan = new UninstallPlan();
            var candidates = new List<string>();
            foreach (var root in installRoots ?? Enumerable.Empty<string>())
            {
                var f = FolderForInstall(root);
                if (f != null) candidates.Add(f);
            }
            candidates.AddRange(Iocs.LauncherDataDirs.Where(Directory.Exists));
            var localLow = Path.Combine(Iocs.UserProfile, @"AppData\LocalLow");
            foreach (var co in new[] { "com.proximabeta", "com_proximabeta" })
                foreach (var d in FileUtil.Dirs(Path.Combine(localLow, co)))
                    if (Path.GetFileName(d).IndexOf("nikke", StringComparison.OrdinalIgnoreCase) >= 0) candidates.Add(d);
            var unity = Path.Combine(localLow, @"Unity\com_proximabeta_NIKKE");
            if (Directory.Exists(unity)) candidates.Add(unity);

            foreach (var c in candidates.Select(c => Path.GetFullPath(c).TrimEnd('\\')).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(c => c.Length))
            {
                if (!IsSafeFolder(c)) continue;
                if (plan.Folders.Any(f => Paths.IsInside(c, f))) continue;
                plan.Folders.Add(c);
            }

            // 내려받은 설치 파일 (오염된 판을 다시 실행하지 않게)
            foreach (var dir in new[] { Path.Combine(Iocs.UserProfile, "Downloads"), Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory) }.Distinct(StringComparer.OrdinalIgnoreCase))
                foreach (var f in FileUtil.Files(dir, 0))
                    if (Regex.IsMatch(Path.GetFileName(f), @"^nikkeminiloader.*\.exe$|^nikke.*(installer|setup).*\.exe$", RegexOptions.IgnoreCase)) plan.Files.Add(f);

            // 바로가기: 대상이 nikke_launcher.exe 이거나 지울 폴더 안
            var linkDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Environment.GetFolderPath(Environment.SpecialFolder.Programs),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms),
            };
            foreach (var dir in linkDirs.Where(d => !string.IsNullOrEmpty(d) && Directory.Exists(d)).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                IEnumerable<string> lnks;
                try { lnks = Directory.EnumerateFiles(dir, "*.lnk", SearchOption.AllDirectories).ToList(); } catch { continue; }
                foreach (var lnk in lnks)
                {
                    var (target, _) = Shortcut.Read(lnk);
                    if (target == null) continue;
                    if (Path.GetFileName(target).Equals("nikke_launcher.exe", StringComparison.OrdinalIgnoreCase) || plan.Folders.Any(f => Paths.IsInside(target, f)))
                        plan.Links.Add(lnk);
                }
            }

            // 레지스트리: 「설치된 앱」 항목, nikkelauncher:// 연결, 게임 설정(이름에 nikke 가 든 하위 키만)
            plan.UserKeys.AddRange(NikkeUninstallKeys(RegistryHive.CurrentUser, RegistryView.Default));
            using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Classes\nikkelauncher")) if (k != null) plan.UserKeys.Add(@"Software\Classes\nikkelauncher");
            foreach (var co in new[] { "com.proximabeta", "com_proximabeta" })
                using (var k = Registry.CurrentUser.OpenSubKey(@"Software\" + co))
                    if (k != null)
                        foreach (var sub in k.GetSubKeyNames().Where(n => n.IndexOf("nikke", StringComparison.OrdinalIgnoreCase) >= 0))
                            plan.UserKeys.Add($@"Software\{co}\{sub}");
            plan.MachineKeys.AddRange(NikkeUninstallKeys(RegistryHive.LocalMachine, RegistryView.Registry64).Select(k => "64:" + k));
            plan.MachineKeys.AddRange(NikkeUninstallKeys(RegistryHive.LocalMachine, RegistryView.Registry32).Select(k => "32:" + k));
            return plan;
        }

        /// <summary>현재 사용자 권한으로 지울 수 있는 것을 지우고, 남은 것(Program Files·공용 바로가기·HKLM)은 관리자 요청으로 돌려준다.</summary>
        public static int Execute(UninstallPlan plan, Logger log, out List<string> elevatedRequests)
        {
            int failed = 0;
            elevatedRequests = new List<string>();
            foreach (var p in Iocs.LauncherProcesses)
                foreach (var proc in Process.GetProcessesByName(p)) using (proc) try { proc.Kill(); proc.WaitForExit(5000); } catch { }

            foreach (var d in plan.Folders)
                if (!Remediator.DeleteDirPublic(d, L("니케 폴더", "NIKKE folder"), log) && Directory.Exists(d)) elevatedRequests.Add("UNDIR\t" + d);
            foreach (var f in plan.Files.Concat(plan.Links))
                if (!Remediator.DeleteFile(f, log) && File.Exists(f)) elevatedRequests.Add("UNFILE\t" + f);
            foreach (var k in plan.UserKeys)
            {
                try
                {
                    Registry.CurrentUser.DeleteSubKeyTree(k, false);
                    log(L($"[+] 레지스트리 키 삭제: HKCU\\{k}", $"[+] Deleted registry key: HKCU\\{k}"), LogLevel.Action);
                }
                catch (Exception ex) { failed++; log(L($"[X] 레지스트리 키 삭제 실패: HKCU\\{k} ({ex.Message})", $"[X] Could not delete registry key: HKCU\\{k} ({ex.Message})"), LogLevel.Bad); }
            }
            elevatedRequests.AddRange(plan.MachineKeys.Select(k => "UNREG\t" + k));
            return failed;
        }

        /// <summary>관리자 프로세스: 요청 경로를 같은 규칙으로 다시 확인한 뒤에만 지운다.</summary>
        public static int ExecuteElevated(string line, Logger log)
        {
            var tab = line.IndexOf('\t');
            var kind = line.Substring(0, tab); var arg = line.Substring(tab + 1);
            try
            {
                switch (kind)
                {
                    case "UNDIR":
                        // 니케 폴더임이 확실해야 한다: 안전 규칙 + (이름에 nikke, 또는 Launcher 폴더 안에 nikke_launcher.exe)
                        bool nikkeFolder = Path.GetFileName(arg).IndexOf("nikke", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                           File.Exists(Path.Combine(arg, "nikke_launcher.exe")) || File.Exists(Path.Combine(arg, @"Launcher\nikke_launcher.exe"));
                        if (!IsSafeFolder(arg) || !nikkeFolder) break;
                        return Remediator.DeleteDirPublic(arg, L("니케 폴더", "NIKKE folder"), log) ? 0 : 1;
                    case "UNFILE":
                        var name = Path.GetFileName(arg);
                        bool ok = name.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)
                            ? Path.GetFileName(Shortcut.Read(arg).Target ?? "").Equals("nikke_launcher.exe", StringComparison.OrdinalIgnoreCase)
                            : Regex.IsMatch(name, @"^nikkeminiloader.*\.exe$|^nikke.*(installer|setup).*\.exe$", RegexOptions.IgnoreCase);
                        if (!ok) break;
                        return Remediator.DeleteFile(arg, log) ? 0 : 1;
                    case "UNREG":
                        var view = arg.StartsWith("32:") ? RegistryView.Registry32 : RegistryView.Registry64;
                        var key = arg.Substring(3);
                        if (!NikkeUninstallKeys(RegistryHive.LocalMachine, view).Contains(key, StringComparer.OrdinalIgnoreCase)) break;
                        using (var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view)) b.DeleteSubKeyTree(key, false);
                        log(L($"[+] 레지스트리 키 삭제: HKLM\\{key}", $"[+] Deleted registry key: HKLM\\{key}"), LogLevel.Action);
                        return 0;
                }
            }
            catch (Exception ex) { log(L($"[X] 삭제 실패: {arg} ({ex.Message})", $"[X] Could not delete: {arg} ({ex.Message})"), LogLevel.Bad); return 1; }
            log(L($"[X] 허용되지 않은 삭제 요청 무시: {arg}", $"[X] Ignored a delete request that is not allowed: {arg}"), LogLevel.Bad);
            return 1;
        }
    }
}
