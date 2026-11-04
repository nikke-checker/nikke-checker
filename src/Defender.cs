using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Xml;
using static NikkeChecker.I18n;

namespace NikkeChecker
{
    /// <summary>Windows Defender: 의심 파일 개별 검사(MpCmdRun), 오프라인 검사(재부팅) 예약.</summary>
    public static class Defender
    {
        private static string MpCmdRun()
        {
            try
            {
                var platform = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows Defender\Platform");
                if (Directory.Exists(platform))
                {
                    var latest = Directory.GetDirectories(platform).OrderBy(d => d, StringComparer.OrdinalIgnoreCase)
                        .Select(d => Path.Combine(d, "MpCmdRun.exe")).LastOrDefault(File.Exists);
                    if (latest != null) return latest;
                }
            }
            catch { }
            var pf = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Windows Defender\MpCmdRun.exe");
            return File.Exists(pf) ? pf : null;
        }

        /// <summary>"malware" / "clean" / null(검사 못 함). 치료는 하지 않고 검사만 한다.</summary>
        public static string ScanFile(string file)
        {
            try
            {
                if (string.IsNullOrEmpty(file) || !File.Exists(file)) return null;
                var mp = MpCmdRun();
                if (mp == null) return null;
                var psi = new ProcessStartInfo(mp, $"-Scan -ScanType 3 -File \"{file}\" -DisableRemediation")
                { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                using (var p = Process.Start(psi))
                {
                    p.StandardOutput.ReadToEnd(); p.StandardError.ReadToEnd();
                    if (!p.WaitForExit(120000)) { try { p.Kill(); } catch { } return null; }
                    return p.ExitCode == 0 ? "clean" : p.ExitCode == 2 ? "malware" : null;
                }
            }
            catch { return null; }
        }

        public static string VerdictText(string v) =>
            v == "malware" ? L("Defender: 악성 프로그램으로 확인됨", "Defender: confirmed MALWARE")
            : v == "clean" ? L("Defender: 알려진 악성 프로그램은 아님", "Defender: not known malware")
            : L("Defender 로 검사하지 못함", "Could not scan with Defender");

        // ------------------------------------------------------------------
        // 오프라인 검사 (관리자). 마이크로소프트 안내 기준으로 권하면 안 되는 PC 를 거른다.
        // ------------------------------------------------------------------

        /// <summary>오프라인 검사를 할 수 없거나 권하지 않는 이유. null 이면 가능.</summary>
        public static string OfflineBlocker()
        {
            string mode = null;
            try
            {
                using (var s = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender", "SELECT AMRunningMode FROM MSFT_MpComputerStatus"))
                    foreach (ManagementObject o in s.Get()) mode = o["AMRunningMode"] as string;
            }
            catch { }
            if (mode == null || !mode.Equals("Normal", StringComparison.OrdinalIgnoreCase))
                return L("이 PC 는 Windows Defender 가 주 백신이 아니라 오프라인 검사를 쓸 수 없습니다. 쓰고 있는 백신으로 「정밀 검사」를 해 주세요.",
                         "Windows Defender is not the active antivirus on this PC, so the offline scan cannot run. Run a full scan with your antivirus.");
            try
            {
                var sysDrive = Paths.Windows.Substring(0, 2);
                using (var s = new ManagementObjectSearcher(@"root\cimv2\Security\MicrosoftVolumeEncryption",
                    $"SELECT ProtectionStatus FROM Win32_EncryptableVolume WHERE DriveLetter='{sysDrive}'"))
                    foreach (ManagementObject o in s.Get())
                        if (Convert.ToInt32(o["ProtectionStatus"]) == 1)
                            return L("이 PC 는 드라이브 암호화(BitLocker)가 켜져 있어 재부팅 검사 때 복구 키를 물을 수 있어 건너뜁니다.",
                                     "BitLocker drive encryption is on, so the restart scan could ask for your recovery key. Skipping it.");
            }
            catch { }
            try
            {
                var reAgent = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\Recovery\ReAgent.xml");
                if (File.Exists(reAgent))
                {
                    var doc = new XmlDocument();
                    doc.Load(reAgent);
                    var state = doc.SelectSingleNode("/WindowsRE/InstallState/@state")?.Value;
                    if (state == "0")
                        return L("이 PC 는 Windows 복구 환경이 꺼져 있어 재부팅 검사를 할 수 없습니다.",
                                 "The Windows Recovery Environment is off on this PC, so the restart scan cannot run.");
                }
            }
            catch { }
            return null;
        }

        public static string FullScanAdvice =>
            L("대신 Windows 안에서 「전체 검사」를 한 번 해 주세요 (시간이 꽤 걸립니다): Windows 보안 → 바이러스 및 위협 방지 → 검사 옵션 → 전체 검사 → 지금 검사",
              "Instead, run a Full scan inside Windows once (it takes a while): Windows Security -> Virus & threat protection -> Scan options -> Full scan -> Scan now");

        /// <summary>오프라인 검사를 예약한다 (곧 재부팅됨). 성공하면 true.</summary>
        public static bool StartOffline(Logger log)
        {
            var blocker = OfflineBlocker();
            if (blocker != null) { log("[!] " + blocker, LogLevel.Warn); log("    " + FullScanAdvice, LogLevel.Info); return false; }
            try
            {
                using (var cls = new ManagementClass(@"root\Microsoft\Windows\Defender", "MSFT_MpWDOScan", null))
                    cls.InvokeMethod("Start", null);
                log(L("[+] Windows Defender 오프라인 검사를 예약했습니다. 곧 재부팅되고 검사 화면이 자동으로 뜹니다 (약 15분).",
                      "[+] Windows Defender offline scan scheduled. The PC will restart soon and the scan screen will appear (about 15 min)."), LogLevel.Action);
                log("[WDO] started", LogLevel.Detail);
                return true;
            }
            catch (Exception ex)
            {
                log(L($"[X] 오프라인 검사를 시작하지 못했습니다: {ex.Message}", $"[X] Could not start the offline scan: {ex.Message}"), LogLevel.Bad);
                log("    " + FullScanAdvice, LogLevel.Info);
                return false;
            }
        }
    }
}
