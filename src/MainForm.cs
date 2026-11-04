using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using static NikkeChecker.I18n;

namespace NikkeChecker
{
    public sealed class MainForm : Form
    {
        private sealed class Item
        {
            public CheckId Id;
            public CheckBox Box;
            public Label Status;
        }

        private readonly List<Item> _items = new List<Item>();
        private readonly TextBox _pathBox = new TextBox();
        private readonly Button _browseBtn = new Button();
        private readonly CheckBox _fixBox = new CheckBox();
        private readonly CheckBox _tbsBox = new CheckBox();
        private readonly CheckBox _blockBox = new CheckBox();
        private readonly CheckBox _wdoBox = new CheckBox();
        private readonly Button _scanBtn = new Button();
        private readonly Button _fixBtn = new Button();
        private readonly Button _stopBtn = new Button();
        private readonly Button _saveBtn = new Button();
        private readonly Button _uninstallBtn = new Button();
        private readonly RichTextBox _logBox = new RichTextBox();
        private readonly ProgressBar _progress = new ProgressBar();
        private readonly Label _summary = new Label();

        private CancellationTokenSource _cts;
        private ScanResult _last;

        private static string UiFont => En ? "Segoe UI" : "Malgun Gothic";
        private static string WdoMarker => Path.Combine(Iocs.LocalAppData, @"NikkeChecker\offline_scan.txt");

        public MainForm()
        {
            Text = L("NIKKE PC 런처 감염 점검 도구 v", "NIKKE PC Launcher Infection Checker v") + Application.ProductVersion;
            Font = new Font(UiFont, 9F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(940, 900);
            MinimumSize = new Size(780, 720);
            StartPosition = FormStartPosition.CenterScreen;
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new Padding(10) };
            for (int i = 0; i < 5; i++) root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            Controls.Add(root);

            // ---- 안내 + 언어 전환 ----
            var top = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 2, Margin = new Padding(0, 0, 0, 8) };
            top.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            top.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            top.Controls.Add(new Label
            {
                AutoSize = true, MaximumSize = new Size(820, 0), Margin = new Padding(3, 0, 3, 0),
                Text = L("2026년 9월 27일 이후 NIKKE PC 런처를 실행한 적이 있다면 점검하세요. (악성 에이전트는 10월 23일부터 일부 실행 시에 배포됨)\n" +
                         "점검할 항목을 선택하고 [점검 시작]을 누르세요. 점검은 아무것도 바꾸지 않습니다.",
                         "Check this PC if you ran the NIKKE PC launcher on or after Sep 27, 2026. (The malicious agent was served on some launches from Oct 23.)\n" +
                         "Select the items to check and press [Start check]. Checking changes nothing."),
            }, 0, 0);
            var lang = new LinkLabel { Text = En ? "한국어" : "English", AutoSize = true, Anchor = AnchorStyles.Top | AnchorStyles.Right };
            lang.LinkClicked += (s, e) => SwitchLanguage();
            top.Controls.Add(lang, 1, 0);
            root.Controls.Add(top);

            // ---- 점검 항목 ----
            var checkGroup = new GroupBox { Text = L("점검 항목", "Checks"), Dock = DockStyle.Fill, AutoSize = true, Padding = new Padding(8) };
            var t = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 2 };
            t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            checkGroup.Controls.Add(t);
            root.Controls.Add(checkGroup);

            AddItem(t, CheckId.BrowserDll,   L("1. 브라우저 지속성 DLL  (Chromium 계열 14종 PlatformExperienceHelper\\<64자리>, 구버전 Chrome 파일 포함)",
                                               "1. Browser persistence DLL  (PlatformExperienceHelper\\<64 hex> in 14 Chromium browsers, older Chrome files)"));
            AddItem(t, CheckId.Clsid,        L("2. 레지스트리 CLSID 하이재킹  (" + Iocs.BadClsid + ", WOW6432Node, 빈 잔여 키 포함)",
                                               "2. Registry CLSID hijack  (" + Iocs.BadClsid + ", WOW6432Node, empty leftover key)"));
            AddItem(t, CheckId.Processes,    L("3. 실행 중 프로세스  (런처 실행 여부, 악성 DLL 이 로드된 프로그램)",
                                               "3. Running processes  (launcher running, programs with the malicious DLL loaded)"));
            AddItem(t, CheckId.LauncherData, L("4. 런처 데이터  (k2f.agent, 악성 스크립트 캐시, HSTS·네트워크 접속 기록)",
                                               "4. Launcher data  (k2f.agent, malicious script cache, HSTS and network records)"));
            AddItem(t, CheckId.Temp,         L("5. 임시 폴더  (k2f-bcreds-* 탈취 자격 증명, k2f_screen_* 화면 캡처)",
                                               "5. Temp folder  (k2f-bcreds-* stolen credentials, k2f_screen_* screenshots)"));
            AddItem(t, CheckId.FullScan,     L("6. 전체 드라이브 파일 이름 검사  (정해진 위치 밖의 에이전트·DLL 파일, 니케 설치 위치 — 수 분 걸릴 수 있음)",
                                               "6. File-name scan of all drives  (agent/DLL files outside known places, NIKKE install location - can take minutes)"));
            AddItem(t, CheckId.InstallLogs,  L("7. 니케 설치 폴더  (debug.log 실행 기록, tinyget 다운로드 기록, 저장된 에이전트 파일)",
                                               "7. NIKKE install folder  (debug.log runs, tinyget download records, saved agent files)"));

            var pathRow = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 3, Margin = new Padding(20, 0, 0, 0) };
            pathRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            pathRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            pathRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            pathRow.Controls.Add(new Label { Text = L("니케 설치 경로:", "NIKKE install path:"), AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 7, 3, 3) }, 0, 0);
            _pathBox.Dock = DockStyle.Fill;
            pathRow.Controls.Add(_pathBox, 1, 0);
            _browseBtn.Text = L("찾아보기…", "Browse…"); _browseBtn.AutoSize = true;
            _browseBtn.Click += (s, e) => BrowseInstallPath();
            pathRow.Controls.Add(_browseBtn, 2, 0);
            AddSpanning(t, pathRow);
            AddSpanning(t, new Label
            {
                AutoSize = true, ForeColor = SystemColors.GrayText, Margin = new Padding(23, 0, 3, 4),
                Text = L("비워 두면 런처가 기록한 설치 경로를 찾고, 없으면 드라이브를 탐색합니다 (수 분 걸릴 수 있음)",
                         "Leave empty to use the path the launcher recorded, or search the drives (can take minutes)"),
            });

            AddItem(t, CheckId.Autostart,  L("8. 자동 실행 프로그램  (9/27 이후 생긴 서명 없는 프로그램 — PC 전체를 보려면 UAC, 읽기만 함, 판정에 영향 없음)",
                                             "8. Autostart programs  (unsigned, new since 9/27 - UAC to read PC-wide entries, read-only, no effect on the verdict)"));
            AddItem(t, CheckId.Extra,      L("9. 추가 보안 점검  (해커 서버 연결·DNS 기록, 브라우저 원격 조종·강제 확장, Defender 제외, 원격 접속 프로그램, 프록시, Winlogon·IFEO·AppInit)",
                                             "9. Extra checks  (hacker server connections, DNS, browser remote control / forced extensions, Defender exclusions, remote-access apps, proxy, Winlogon/IFEO/AppInit)"));
            AddItem(t, CheckId.Protection, L("10. 차단 상태 확인  (hosts 7개 도메인, 방화벽 규칙 내용) ※ 참고용",
                                             "10. Block status  (7 domains in hosts, firewall rule contents) - for reference"));

            // ---- 조치 옵션 ----
            var fixGroup = new GroupBox
            {
                Text = L("조치 옵션 ([조치 실행] 시 적용 — 실행 전에 보고서를 바탕화면에 자동 저장)", "Clean-up options (applied by [Clean up] - the report is saved to the Desktop first)"),
                Dock = DockStyle.Fill, AutoSize = true, Padding = new Padding(8),
            };
            var fixFlow = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false };
            fixGroup.Controls.Add(fixFlow);
            root.Controls.Add(fixGroup);

            SetupOption(_fixBox, L("발견된 악성 항목 제거  (레지스트리 키 → 프로세스 종료 → DLL 폴더, Temp k2f 파일, 에이전트 파일) + 고른 자동 실행 프로그램",
                                   "Remove what was found  (registry key -> end processes -> DLL folder, temp k2f files, agent files) + autostart programs you pick"), true);
            SetupOption(_tbsBox, L("런처 캐시(tbs_cache) 삭제  (흔적이 없어도 런처를 다시 열기 전에 권장)",
                                   "Delete the launcher cache (tbs_cache)  (recommended before opening the launcher again, even with no traces)"), true);
            SetupOption(_blockBox, L($"hosts 도메인 차단 + 방화벽 IP 차단 ({string.Join(", ", Iocs.C2Ips)})  — 관리자 권한(UAC) 필요",
                                     $"Block the domains in hosts + the IPs in the firewall ({string.Join(", ", Iocs.C2Ips)})  - needs administrator rights (UAC)"), true);
            SetupOption(_wdoBox, L("마지막에 Windows Defender 오프라인 검사  (재부팅, 약 15분 — 이름이 알려진 다른 해킹 도구를 찾아 지움)",
                                   "Finally run a Windows Defender offline scan  (restarts the PC, about 15 min - finds and removes other known hacking tools)"), false);
            fixFlow.Controls.AddRange(new Control[] { _fixBox, _tbsBox, _blockBox, _wdoBox });

            // ---- 버튼 ----
            var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, Margin = new Padding(0, 6, 0, 0) };
            root.Controls.Add(buttons);
            SetupButton(_scanBtn, L("점검 시작", "Start check"), async (s, e) => await ScanAsync());
            SetupButton(_fixBtn, L("조치 실행", "Clean up"), async (s, e) => await FixAsync());
            SetupButton(_stopBtn, L("중지", "Stop"), (s, e) => _cts?.Cancel());
            SetupButton(_saveBtn, L("보고서 저장", "Save report"), (s, e) => SaveLogDialog());
            SetupButton(_uninstallBtn, L("니케 완전 삭제…", "Remove NIKKE…"), async (s, e) => await UninstallAsync());
            _scanBtn.Font = new Font(Font, FontStyle.Bold);
            buttons.Controls.AddRange(new Control[] { _scanBtn, _fixBtn, _stopBtn, _saveBtn, _uninstallBtn });
            _progress.Style = ProgressBarStyle.Marquee; _progress.MarqueeAnimationSpeed = 0;
            _progress.Width = 160; _progress.Margin = new Padding(12, 10, 3, 3);
            buttons.Controls.Add(_progress);

            _summary.AutoSize = true; _summary.MaximumSize = new Size(900, 0); _summary.Margin = new Padding(3, 4, 3, 4);
            _summary.Font = new Font(Font.FontFamily, 10F, FontStyle.Bold);
            _summary.Text = L("점검 전", "Not checked yet");
            root.Controls.Add(_summary);

            // ---- 로그 ----
            _logBox.Dock = DockStyle.Fill; _logBox.ReadOnly = true;
            _logBox.BackColor = Color.FromArgb(24, 24, 28); _logBox.ForeColor = Color.Gainsboro;
            _logBox.Font = new Font(UiFont, 9F);
            _logBox.WordWrap = false; _logBox.DetectUrls = false;
            root.Controls.Add(_logBox);

            UpdateButtons();
            Log(L($"NIKKE PC 런처 감염 점검 도구 v{Application.ProductVersion} — {Environment.MachineName} / {Environment.UserName}",
                  $"NIKKE PC Launcher Infection Checker v{Application.ProductVersion} - {Environment.MachineName} / {Environment.UserName}"), LogLevel.Detail);
            if (!Remediator.IsAdmin())
                Log(L("일반 권한으로 실행 중입니다. 관리자 권한이 필요한 작업(PC 전체 자동 실행 점검, hosts·방화벽, Program Files 파일)만 UAC 로 요청합니다.",
                      "Running with normal rights. UAC is requested only for admin tasks (PC-wide autostart check, hosts/firewall, Program Files files)."), LogLevel.Detail);
        }

        private void SwitchLanguage()
        {
            if (Busy) return;
            try
            {
                Process.Start(new ProcessStartInfo(Application.ExecutablePath, "--lang " + (En ? "ko" : "en")) { UseShellExecute = true });
                Close();
            }
            catch { }
        }

        private void AddItem(TableLayoutPanel t, CheckId id, string text)
        {
            var box = new CheckBox { Text = text, Checked = true, AutoSize = true, Margin = new Padding(3, 4, 3, 2) };
            var status = new Label { Text = "", AutoSize = true, Anchor = AnchorStyles.Right, Margin = new Padding(12, 6, 3, 2) };
            t.Controls.Add(box, 0, t.RowCount);
            t.Controls.Add(status, 1, t.RowCount);
            t.RowCount++;
            box.CheckedChanged += (s, e) => UpdateButtons();
            _items.Add(new Item { Id = id, Box = box, Status = status });
        }

        private static void AddSpanning(TableLayoutPanel t, Control c)
        {
            t.Controls.Add(c, 0, t.RowCount);
            t.SetColumnSpan(c, 2);
            t.RowCount++;
        }

        private void SetupOption(CheckBox c, string text, bool on)
        {
            c.Text = text; c.Checked = on; c.AutoSize = true;
            c.CheckedChanged += (s, e) => UpdateButtons();
        }

        private static void SetupButton(Button b, string text, EventHandler onClick)
        {
            b.Text = text; b.AutoSize = true; b.MinimumSize = new Size(100, 32); b.Click += onClick;
        }

        private bool Busy => _cts != null;

        private void UpdateButtons()
        {
            _scanBtn.Enabled = !Busy && _items.Any(i => i.Box.Checked);
            bool hasFix = _last != null && (_last.Fixable.Any() || _last.Review.Any()) && _fixBox.Checked;
            _fixBtn.Enabled = !Busy && _last != null && (hasFix || _tbsBox.Checked || _blockBox.Checked || _wdoBox.Checked);
            _uninstallBtn.Enabled = !Busy && _last != null;
            _stopBtn.Enabled = Busy;
            foreach (var i in _items) i.Box.Enabled = !Busy;
            _fixBox.Enabled = _tbsBox.Enabled = _blockBox.Enabled = _wdoBox.Enabled = !Busy;
            _progress.MarqueeAnimationSpeed = Busy ? 30 : 0;
            bool logsOn = _items.First(i => i.Id == CheckId.InstallLogs).Box.Checked;
            _pathBox.Enabled = _browseBtn.Enabled = logsOn && !Busy;
        }

        private void BrowseInstallPath()
        {
            using (var d = new FolderBrowserDialog { Description = L("NIKKE 설치 폴더(Launcher 폴더가 들어 있는 폴더)를 선택하세요", "Select the NIKKE install folder (the folder that holds the Launcher folder)") })
                if (d.ShowDialog(this) == DialogResult.OK) _pathBox.Text = d.SelectedPath;
        }

        // ------------------------------------------------------------------
        private async Task ScanAsync()
        {
            var opt = new ScanOptions { InstallPath = _pathBox.Text, AuditSystem = () => Remediator.RunAudit(SafeLog) };
            foreach (var i in _items.Where(i => i.Box.Checked)) opt.Checks.Add(i.Id);
            foreach (var i in _items) SetStatus(i, i.Box.Checked ? L("점검 중…", "Checking…") : L("미점검", "Skipped"), Color.Gray);

            _last = null;
            _cts = new CancellationTokenSource();
            UpdateButtons();
            _summary.Text = L("점검 중…", "Checking…"); _summary.ForeColor = SystemColors.ControlText;
            Log("", LogLevel.Info);
            Log(L($"===== 점검 시작 {DateTime.Now:yyyy-MM-dd HH:mm:ss} =====", $"===== Check started {DateTime.Now:yyyy-MM-dd HH:mm:ss} ====="), LogLevel.Header);

            try
            {
                var token = _cts.Token;
                var r = await Task.Run(() => new Scanner(SafeLog, token).Run(opt));
                _last = r;
                if (r.Installs.Count > 0 && string.IsNullOrWhiteSpace(_pathBox.Text)) _pathBox.Text = r.Installs[0];

                foreach (var i in _items.Where(i => opt.Checks.Contains(i.Id)))
                {
                    var w = r.Worst(i.Id);
                    if (w == Severity.Critical && r.Findings.Where(f => f.Check == i.Id && f.Severity == Severity.Critical).All(f => f.Past))
                        SetStatus(i, L("● 과거 기록", "● Past record"), Color.Firebrick);
                    else if (w == Severity.Critical) SetStatus(i, L("● 감염 흔적", "● Infected"), Color.Firebrick);
                    else if (w == Severity.Warning) SetStatus(i, L("▲ 노출 흔적", "▲ Exposed"), Color.DarkOrange);
                    else if (w == Severity.Review)
                    {
                        int n = r.Findings.Count(f => f.Check == i.Id && f.Severity == Severity.Review);
                        bool mal = r.Review.Any(a => a.Defender == "malware");
                        SetStatus(i, L($"◆ 확인 필요 {n}건", $"◆ Check {n}") + (mal ? L(" (악성 포함)", " (malware)") : ""), mal ? Color.Firebrick : Color.DarkOrange);
                    }
                    else if (r.Unknown.ContainsKey(i.Id)) SetStatus(i, L("? 일부 확인 불가", "? Partly unchecked"), Color.DarkGoldenrod);
                    else if (i.Id == CheckId.Protection) SetStatus(i, L("ⓘ 결과 참고", "ⓘ See log"), Color.SteelBlue);
                    else SetStatus(i, L("○ 이상 없음", "○ OK"), Color.SeaGreen);
                }
                ReportVerdict(r);
            }
            catch (OperationCanceledException)
            {
                Log(L("[!] 사용자가 점검을 중지했습니다.", "[!] The check was stopped."), LogLevel.Warn);
                _summary.Text = L("점검 중지됨", "Check stopped"); _summary.ForeColor = Color.DarkOrange;
                foreach (var i in _items.Where(i => i.Status.Text == L("점검 중…", "Checking…"))) SetStatus(i, L("중지됨", "Stopped"), Color.Gray);
            }
            catch (Exception ex)
            {
                Log(L("[X] 점검 중 오류: ", "[X] Error during the check: ") + ex, LogLevel.Bad);
                _summary.Text = L("점검 중 오류 발생", "An error occurred during the check"); _summary.ForeColor = Color.Firebrick;
            }
            finally
            {
                _cts.Dispose(); _cts = null;
                UpdateButtons();
            }
        }

        private void ReportVerdict(ScanResult r)
        {
            int nFix = r.Fixable.Count();
            int nReview = r.Review.Count();
            Log("=================================================", LogLevel.Header);
            switch (r.Verdict)
            {
                case Verdict.Infected:
                    _summary.Text = L($"감염 — 악성 에이전트가 내려받아졌거나 실행된 흔적이 있습니다. (제거 대상 {nFix}건)",
                                      $"INFECTED - the malicious agent was downloaded or ran on this PC. ({nFix} items to remove)");
                    _summary.ForeColor = Color.Firebrick;
                    Log(L("[판정] 감염: 런처가 열려 있는 동안 공격자가 이 PC 에서 명령을 실행할 수 있었습니다.",
                          "[Verdict] INFECTED: while the launcher was open, the attacker could run commands on this PC."), LogLevel.Bad);
                    Guide(new[]
                    {
                        L("1. 지금 런처를 닫고 이 PC 를 네트워크에서 분리하세요.", "1. Close the launcher now and disconnect this PC from the network."),
                        L("2. [조치 실행] 을 누르세요. 보고서가 바탕화면에 먼저 저장된 뒤 레지스트리 키 → 프로세스 → DLL → 런처 캐시 순으로 제거합니다.",
                          "2. Press [Clean up]. The report is saved to the Desktop first, then the registry key, processes, DLL and launcher cache are removed in that order."),
                        L("3. DLL 이 사용 중이라 지워지지 않으면 Windows 를 재시작한 뒤 이 도구로 다시 점검·조치하세요.",
                          "3. If the DLL is in use and cannot be deleted, restart Windows and run this tool again."),
                        L("4. 깨끗한 기기(휴대폰 등)에서 비밀번호 변경: NIKKE/Level Infinite → 구글·네이버·카카오 → 디스코드·스팀 → 은행, 그리고 브라우저에 저장된 모든 비밀번호. 2단계 인증도 켜세요.",
                          "4. From a clean device (e.g. your phone), change passwords: Level Infinite (NIKKE), Google, Discord, Steam, banks, and every password saved in your browsers. Turn on 2-step verification."),
                        L("5. 각 서비스에서 「모든 기기에서 로그아웃」 (탈취된 쿠키는 비밀번호 없이도 쓰일 수 있음). 이 PC 의 브라우저 쿠키도 브라우저 설정에서 삭제하세요.",
                          "5. Use \"Sign out of all devices\" on each service (stolen cookies work without the password). Also clear this PC's browser cookies in the browser settings."),
                        L("6. 이 PC 에 저장된 API 토큰·SSH 키·클라우드 CLI 자격 증명(.ssh, .aws, gh 등)을 폐기하고 재발급하세요.",
                          "6. Revoke and reissue API tokens, SSH keys and cloud CLI credentials stored on this PC (.ssh, .aws, gh, etc.)."),
                        L("7. 암호화폐가 있다면 깨끗한 기기에서 만든 새 시드의 지갑으로 옮기세요.",
                          "7. If you hold cryptocurrency, move it to a wallet with a new seed phrase made on a clean device."),
                        L("8. 레벨 인피니트가 11월 4일 수정을 발표했지만, 공격자가 CDN 에 어떻게 접근했는지는 아직 알려지지 않았습니다. 차단은 유지하고, 런처를 다시 열기 전에 런처 캐시(tbs_cache)를 지우세요. 가장 확실한 방법은 Windows 재설치입니다.",
                          "8. Level Infinite announced a fix on Nov 4, but how the attacker got into the CDN is still unknown. Keep the blocks, and delete the launcher cache (tbs_cache) before opening the launcher again. Reinstalling Windows is the safest fix."),
                        L("9. 다른 Windows 사용자 계정도 이 PC 를 쓴다면, 그 계정으로 로그인해 이 도구를 한 번 더 실행하세요.",
                          "9. If other Windows user accounts use this PC, sign in to each and run this tool again."),
                    });
                    break;
                case Verdict.PastInfection:
                    _summary.Text = L("감염됐던 기록 (과거 기록) — 해킹 프로그램이 전에 이 PC 에서 실행됐습니다. 지금 남은 해킹 파일은 없습니다.",
                                      "PAST INFECTION (records only) - the hacking program ran on this PC before. No hacking files remain now.");
                    _summary.ForeColor = Color.Firebrick;
                    Log(L("[판정] 감염됐던 기록 (과거 기록): 해킹 프로그램이 전에 이 PC 에서 실행됐습니다. 지금 남아 있는 해킹 파일은 없습니다.",
                          "[Verdict] PAST INFECTION (records only): the hacking program ran on this PC before. No hacking files remain now."), LogLevel.Bad);
                    Log(L("       런처 기록 파일(debug.log)에 남은 기록이라 다시 검사해도 계속 나옵니다. 지금 PC 에 해킹 파일이 남아 있다는 뜻은 아닙니다.",
                          "       These stay in the launcher log (debug.log), so they appear on every run. It does not mean hacking files are still on this PC."), LogLevel.Warn);
                    Guide(new[]
                    {
                        L("1. 그때 비밀번호가 빠져나갔을 수 있습니다. 깨끗한 기기에서 비밀번호를 바꾸고 「모든 기기에서 로그아웃」 하세요 (NIKKE/Level Infinite → 구글·네이버·카카오 → 디스코드·스팀 → 은행). 2단계 인증도 켜세요.",
                          "1. Passwords may have been stolen back then. From a clean device change them and sign out of all devices (Level Infinite, Google, Discord, Steam, banks). Turn on 2-step verification."),
                        L("2. 이 PC 에 저장된 API 토큰·SSH 키·클라우드 CLI 자격 증명을 폐기하고 재발급하고, 암호화폐는 새 시드의 지갑으로 옮기세요.",
                          "2. Revoke and reissue API tokens, SSH keys and cloud CLI credentials stored on this PC, and move crypto to a wallet with a new seed phrase."),
                        L("3. [조치 실행] 으로 런처 캐시(tbs_cache) 삭제와 hosts·방화벽 차단을 하세요.", "3. Use [Clean up] to delete the launcher cache (tbs_cache) and block hosts/firewall."),
                        L("4. " + "레벨 인피니트가 11월 4일 수정을 발표했지만, 공격자가 CDN 에 어떻게 접근했는지는 아직 알려지지 않았습니다. 차단은 유지하고, 런처를 다시 열기 전에 런처 캐시(tbs_cache)를 지우세요.", "4. " + "Level Infinite announced a fix on Nov 4, but how the attacker got into the CDN is still unknown. Keep the blocks, and delete the launcher cache (tbs_cache) before opening the launcher again."),
                    });
                    break;
                case Verdict.Exposed:
                    _summary.Text = L("노출 — 런처가 악성 스크립트를 불러왔지만 에이전트 실행 흔적은 없습니다.",
                                      "EXPOSED - the launcher loaded the malicious script, but there is no sign the agent ran.");
                    _summary.ForeColor = Color.DarkOrange;
                    Log(L("[판정] 노출: 악성 로더는 실행됐지만 에이전트가 실행된 흔적은 찾지 못했습니다.",
                          "[Verdict] EXPOSED: the malicious loader ran, but no sign that the agent ran was found."), LogLevel.Warn);
                    Guide(new[]
                    {
                        L("1. 니케 설치 폴더를 찾지 못했다면 경로를 지정해 다시 점검하세요. debug.log 에 에이전트 실행 기록이 있으면 '감염'으로 바뀝니다.",
                          "1. If the NIKKE install folder was not found, enter its path and check again. Agent runs in debug.log change the verdict to INFECTED."),
                        L("2. [조치 실행] 으로 런처 캐시(tbs_cache) 삭제와 hosts·방화벽 차단을 하세요.",
                          "2. Use [Clean up] to delete the launcher cache (tbs_cache) and block hosts/firewall."),
                        L("3. 9월 27일 이후 런처를 연 적이 있다면 감염으로 간주하고 비밀번호 변경·「모든 기기에서 로그아웃」·토큰 폐기를 하세요.",
                          "3. If you opened the launcher on or after Sep 27, treat the PC as infected: change passwords, sign out of all devices and revoke tokens."),
                        L("4. 레벨 인피니트가 11월 4일 수정을 발표했지만, 공격자가 CDN 에 어떻게 접근했는지는 아직 알려지지 않았습니다. 차단은 유지하고, 런처를 다시 열기 전에 런처 캐시(tbs_cache)를 지우세요.",
                          "4. Level Infinite announced a fix on Nov 4, but how the attacker got into the CDN is still unknown. Keep the blocks, and delete the launcher cache (tbs_cache) before opening the launcher again."),
                    });
                    break;
                case Verdict.NotFound:
                    _summary.Text = L("NIKKE 설치 폴더와 런처 데이터를 찾지 못했습니다.", "No NIKKE install folder or launcher data was found.");
                    _summary.ForeColor = Color.DarkGoldenrod;
                    Log(L("[판정] NIKKE 를 찾지 못함: 다른 위치에 설치했다면 설치 경로를 지정해 다시 점검하세요.",
                          "[Verdict] NIKKE not found: if it is installed elsewhere, enter the install path and check again."), LogLevel.Warn);
                    Log(L("       런처를 이미 지웠다면 지난 실행 기록도 함께 지워져, 그동안 감염됐었는지는 알 수 없습니다.",
                          "       If you already deleted the launcher, its logs are gone too, so a past infection cannot be confirmed."), LogLevel.Warn);
                    break;
                default:
                    _summary.Text = L("선택한 항목에서 악성 흔적이 발견되지 않았습니다. (흔적이 없다고 깨끗함이 보장되지는 않습니다)",
                                      "No known traces were found in the selected checks. (Finding nothing does not prove the PC is clean.)");
                    _summary.ForeColor = Color.SeaGreen;
                    Log(L("[판정] 흔적 없음: 선택한 항목에서 악성 흔적을 찾지 못했습니다.", "[Verdict] No known traces in the selected checks."), LogLevel.Ok);
                    Guide(new[]
                    {
                        L("1. 런처를 다시 열기 전에 런처 캐시(tbs_cache)를 삭제하고 hosts·방화벽 차단을 하세요 ([조치 실행]).",
                          "1. Before opening the launcher again, delete the launcher cache (tbs_cache) and block hosts/firewall ([Clean up])."),
                        L("2. 9월 27일 이후 런처를 연 적이 있다면 중요한 비밀번호는 바꿔 두는 게 안전합니다 (10월 23일 이후라면 특히).",
                          "2. If you used the launcher after Sep 27, changing important passwords is the safe choice (especially after Oct 23)."),
                        L("3. 레벨 인피니트가 11월 4일 수정을 발표했지만, 공격자가 CDN 에 어떻게 접근했는지는 아직 알려지지 않았습니다. 차단은 유지하고, 런처를 다시 열기 전에 런처 캐시(tbs_cache)를 지우세요.",
                          "3. Level Infinite announced a fix on Nov 4, but how the attacker got into the CDN is still unknown. Keep the blocks, and delete the launcher cache (tbs_cache) before opening the launcher again."),
                    });
                    break;
            }
            if (nReview > 0)
            {
                Log(L($"[확인 필요] 9월 27일 이후 생긴 서명 없는 자동 실행 프로그램 {nReview}개 — 해커가 따로 깔았을 수 있습니다. 직접 설치한 것이면 괜찮습니다.",
                      $"[Check] {nReview} unsigned autostart programs new since Sep 27 - the hacker may have installed them. Programs you installed yourself are fine."), LogLevel.Warn);
                Log(L("       [조치 실행] 에서 하나씩 골라 지울 수 있습니다. 직접 설치하지 않은 게 있으면 Windows 재설치를 권합니다.",
                      "       You can pick which ones to delete in [Clean up]. If any was not installed by you, reinstalling Windows is recommended."), LogLevel.Warn);
            }
            if (nFix > 0) Log(L($"[조치 대상] {nFix}건 — [조치 실행] 으로 제거할 수 있습니다.", $"[To remove] {nFix} items - press [Clean up] to remove them."), LogLevel.Info);
            if (r.Unreadable.Count > 0)
            {
                Log(L($"[참고] 읽지 못해 검사가 불완전한 파일 {r.Unreadable.Count}개 (최대 50개 표시):", $"[Note] Files that could not be fully checked: {r.Unreadable.Count} (up to 50 shown):"), LogLevel.Warn);
                foreach (var u in r.Unreadable.Distinct().Take(50)) Log("        " + u, LogLevel.Detail);
            }
        }

        private void Guide(IEnumerable<string> lines)
        {
            Log(L("[해야 할 일]", "[What to do]"), LogLevel.Header);
            foreach (var l in lines) Log("  " + l, LogLevel.Info);
        }

        private async Task FixAsync()
        {
            var opt = new FixOptions
            {
                DeleteFindings = _fixBox.Checked, AlwaysDeleteTbsCache = _tbsBox.Checked,
                Block = _blockBox.Checked,
            };
            var fixes = opt.DeleteFindings && _last != null ? _last.Fixable.ToList() : new List<Finding>();
            var review = opt.DeleteFindings && _last != null ? _last.Review.ToList() : new List<AutostartItem>();
            bool wdo = _wdoBox.Checked;

            var plan = new StringBuilder(L("다음 작업을 실행합니다:\n\n", "The following will be done:\n\n"));
            foreach (var d in fixes.Select(f => f.FixDescription).Distinct().Take(25)) plan.AppendLine("• " + d);
            if (fixes.Count > 25) plan.AppendLine(L($"• … 외 {fixes.Count - 25}건", $"• … {fixes.Count - 25} more"));
            if (opt.AlwaysDeleteTbsCache) plan.AppendLine(L("• 런처 캐시(tbs_cache) 삭제", "• Delete the launcher cache (tbs_cache)"));
            if (fixes.Any(f => f.Browser != null)) plan.AppendLine(L("• 관련 브라우저 강제 종료", "• Close the affected browsers"));
            if (fixes.Count > 0 || opt.AlwaysDeleteTbsCache) plan.AppendLine(L("• NIKKE 런처 강제 종료", "• Close the NIKKE launcher"));
            if (review.Count > 0) plan.AppendLine(L($"• 「확인 필요」 자동 실행 프로그램 {review.Count}개 — 다음 창에서 지울 것을 직접 고릅니다",
                                                    $"• {review.Count} autostart programs to check - you pick which to delete in the next window"));
            if (opt.Block) plan.AppendLine(L($"• hosts 도메인 차단, 방화벽 IP 차단 ({string.Join(", ", Iocs.C2Ips)}) — UAC 요청",
                                             $"• Block the domains in hosts and the IPs in the firewall ({string.Join(", ", Iocs.C2Ips)}) - UAC prompt"));
            if (wdo) plan.AppendLine(L("• 마지막에 Windows Defender 오프라인 검사 (재부팅 전에 한 번 더 묻습니다)", "• Finally, a Windows Defender offline scan (you are asked again before the restart)"));
            plan.AppendLine(L("\n실행 전에 현재 보고서를 바탕화면에 저장합니다 (삭제하면 증거가 사라지므로).", "\nThe current report is saved to the Desktop first (deleting removes the evidence)."));
            plan.AppendLine(L("브라우저에서 작업 중인 내용이 있다면 먼저 저장해 주세요. 계속할까요?", "Save any work open in your browsers first. Continue?"));
            if (MessageBox.Show(this, plan.ToString(), L("조치 확인", "Confirm clean-up"), MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;

            if (review.Count > 0)
            {
                using (var dlg = new ReviewDialog(review, Font))
                {
                    if (dlg.ShowDialog(this) != DialogResult.OK) return;
                    opt.RemoveAutostart = dlg.Selected;
                }
            }

            var report = SaveReport(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), ReportName()));
            if (report == null)
            {
                // 증거가 남지 않은 채로 지우지 않는다
                Log(L("[X] 보고서를 저장하지 못해 아무것도 바꾸지 않았습니다. 바탕화면 공간·권한을 확인한 뒤 다시 시도하세요.",
                      "[X] Could not save the report, so nothing was changed. Check Desktop space/permissions and try again."), LogLevel.Bad);
                MessageBox.Show(this, L("보고서를 저장하지 못해 조치를 취소했습니다.\n\n바탕화면의 공간과 권한을 확인한 뒤 다시 시도해 주세요.",
                                        "The report could not be saved, so the clean-up was canceled.\n\nCheck Desktop space and permissions, then try again."),
                                L("조치 취소", "Clean-up canceled"), MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            Log(L($"[+] 조치 전 보고서 저장: {report}", $"[+] Report saved before clean-up: {report}"), LogLevel.Action);
            foreach (var a in opt.RemoveAutostart)
                Log(L($"    삭제하기로 고른 자동 실행 항목: [{a.Where}] {a.Name} — {a.Display}", $"    Autostart item chosen for deletion: [{a.Where}] {a.Name} - {a.Display}"), LogLevel.Detail);

            _cts = new CancellationTokenSource();
            UpdateButtons();
            Log("", LogLevel.Info);
            Log(L($"===== 조치 시작 {DateTime.Now:yyyy-MM-dd HH:mm:ss} =====", $"===== Clean-up started {DateTime.Now:yyyy-MM-dd HH:mm:ss} ====="), LogLevel.Header);
            FixOutcome outcome;
            try { outcome = await Task.Run(() => Remediator.Fix(fixes, opt, SafeLog)); }
            catch (Exception ex) { outcome = new FixOutcome { Failed = 1 }; Log(L("[X] 조치 중 오류: ", "[X] Error during clean-up: ") + ex, LogLevel.Bad); }
            finally { _cts.Dispose(); _cts = null; }

            Log("=================================================", LogLevel.Header);
            string msg;
            if (outcome.NeedsReboot)
            {
                Log(L("[재시작 필요] 사용 중인 파일이 있어 일부를 지우지 못했습니다. 레지스트리 키는 제거됐으므로 Windows 를 재시작한 뒤 이 도구로 다시 점검·조치하세요.",
                      "[Restart needed] Some files are in use and could not be deleted. The registry key is gone, so restart Windows and run this tool again."), LogLevel.Bad);
                _summary.Text = L("Windows 재시작 후 다시 점검·조치가 필요합니다.", "Restart Windows, then check and clean up again."); _summary.ForeColor = Color.Firebrick;
                msg = L("사용 중인 파일이 있어 일부를 지우지 못했습니다.\n\nWindows 를 재시작한 뒤 이 도구를 다시 실행해 점검·조치해 주세요.",
                        "Some files are in use and could not be deleted.\n\nRestart Windows, then run this tool again.");
            }
            else if (outcome.Failed > 0)
            {
                Log(L($"[주의] {outcome.Failed}건이 실패했습니다. PC 재시작 후 다시 점검·조치해 주세요.", $"[Note] {outcome.Failed} tasks failed. Restart the PC and run the tool again."), LogLevel.Bad);
                _summary.Text = L($"{outcome.Failed}건 실패 — 재시작 후 다시 시도하세요.", $"{outcome.Failed} failed - restart and try again."); _summary.ForeColor = Color.Firebrick;
                msg = L($"{outcome.Failed}건의 작업이 실패했습니다. 재시작 후 다시 시도해 주세요.", $"{outcome.Failed} tasks failed. Restart the PC and try again.");
            }
            else
            {
                Log(L("[완료] 조치가 끝났습니다. [점검 시작] 으로 다시 점검해 결과를 확인하세요.", "[Done] Clean-up finished. Press [Start check] to check again."), LogLevel.Ok);
                _summary.Text = L("조치 완료 — 다시 점검하여 확인하세요.", "Clean-up done - check again to confirm."); _summary.ForeColor = Color.SeaGreen;
                msg = L("조치가 완료되었습니다. 다시 점검하여 결과를 확인하세요.", "Clean-up finished. Check again to confirm the result.");
            }
            if (fixes.Any(f => f.Severity == Severity.Critical))
                msg += L("\n\n감염 흔적이 있었으므로 깨끗한 기기에서 모든 계정의 비밀번호 변경과 「모든 기기에서 로그아웃」을 해 주세요.",
                         "\n\nInfection traces were found, so from a clean device change all your passwords and sign out of all devices.");
            _last = null; // 조치 후에는 재점검을 거쳐야 다시 조치 가능
            UpdateButtons();
            SaveReport(report);   // 조치 결과까지 담아 같은 보고서를 갱신
            MessageBox.Show(this, msg, L("조치 결과", "Clean-up result"), MessageBoxButtons.OK, outcome.Failed == 0 ? MessageBoxIcon.Information : MessageBoxIcon.Warning);

            if (wdo) await OfferOfflineScanAsync(report);
        }

        /// <summary>
        /// NIKKE 완전 삭제 (선택, 두 번 동의 — 햄찌 v4.4·v4.5). 니케를 계속 할 사람은 쓰지 않는다.
        /// 계정·진행 상황은 니케 서버에 있어 지워지지 않는다. 런처가 깔아 둔 실행 파일은 실행하지 않는다.
        /// </summary>
        private async Task UninstallAsync()
        {
            var q1 = L("니케를 계속 하실 분은 [아니요]를 누르세요. 게임은 그대로 둡니다.\n\n" +
                       "니케를 이 PC 에서 완전히 삭제하실 분만 [예]를 누르세요. 다음을 지웁니다:\n" +
                       "  • 설치 폴더 (게임·런처, 실행 파일 포함)\n  • 런처 데이터 폴더 (AppData\\Roaming\\nikke_launcher…)\n" +
                       "  • 게임 데이터 폴더 (AppData\\LocalLow, 약 5GB)\n  • 내려받은 설치 파일 (nikkeminiloader…exe)\n" +
                       "  • 레지스트리: 「설치된 앱」 항목, nikkelauncher:// 연결, 게임 설정\n  • 바로가기 (바탕 화면·시작 메뉴)\n\n" +
                       "계정과 게임 진행은 니케 서버에 있어 지워지지 않습니다. [예]를 누르면 지울 목록을 보여 주고 한 번 더 묻습니다.",
                       "Keep playing NIKKE? Press [No]. The game is left as it is.\n\n" +
                       "Only if you want NIKKE removed from this PC completely, press [Yes]. It deletes:\n" +
                       "  • install folder (game + launcher, executables included)\n  • launcher data folder (AppData\\Roaming\\nikke_launcher...)\n" +
                       "  • game data folder (AppData\\LocalLow, about 5 GB)\n  • downloaded installer (nikkeminiloader...exe)\n" +
                       "  • registry: Installed apps entry, nikkelauncher:// link, game settings\n  • shortcuts (Desktop, Start menu)\n\n" +
                       "Your account and game progress stay on the NIKKE servers. [Yes] shows the list and asks once more.");
            if (MessageBox.Show(this, q1, L("니케 완전 삭제 (선택)", "Remove NIKKE completely (optional)"), MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
            {
                Log(L("[-] 니케는 그대로 둡니다.", "[-] NIKKE is left as it is."), LogLevel.Detail);
                return;
            }
            var installs = _last?.Installs.ToList() ?? new List<string>();
            if (installs.Count == 0 && !string.IsNullOrWhiteSpace(_pathBox.Text) && InstallLocator.IsInstall(_pathBox.Text.Trim().Trim('"'))) installs.Add(_pathBox.Text.Trim().Trim('"'));
            var plan = await Task.Run(() => Uninstaller.Plan(installs));
            if (plan.Count == 0)
            {
                MessageBox.Show(this, L("지울 니케 파일·등록이 없습니다.", "Nothing of NIKKE is left to remove."), L("니케 완전 삭제", "Remove NIKKE"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            var list = new StringBuilder(L("지울 항목:\n\n", "To be removed:\n\n"));
            foreach (var f in plan.Folders) list.AppendLine("• " + f);
            foreach (var f in plan.Files) list.AppendLine(L("• 설치 파일: ", "• installer: ") + f);
            if (plan.Links.Count > 0) list.AppendLine(L($"• 바로가기 {plan.Links.Count}개 (바탕 화면·시작 메뉴)", $"• {plan.Links.Count} shortcut(s) (Desktop, Start menu)"));
            foreach (var k in plan.UserKeys) list.AppendLine(L("• 레지스트리: HKCU\\", "• registry: HKCU\\") + k);
            foreach (var k in plan.MachineKeys) list.AppendLine(L("• 레지스트리: HKLM\\", "• registry: HKLM\\") + k.Substring(3));
            list.AppendLine(L("\n지운 뒤에는 되돌릴 수 없습니다. 정말 삭제할까요?", "\nThis cannot be undone. Really delete all of it?"));
            if (MessageBox.Show(this, list.ToString(), L("니케 완전 삭제 — 마지막 확인", "Remove NIKKE - final confirmation"), MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
            {
                Log(L("[-] 니케는 그대로 둡니다.", "[-] NIKKE is left as it is."), LogLevel.Detail);
                return;
            }
            var report = SaveReport(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), ReportName()));
            if (report == null) { Log(L("[X] 보고서를 저장하지 못해 아무것도 지우지 않았습니다.", "[X] Could not save the report, so nothing was deleted."), LogLevel.Bad); return; }

            _cts = new CancellationTokenSource(); UpdateButtons();
            Log("", LogLevel.Info);
            Log(L($"===== 니케 완전 삭제 (사용자 선택) {DateTime.Now:yyyy-MM-dd HH:mm:ss} =====", $"===== Remove NIKKE (user choice) {DateTime.Now:yyyy-MM-dd HH:mm:ss} ====="), LogLevel.Header);
            int failed = 0;
            try
            {
                failed = await Task.Run(() =>
                {
                    int fl = Uninstaller.Execute(plan, SafeLog, out var elevated);
                    if (elevated.Count > 0) fl += Remediator.RunElevated(elevated, SafeLog, out _);
                    return fl;
                });
            }
            finally { _cts.Dispose(); _cts = null; UpdateButtons(); }
            if (failed > 0)
                Log(L("[주의] 일부 삭제 실패. PC 를 재시작한 뒤 다시 실행하세요.", "[Note] Some items could not be removed. Restart the PC and run again."), LogLevel.Bad);
            else
                Log(L("[완료] 니케 삭제 완료. 재설치는 공식 홈페이지에서 런처를 새로 받으세요.", "[Done] NIKKE removed. To reinstall, get a new launcher from the official website."), LogLevel.Ok);
            SaveReport(report);
        }

        /// <summary>Defender 오프라인 검사: 재부팅이 필요하므로 한 번 더 묻는다. 24시간 안에 이미 했으면 건너뜀.</summary>
        private async Task OfferOfflineScanAsync(string report)
        {
            try
            {
                if (File.Exists(WdoMarker) && (DateTime.Now - File.GetLastWriteTime(WdoMarker)).TotalHours < 24)
                {
                    Log(L("[-] Windows Defender 오프라인 검사는 최근 24시간 안에 이미 해서 건너뜁니다.", "[-] Skipping the Windows Defender offline scan (already done in the last 24 hours)."), LogLevel.Detail);
                    return;
                }
            }
            catch { }
            var q = L("Windows Defender 오프라인 검사로 PC 전체를 한 번 더 검사합니다. 이름이 알려진 다른 해킹 도구를 찾아 지웁니다.\n\n" +
                      "이 검사는 Windows 가 꺼진 상태에서 해야 해서 재부팅이 필요합니다. 재부팅하면 검사 화면이 자동으로 뜨고, 약 15분 뒤 Windows 로 돌아옵니다.\n\n" +
                      "저장하지 않은 작업이 있으면 먼저 저장하세요. 지금 재부팅해서 검사할까요?",
                      "The Windows Defender offline scan checks the whole PC once more and removes other known hacking tools.\n\n" +
                      "It runs while Windows is not running, so the PC must restart. The scan screen appears by itself, and Windows starts again after about 15 minutes.\n\n" +
                      "Save any unsaved work first. Restart now for the scan?");
            if (MessageBox.Show(this, q, L("Defender 오프라인 검사", "Defender offline scan"), MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
            {
                Log(L("[-] 오프라인 검사를 하지 않았습니다. 나중에 하려면 다시 실행해 이 옵션으로 조치하세요.", "[-] Offline scan not started. To do it later, run the tool again with this option."), LogLevel.Detail);
                return;
            }
            var lines = new List<string>();
            Logger capture = (m, l) => { lines.Add(m); SafeLog(m, l); };
            _cts = new CancellationTokenSource(); UpdateButtons();
            try { await Task.Run(() => Remediator.RunElevated(new List<string> { "WDO" }, capture, out _)); }
            finally { _cts.Dispose(); _cts = null; UpdateButtons(); }
            if (lines.Any(l => l.Contains("[WDO] started")))
            {
                try { Directory.CreateDirectory(Path.GetDirectoryName(WdoMarker)); File.WriteAllText(WdoMarker, DateTime.Now.ToString("s")); } catch { }
            }
            SaveReport(report);
        }

        private static string ReportName() => L("NikkeChecker_보고서_", "NikkeChecker_report_") + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".txt";

        private static void SetStatus(Item i, string text, Color color) { i.Status.Text = text; i.Status.ForeColor = color; }

        // ------------------------------------------------------------------
        private void SafeLog(string msg, LogLevel level)
        {
            if (IsDisposed) return;
            if (InvokeRequired) { try { BeginInvoke(new Action(() => Log(msg, level))); } catch { } }
            else Log(msg, level);
        }

        private void Log(string msg, LogLevel level)
        {
            Color c;
            switch (level)
            {
                case LogLevel.Header: c = Color.DeepSkyBlue; break;
                case LogLevel.Ok: c = Color.FromArgb(140, 200, 140); break;
                case LogLevel.Warn: c = Color.Gold; break;
                case LogLevel.Bad: c = Color.FromArgb(255, 105, 97); break;
                case LogLevel.Action: c = Color.Aquamarine; break;
                case LogLevel.Detail: c = Color.Gray; break;
                default: c = Color.Gainsboro; break;
            }
            _logBox.SelectionStart = _logBox.TextLength;
            _logBox.SelectionLength = 0;
            _logBox.SelectionColor = c;
            _logBox.AppendText(msg + Environment.NewLine);
            _logBox.ScrollToCaret();
        }

        private string SaveReport(string path)
        {
            var text = _logBox.Text.Replace("\r\n", "\n").Replace("\n", "\r\n");
            // 바탕화면에 못 쓰면 사용자 폴더에 저장
            foreach (var p in new[] { path, Path.Combine(Iocs.UserProfile, Path.GetFileName(path)) })
            {
                try { File.WriteAllText(p, text, new UTF8Encoding(true)); return p; }
                catch (Exception ex) { Log(L($"[X] 보고서 저장 실패 ({p}): {ex.Message}", $"[X] Could not save the report ({p}): {ex.Message}"), LogLevel.Bad); }
            }
            return null;
        }

        private void SaveLogDialog()
        {
            using (var d = new SaveFileDialog
            {
                Filter = L("텍스트 파일 (*.txt)|*.txt", "Text files (*.txt)|*.txt"),
                FileName = ReportName(),
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            })
            {
                if (d.ShowDialog(this) == DialogResult.OK) SaveReport(d.FileName);
            }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (Busy && MessageBox.Show(this, L("작업이 진행 중입니다. 종료할까요?", "A task is running. Close anyway?"), L("확인", "Confirm"), MessageBoxButtons.YesNo) != DialogResult.Yes)
            { e.Cancel = true; return; }
            _cts?.Cancel();
            base.OnFormClosing(e);
        }
    }

    /// <summary>「확인 필요」 자동 실행 프로그램 중 지울 것을 고르는 창. Defender 가 악성으로 확인한 것만 미리 체크된다.</summary>
    internal sealed class ReviewDialog : Form
    {
        private readonly CheckedListBox _list = new CheckedListBox();
        private readonly List<AutostartItem> _items;

        public List<AutostartItem> Selected => _list.CheckedIndices.Cast<int>().Select(i => _items[i]).ToList();

        public ReviewDialog(List<AutostartItem> items, Font font)
        {
            _items = items;
            Text = L("확인이 필요한 자동 실행 프로그램", "Autostart programs to check");
            Font = font;
            ClientSize = new Size(900, 460);
            MinimumSize = new Size(640, 360);
            StartPosition = FormStartPosition.CenterParent;
            MinimizeBox = MaximizeBox = false;

            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new Padding(10) };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            Controls.Add(root);

            root.Controls.Add(new Label
            {
                AutoSize = true, MaximumSize = new Size(860, 0), Margin = new Padding(3, 0, 3, 8),
                Text = L("9월 27일 이후 새로 생긴, 제작사 서명이 없는 자동 실행 프로그램입니다. 해커가 따로 깔았을 수 있습니다.\n" +
                         "직접 설치한 게 아닌 것만 체크하세요. Defender 가 악성으로 확인한 것은 미리 체크되어 있습니다.\n" +
                         "체크한 항목은 자동 실행 등록을 끊고 실행되던 파일도 지웁니다 (Windows 폴더 안 파일은 등록만 끊음).",
                         "These autostart programs are new since Sep 27 and have no publisher signature. The hacker may have installed them.\n" +
                         "Check only the ones you did NOT install. Items Defender confirmed as malware are checked already.\n" +
                         "Checked items are unregistered and their files deleted (files inside the Windows folder are only unregistered)."),
            });

            _list.Dock = DockStyle.Fill; _list.CheckOnClick = true; _list.HorizontalScrollbar = true; _list.IntegralHeight = false;
            foreach (var it in items)
            {
                var tag = it.Hidden ? L("위험 높음: 숨겨진 명령", "HIGH RISK: hidden command") : Defender.VerdictText(it.Defender);
                _list.Items.Add($"[{it.Where}] {it.Name}  —  {it.Display}  ({L("생긴 날", "created")} {it.Date})  [{tag}]", it.Defender == "malware");
            }
            root.Controls.Add(_list);

            var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, FlowDirection = FlowDirection.RightToLeft };
            var cancel = new Button { Text = L("조치 취소", "Cancel clean-up"), AutoSize = true, MinimumSize = new Size(100, 30), DialogResult = DialogResult.Cancel };
            var ok = new Button { Text = L("계속 (체크한 것만 삭제)", "Continue (delete checked only)"), AutoSize = true, MinimumSize = new Size(160, 30), DialogResult = DialogResult.OK };
            buttons.Controls.AddRange(new Control[] { cancel, ok });
            root.Controls.Add(buttons);
            AcceptButton = ok; CancelButton = cancel;
        }
    }
}
