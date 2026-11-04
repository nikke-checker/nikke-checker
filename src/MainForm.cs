using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

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
        private readonly CheckBox _cookieBox = new CheckBox();
        private readonly Button _scanBtn = new Button();
        private readonly Button _fixBtn = new Button();
        private readonly Button _stopBtn = new Button();
        private readonly Button _saveBtn = new Button();
        private readonly RichTextBox _logBox = new RichTextBox();
        private readonly ProgressBar _progress = new ProgressBar();
        private readonly Label _summary = new Label();

        private CancellationTokenSource _cts;
        private ScanResult _last;

        public MainForm()
        {
            Text = "NIKKE PC 런처 감염 점검 도구 v" + Application.ProductVersion;
            Font = new Font("Malgun Gothic", 9F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(920, 860);
            MinimumSize = new Size(760, 700);
            StartPosition = FormStartPosition.CenterScreen;
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new Padding(10) };
            for (int i = 0; i < 5; i++) root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            Controls.Add(root);

            root.Controls.Add(new Label
            {
                AutoSize = true, MaximumSize = new Size(880, 0), Margin = new Padding(3, 0, 3, 8),
                Text = "2026년 9월 27일 이후 NIKKE PC 런처를 실행한 적이 있다면 점검하세요. (악성 에이전트는 10월 23일부터 일부 실행 시에 배포됨)\n" +
                       "점검할 항목을 선택하고 [점검 시작]을 누르세요. 점검은 아무것도 바꾸지 않습니다.",
            });

            // ---- 점검 항목 ----
            var checkGroup = new GroupBox { Text = "점검 항목", Dock = DockStyle.Fill, AutoSize = true, Padding = new Padding(8) };
            var t = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 2 };
            t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            checkGroup.Controls.Add(t);
            root.Controls.Add(checkGroup);

            AddItem(t, CheckId.BrowserDll,   "1. 브라우저 지속성 DLL  (PlatformExperienceHelper\\<64자리>, 구버전 Chrome 파일 포함)");
            AddItem(t, CheckId.Clsid,        "2. 레지스트리 CLSID 하이재킹  (" + Iocs.BadClsid + ", WOW6432Node, 빈 잔여 키 포함)");
            AddItem(t, CheckId.Processes,    "3. 실행 중 프로세스  (런처 실행 여부, 악성 DLL 이 로드된 프로그램)");
            AddItem(t, CheckId.LauncherData, "4. 런처 데이터  (k2f.agent, 악성 스크립트 캐시, HSTS·네트워크 접속 기록)");
            AddItem(t, CheckId.Temp,         "5. 임시 폴더  (k2f-bcreds-* 탈취 자격 증명, k2f_screen_* 화면 캡처)");
            AddItem(t, CheckId.InstallLogs,  "6. 니케 설치 폴더  (debug.log 실행 기록, tinyget 다운로드 기록, 저장된 에이전트 파일)");

            var pathRow = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 3, Margin = new Padding(20, 0, 0, 0) };
            pathRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            pathRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            pathRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            pathRow.Controls.Add(new Label { Text = "니케 설치 경로:", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 7, 3, 3) }, 0, 0);
            _pathBox.Dock = DockStyle.Fill;
            pathRow.Controls.Add(_pathBox, 1, 0);
            _browseBtn.Text = "찾아보기…"; _browseBtn.AutoSize = true;
            _browseBtn.Click += (s, e) => BrowseInstallPath();
            pathRow.Controls.Add(_browseBtn, 2, 0);
            AddSpanning(t, pathRow);
            AddSpanning(t, new Label
            {
                AutoSize = true, ForeColor = SystemColors.GrayText, Margin = new Padding(23, 0, 3, 4),
                Text = "비워 두면 런처가 기록한 설치 경로를 찾고, 없으면 드라이브를 탐색합니다 (수 분 걸릴 수 있음)",
            });

            AddItem(t, CheckId.Exposure,   "7. 유출 가능 데이터 확인  (저장된 비밀번호, 지갑 확장, 인증 파일 — 파일을 열지 않음) ※ 참고용");
            AddItem(t, CheckId.Protection, "8. 차단 상태 확인  (hosts, 방화벽) ※ 참고용");
            _items.First(i => i.Id == CheckId.InstallLogs).Box.CheckedChanged += (s, e) => UpdateButtons();

            // ---- 조치 옵션 ----
            var fixGroup = new GroupBox { Text = "조치 옵션 ([조치 실행] 시 적용 — 실행 전에 보고서를 바탕화면에 자동 저장)", Dock = DockStyle.Fill, AutoSize = true, Padding = new Padding(8) };
            var fixFlow = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false };
            fixGroup.Controls.Add(fixFlow);
            root.Controls.Add(fixGroup);

            SetupOption(_fixBox, "발견된 악성 항목 제거  (레지스트리 키 → 프로세스 종료 → DLL 폴더, Temp k2f 파일, 에이전트 파일)", true);
            SetupOption(_tbsBox, "런처 캐시(tbs_cache) 삭제  (흔적이 없어도 런처를 다시 열기 전에 권장)", true);
            SetupOption(_blockBox, $"hosts 도메인 차단 + 방화벽 IP 차단 ({string.Join(", ", Iocs.C2Ips)})  — 관리자 권한(UAC) 필요", true);
            SetupOption(_cookieBox, "브라우저 쿠키 초기화  (모든 브라우저 강제 종료, 모든 사이트 로그아웃)", false);
            fixFlow.Controls.AddRange(new Control[] { _fixBox, _tbsBox, _blockBox, _cookieBox });

            // ---- 버튼 ----
            var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, Margin = new Padding(0, 6, 0, 0) };
            root.Controls.Add(buttons);
            SetupButton(_scanBtn, "점검 시작", async (s, e) => await ScanAsync());
            SetupButton(_fixBtn, "조치 실행", async (s, e) => await FixAsync());
            SetupButton(_stopBtn, "중지", (s, e) => _cts?.Cancel());
            SetupButton(_saveBtn, "보고서 저장", (s, e) => SaveLogDialog());
            _scanBtn.Font = new Font(Font, FontStyle.Bold);
            buttons.Controls.AddRange(new Control[] { _scanBtn, _fixBtn, _stopBtn, _saveBtn });
            _progress.Style = ProgressBarStyle.Marquee; _progress.MarqueeAnimationSpeed = 0;
            _progress.Width = 160; _progress.Margin = new Padding(12, 10, 3, 3);
            buttons.Controls.Add(_progress);

            _summary.AutoSize = true; _summary.MaximumSize = new Size(880, 0); _summary.Margin = new Padding(3, 4, 3, 4);
            _summary.Font = new Font(Font.FontFamily, 10F, FontStyle.Bold);
            _summary.Text = "점검 전";
            root.Controls.Add(_summary);

            // ---- 로그 ----
            _logBox.Dock = DockStyle.Fill; _logBox.ReadOnly = true;
            _logBox.BackColor = Color.FromArgb(24, 24, 28); _logBox.ForeColor = Color.Gainsboro;
            _logBox.Font = new Font("Malgun Gothic", 9F);
            _logBox.WordWrap = false; _logBox.DetectUrls = false;
            root.Controls.Add(_logBox);

            UpdateButtons();
            Log($"NIKKE PC 런처 감염 점검 도구 v{Application.ProductVersion} — {Environment.MachineName} / {Environment.UserName}", LogLevel.Detail);
            if (!Remediator.IsAdmin())
                Log("일반 권한으로 실행 중입니다. 관리자 작업(hosts·방화벽, Program Files 파일)은 조치할 때만 UAC 로 요청합니다.", LogLevel.Detail);
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
            bool hasFix = _last != null && _last.Fixable.Any() && _fixBox.Checked;
            _fixBtn.Enabled = !Busy && _last != null && (hasFix || _tbsBox.Checked || _blockBox.Checked || _cookieBox.Checked);
            _stopBtn.Enabled = Busy;
            foreach (var i in _items) i.Box.Enabled = !Busy;
            _fixBox.Enabled = _tbsBox.Enabled = _blockBox.Enabled = _cookieBox.Enabled = !Busy;
            _progress.MarqueeAnimationSpeed = Busy ? 30 : 0;
            bool logsOn = _items.First(i => i.Id == CheckId.InstallLogs).Box.Checked;
            _pathBox.Enabled = _browseBtn.Enabled = logsOn && !Busy;
        }

        private void BrowseInstallPath()
        {
            using (var d = new FolderBrowserDialog { Description = "NIKKE 설치 폴더(Launcher 폴더가 들어 있는 폴더)를 선택하세요" })
                if (d.ShowDialog(this) == DialogResult.OK) _pathBox.Text = d.SelectedPath;
        }

        // ------------------------------------------------------------------
        private async Task ScanAsync()
        {
            var opt = new ScanOptions { InstallPath = _pathBox.Text };
            foreach (var i in _items.Where(i => i.Box.Checked)) opt.Checks.Add(i.Id);
            foreach (var i in _items) SetStatus(i, i.Box.Checked ? "점검 중…" : "미점검", Color.Gray);

            _last = null;
            _cts = new CancellationTokenSource();
            UpdateButtons();
            _summary.Text = "점검 중…"; _summary.ForeColor = SystemColors.ControlText;
            Log("", LogLevel.Info);
            Log($"===== 점검 시작 {DateTime.Now:yyyy-MM-dd HH:mm:ss} =====", LogLevel.Header);

            try
            {
                var token = _cts.Token;
                var r = await Task.Run(() => new Scanner(SafeLog, token).Run(opt));
                _last = r;
                if (r.Installs.Count > 0 && string.IsNullOrWhiteSpace(_pathBox.Text)) _pathBox.Text = r.Installs[0];

                foreach (var i in _items.Where(i => opt.Checks.Contains(i.Id)))
                {
                    var w = r.Worst(i.Id);
                    if (w == Severity.Critical) SetStatus(i, "● 감염 흔적", Color.Firebrick);
                    else if (w == Severity.Warning) SetStatus(i, "▲ 노출 흔적", Color.DarkOrange);
                    else if (r.Unknown.ContainsKey(i.Id)) SetStatus(i, "? 확인 불가", Color.DarkGoldenrod);
                    else if (i.Id == CheckId.Exposure || i.Id == CheckId.Protection) SetStatus(i, "ⓘ 결과 참고", Color.SteelBlue);
                    else SetStatus(i, "○ 이상 없음", Color.SeaGreen);
                }
                ReportVerdict(r);
            }
            catch (OperationCanceledException)
            {
                Log("[!] 사용자가 점검을 중지했습니다.", LogLevel.Warn);
                _summary.Text = "점검 중지됨"; _summary.ForeColor = Color.DarkOrange;
                foreach (var i in _items.Where(i => i.Status.Text == "점검 중…")) SetStatus(i, "중지됨", Color.Gray);
            }
            catch (Exception ex)
            {
                Log("[X] 점검 중 오류: " + ex, LogLevel.Bad);
                _summary.Text = "점검 중 오류 발생"; _summary.ForeColor = Color.Firebrick;
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
            Log("=================================================", LogLevel.Header);
            switch (r.Verdict)
            {
                case Verdict.Infected:
                    _summary.Text = $"감염 — 악성 에이전트가 내려받아졌거나 실행된 흔적이 있습니다. (제거 대상 {nFix}건)";
                    _summary.ForeColor = Color.Firebrick;
                    Log("[판정] 감염 (Infected): 런처가 열려 있는 동안 공격자가 이 PC 에서 명령을 실행할 수 있었습니다.", LogLevel.Bad);
                    Guide(new[]
                    {
                        "1. 지금 런처를 닫고 이 PC 를 네트워크에서 분리하세요.",
                        "2. [조치 실행] 을 누르세요. 보고서가 바탕화면에 먼저 저장된 뒤 레지스트리 키 → 프로세스 → DLL → 런처 캐시 순으로 제거합니다.",
                        "3. DLL 이 사용 중이라 지워지지 않으면 Windows 를 재시작한 뒤 이 도구로 다시 점검·조치하세요.",
                        "4. 깨끗한 기기(휴대폰 등)에서 비밀번호 변경: NIKKE/Level Infinite 계정 → 이메일, Discord, 은행, 브라우저에 저장된 모든 비밀번호.",
                        "5. 해당 서비스에서 모든 세션 로그아웃 (탈취된 쿠키는 비밀번호 없이도 쓰일 수 있음).",
                        "6. 이 PC 에 저장된 API 토큰·SSH 키를 폐기하고 재발급하세요 (항목 7 결과 참고).",
                        "7. 암호화폐가 있다면 깨끗한 기기에서 만든 새 시드의 지갑으로 옮기세요.",
                        "8. Level Infinite 가 수정을 확인할 때까지 NIKKE 런처를 열지 마세요. 가장 확실한 방법은 OS 재설치입니다.",
                    });
                    break;
                case Verdict.Exposed:
                    _summary.Text = "노출 — 런처가 악성 스크립트를 불러왔지만 에이전트 실행 흔적은 없습니다.";
                    _summary.ForeColor = Color.DarkOrange;
                    Log("[판정] 노출 (Exposed): 악성 로더는 실행됐지만 에이전트가 실행된 흔적은 찾지 못했습니다.", LogLevel.Warn);
                    Guide(new[]
                    {
                        "1. 니케 설치 폴더를 찾지 못했다면 경로를 지정해 다시 점검하세요. debug.log 에 에이전트 실행 기록이 있으면 '감염'으로 바뀝니다.",
                        "2. [조치 실행] 으로 런처 캐시(tbs_cache) 삭제와 hosts·방화벽 차단을 하세요.",
                        "3. 10월 23일 이후 런처를 연 적이 있다면 감염으로 간주하고 비밀번호 변경·세션 로그아웃·토큰 폐기를 하세요.",
                        "4. Level Infinite 가 수정을 확인할 때까지 NIKKE 런처를 열지 마세요.",
                    });
                    break;
                case Verdict.NotFound:
                    _summary.Text = "NIKKE 설치 폴더와 런처 데이터를 찾지 못했습니다.";
                    _summary.ForeColor = Color.DarkGoldenrod;
                    Log("[판정] NIKKE 를 찾지 못함: 다른 위치에 설치했다면 설치 경로를 지정해 다시 점검하세요.", LogLevel.Warn);
                    break;
                default:
                    _summary.Text = "선택한 항목에서 악성 흔적이 발견되지 않았습니다. (흔적이 없다고 깨끗함이 보장되지는 않습니다)";
                    _summary.ForeColor = Color.SeaGreen;
                    Log("[판정] 흔적 없음: 선택한 항목에서 악성 흔적을 찾지 못했습니다.", LogLevel.Ok);
                    Guide(new[]
                    {
                        "1. 런처를 다시 열기 전에 런처 캐시(tbs_cache)를 삭제하고 hosts·방화벽 차단을 하세요 ([조치 실행]).",
                        "2. 10월 23일 이후 런처를 연 적이 있다면 깨끗한 기기에서 NIKKE/Level Infinite 비밀번호를 변경하세요.",
                    });
                    break;
            }
            if (nFix > 0) Log($"[조치 대상] {nFix}건 — [조치 실행] 으로 제거할 수 있습니다.", LogLevel.Info);
        }

        private void Guide(IEnumerable<string> lines)
        {
            Log("[해야 할 일]", LogLevel.Header);
            foreach (var l in lines) Log("  " + l, LogLevel.Info);
        }

        private async Task FixAsync()
        {
            var opt = new FixOptions
            {
                DeleteFindings = _fixBox.Checked, AlwaysDeleteTbsCache = _tbsBox.Checked,
                Block = _blockBox.Checked, ClearCookies = _cookieBox.Checked,
            };
            var fixes = opt.DeleteFindings && _last != null ? _last.Fixable.ToList() : new List<Finding>();

            var plan = new StringBuilder("다음 작업을 실행합니다:\n\n");
            foreach (var d in fixes.Select(f => f.FixDescription).Distinct().Take(25)) plan.AppendLine("• " + d);
            if (fixes.Count > 25) plan.AppendLine($"• … 외 {fixes.Count - 25}건");
            if (opt.AlwaysDeleteTbsCache) plan.AppendLine("• 런처 캐시(tbs_cache) 삭제");
            if (fixes.Any(f => f.Browser != null)) plan.AppendLine("• 관련 브라우저 강제 종료");
            if (fixes.Count > 0 || opt.AlwaysDeleteTbsCache) plan.AppendLine("• NIKKE 런처 강제 종료");
            if (opt.ClearCookies) plan.AppendLine("• 모든 브라우저 강제 종료 후 쿠키 삭제 (모든 사이트 로그아웃)");
            if (opt.Block) plan.AppendLine($"• hosts 도메인 차단, 방화벽 IP 차단 ({string.Join(", ", Iocs.C2Ips)}) — UAC 요청");
            plan.AppendLine("\n실행 전에 현재 보고서를 바탕화면에 저장합니다 (삭제하면 증거가 사라지므로).");
            plan.AppendLine("브라우저에서 작업 중인 내용이 있다면 먼저 저장해 주세요. 계속할까요?");
            if (MessageBox.Show(this, plan.ToString(), "조치 확인", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;

            var report = SaveReport(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                $"NikkeChecker_보고서_{DateTime.Now:yyyyMMdd_HHmmss}.txt"));
            if (report != null) Log($"[+] 조치 전 보고서 저장: {report}", LogLevel.Action);

            _cts = new CancellationTokenSource();
            UpdateButtons();
            Log("", LogLevel.Info);
            Log($"===== 조치 시작 {DateTime.Now:yyyy-MM-dd HH:mm:ss} =====", LogLevel.Header);
            FixOutcome outcome;
            try { outcome = await Task.Run(() => Remediator.Fix(fixes, opt, SafeLog)); }
            catch (Exception ex) { outcome = new FixOutcome { Failed = 1 }; Log("[X] 조치 중 오류: " + ex, LogLevel.Bad); }
            finally { _cts.Dispose(); _cts = null; }

            Log("=================================================", LogLevel.Header);
            string msg;
            if (outcome.NeedsReboot)
            {
                Log("[재시작 필요] 사용 중인 DLL 이 있어 일부를 지우지 못했습니다. 레지스트리 키는 제거됐으므로 Windows 를 재시작한 뒤 이 도구로 다시 점검·조치하세요.", LogLevel.Bad);
                _summary.Text = "Windows 재시작 후 다시 점검·조치가 필요합니다."; _summary.ForeColor = Color.Firebrick;
                msg = "사용 중인 DLL 이 있어 일부를 지우지 못했습니다.\n\nWindows 를 재시작한 뒤 이 도구를 다시 실행해 점검·조치해 주세요.";
            }
            else if (outcome.Failed > 0)
            {
                Log($"[주의] {outcome.Failed}건이 실패했습니다. PC 재시작 후 다시 점검·조치해 주세요.", LogLevel.Bad);
                _summary.Text = $"{outcome.Failed}건 실패 — 재시작 후 다시 시도하세요."; _summary.ForeColor = Color.Firebrick;
                msg = $"{outcome.Failed}건의 작업이 실패했습니다. 재시작 후 다시 시도해 주세요.";
            }
            else
            {
                Log("[완료] 조치가 끝났습니다. [점검 시작] 으로 다시 점검해 결과를 확인하세요.", LogLevel.Ok);
                _summary.Text = "조치 완료 — 다시 점검하여 확인하세요."; _summary.ForeColor = Color.SeaGreen;
                msg = "조치가 완료되었습니다. 다시 점검하여 결과를 확인하세요.";
            }
            if (fixes.Any(f => f.Severity == Severity.Critical))
                msg += "\n\n감염 흔적이 있었으므로 깨끗한 기기에서 모든 계정의 비밀번호 변경과 세션 로그아웃을 해 주세요.";
            _last = null; // 조치 후에는 재점검을 거쳐야 다시 조치 가능
            UpdateButtons();
            MessageBox.Show(this, msg, "조치 결과", MessageBoxButtons.OK, outcome.Failed == 0 ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
        }

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
            try { File.WriteAllText(path, _logBox.Text.Replace("\r\n", "\n").Replace("\n", "\r\n"), new UTF8Encoding(true)); return path; }
            catch (Exception ex) { Log($"[X] 보고서 저장 실패: {ex.Message}", LogLevel.Bad); return null; }
        }

        private void SaveLogDialog()
        {
            using (var d = new SaveFileDialog
            {
                Filter = "텍스트 파일 (*.txt)|*.txt",
                FileName = $"NikkeChecker_보고서_{DateTime.Now:yyyyMMdd_HHmmss}.txt",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            })
            {
                if (d.ShowDialog(this) == DialogResult.OK) SaveReport(d.FileName);
            }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (Busy && MessageBox.Show(this, "작업이 진행 중입니다. 종료할까요?", "확인", MessageBoxButtons.YesNo) != DialogResult.Yes)
            { e.Cancel = true; return; }
            _cts?.Cancel();
            base.OnFormClosing(e);
        }
    }
}
