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
        private readonly CheckBox _cookieBox = new CheckBox();
        private readonly CheckBox _blockBox = new CheckBox();
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
            Text = "NIKKE PC 런처 감염 점검 도구";
            Font = new Font("Malgun Gothic", 9F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(860, 760);
            MinimumSize = new Size(700, 600);
            StartPosition = FormStartPosition.CenterScreen;
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new Padding(10) };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            Controls.Add(root);

            root.Controls.Add(new Label
            {
                AutoSize = true, MaximumSize = new Size(820, 0), Margin = new Padding(3, 0, 3, 8),
                Text = "9월 27일 이후 NIKKE PC 클라이언트(런처)를 실행한 적이 있다면 점검을 권장합니다.\n" +
                       "점검할 항목을 선택한 뒤 [점검 시작]을 누르세요. 점검만으로는 아무것도 변경되지 않습니다.",
            });

            // ---- 점검 항목 ----
            var checkGroup = new GroupBox { Text = "점검 항목", Dock = DockStyle.Fill, AutoSize = true, Padding = new Padding(8) };
            var checkTable = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 2 };
            checkTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            checkTable.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            checkGroup.Controls.Add(checkTable);
            root.Controls.Add(checkGroup);

            AddItem(checkTable, CheckId.BrowserDll, "1. 브라우저 악성 DLL  (User Data\\PlatformExperienceHelper\\<64자리>\\platform_experience_helper.dll)");
            AddItem(checkTable, CheckId.Clsid,      "2. 레지스트리 CLSID 하이재킹  (HKCU\\...\\CLSID\\" + Iocs.KnownBadClsid + " 및 변종)");
            AddItem(checkTable, CheckId.LevelDb,    "3. 런처 Local Storage 내 'k2f.agent' 흔적");
            AddItem(checkTable, CheckId.TbsCache,   "4. 런처 tbs_cache 내 악성 로더(insightjs) 캐시");
            AddItem(checkTable, CheckId.Logs,       "5. 런처 로그 실행 이력 (debug.log / tinyget)  ※ 증거 확인용");

            var pathRow = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 3, Margin = new Padding(20, 0, 0, 0) };
            pathRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            pathRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            pathRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            pathRow.Controls.Add(new Label { Text = "니케 설치 경로:", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 7, 3, 3) }, 0, 0);
            _pathBox.Dock = DockStyle.Fill;
            pathRow.Controls.Add(_pathBox, 1, 0);
            _browseBtn.Text = "찾아보기…";
            _browseBtn.AutoSize = true;
            _browseBtn.Click += (s, e) => BrowseInstallPath();
            pathRow.Controls.Add(_browseBtn, 2, 0);
            checkTable.Controls.Add(pathRow, 0, checkTable.RowCount);
            checkTable.SetColumnSpan(pathRow, 2);
            checkTable.RowCount++;
            var pathHint = new Label
            {
                AutoSize = true, ForeColor = SystemColors.GrayText, Margin = new Padding(23, 0, 3, 3),
                Text = "비워 두면 레지스트리와 드라이브를 자동 탐색합니다 (드라이브 탐색은 수 분 걸릴 수 있음)",
            };
            checkTable.Controls.Add(pathHint, 0, checkTable.RowCount);
            checkTable.SetColumnSpan(pathHint, 2);
            checkTable.RowCount++;
            _items.First(i => i.Id == CheckId.Logs).Box.CheckedChanged += (s, e) => UpdatePathEnabled();

            // ---- 조치 옵션 ----
            var fixGroup = new GroupBox { Text = "조치 옵션 ([조치 실행] 시 적용)", Dock = DockStyle.Fill, AutoSize = true, Padding = new Padding(8) };
            var fixFlow = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false };
            fixGroup.Controls.Add(fixFlow);
            root.Controls.Add(fixGroup);

            _fixBox.Text = "발견된 악성 항목 삭제  (64자리 폴더 / CLSID 키 / 런처 tbs_cache — 관련 브라우저·런처가 종료됩니다)";
            _fixBox.Checked = true; _fixBox.AutoSize = true;
            _blockBox.Text = "hosts 도메인 차단 + 방화벽 C2 IP(" + Iocs.C2Ip + ") 차단  (관리자 권한 필요, 감염 여부와 무관하게 적용 가능)";
            _blockBox.Checked = true; _blockBox.AutoSize = true;
            _cookieBox.Text = "브라우저 쿠키 초기화  (모든 브라우저 강제 종료, 모든 사이트 로그아웃)";
            _cookieBox.AutoSize = true;
            fixFlow.Controls.AddRange(new Control[] { _fixBox, _blockBox, _cookieBox });
            foreach (var c in new[] { _fixBox, _blockBox, _cookieBox }) c.CheckedChanged += (s, e) => UpdateButtons();

            // ---- 버튼 ----
            var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, Margin = new Padding(0, 6, 0, 0) };
            root.Controls.Add(buttons);
            SetupButton(_scanBtn, "점검 시작", async (s, e) => await ScanAsync());
            SetupButton(_fixBtn, "조치 실행", async (s, e) => await FixAsync());
            SetupButton(_stopBtn, "중지", (s, e) => _cts?.Cancel());
            SetupButton(_saveBtn, "로그 저장", (s, e) => SaveLog());
            _scanBtn.Font = new Font(Font, FontStyle.Bold);
            buttons.Controls.AddRange(new Control[] { _scanBtn, _fixBtn, _stopBtn, _saveBtn });
            _progress.Style = ProgressBarStyle.Marquee; _progress.MarqueeAnimationSpeed = 0;
            _progress.Width = 160; _progress.Margin = new Padding(12, 10, 3, 3);
            buttons.Controls.Add(_progress);

            _summary.AutoSize = true; _summary.Margin = new Padding(3, 4, 3, 4);
            _summary.Font = new Font(Font.FontFamily, 10F, FontStyle.Bold);
            _summary.Text = "점검 전";
            root.Controls.Add(_summary);

            // ---- 로그 ----
            _logBox.Dock = DockStyle.Fill; _logBox.ReadOnly = true;
            _logBox.BackColor = Color.FromArgb(24, 24, 28); _logBox.ForeColor = Color.Gainsboro;
            _logBox.Font = new Font("Malgun Gothic", 9F);
            _logBox.WordWrap = false; _logBox.DetectUrls = false;
            root.Controls.Add(_logBox);

            UpdatePathEnabled();
            UpdateButtons();
            if (!Remediator.IsAdmin())
                Log("※ 일반 권한으로 실행 중입니다. hosts·방화벽 차단 시에만 관리자 권한(UAC)을 요청합니다.", LogLevel.Detail);
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

        private void SetupButton(Button b, string text, EventHandler onClick)
        {
            b.Text = text; b.AutoSize = true; b.MinimumSize = new Size(100, 32); b.Click += onClick;
        }

        private void UpdatePathEnabled()
        {
            bool on = _items.First(i => i.Id == CheckId.Logs).Box.Checked;
            _pathBox.Enabled = _browseBtn.Enabled = on && _cts == null;
        }

        private bool Busy => _cts != null;

        private void UpdateButtons()
        {
            _scanBtn.Enabled = !Busy && _items.Any(i => i.Box.Checked);
            bool hasFix = _last != null && _last.Infected && _fixBox.Checked;
            _fixBtn.Enabled = !Busy && _last != null && (hasFix || _blockBox.Checked || _cookieBox.Checked);
            _stopBtn.Enabled = Busy;
            foreach (var i in _items) i.Box.Enabled = !Busy;
            _fixBox.Enabled = _blockBox.Enabled = _cookieBox.Enabled = !Busy;
            _progress.MarqueeAnimationSpeed = Busy ? 30 : 0;
            UpdatePathEnabled();
        }

        private void BrowseInstallPath()
        {
            using (var d = new FolderBrowserDialog { Description = "NIKKE 설치 폴더(Launcher 폴더가 들어있는 폴더)를 선택하세요" })
                if (d.ShowDialog(this) == DialogResult.OK) _pathBox.Text = d.SelectedPath;
        }

        // ------------------------------------------------------------------
        private async Task ScanAsync()
        {
            var opt = new ScanOptions { InstallPath = _pathBox.Text };
            foreach (var i in _items.Where(i => i.Box.Checked)) opt.Checks.Add(i.Id);
            foreach (var i in _items) SetStatus(i, i.Box.Checked ? (bool?)null : null, i.Box.Checked ? "점검 중…" : "미점검", Color.Gray);

            _last = null;
            _cts = new CancellationTokenSource();
            UpdateButtons();
            _summary.Text = "점검 중…"; _summary.ForeColor = SystemColors.ControlText;
            Log("", LogLevel.Info);
            Log($"===== 점검 시작 {DateTime.Now:yyyy-MM-dd HH:mm:ss} =====", LogLevel.Header);

            try
            {
                var token = _cts.Token;
                var result = await Task.Run(() => new Scanner(SafeLog, token).Run(opt));
                _last = result;
                if (!string.IsNullOrEmpty(result.InstallPath) && string.IsNullOrWhiteSpace(_pathBox.Text)) _pathBox.Text = result.InstallPath;

                foreach (var i in _items.Where(i => opt.Checks.Contains(i.Id)))
                {
                    result.Status.TryGetValue(i.Id, out var st);
                    if (st == true) SetStatus(i, true, "● 발견", Color.Firebrick);
                    else if (st == false) SetStatus(i, false, "○ 이상 없음", Color.SeaGreen);
                    else SetStatus(i, null, "? 확인 불가", Color.DarkOrange);
                }

                Log("=================================================", LogLevel.Header);
                if (result.Infected)
                {
                    _summary.Text = $"감염 흔적 발견 — 조치 대상 {result.Findings.Count(f => f.Fix != FixKind.None)}건. [조치 실행]을 눌러 주세요.";
                    _summary.ForeColor = Color.Firebrick;
                    Log("[판정] 감염 또는 악성 캐시 흔적이 감지되었습니다.", LogLevel.Bad);
                }
                else if (result.Status.Values.Any(v => v == true))
                {
                    _summary.Text = "감염 이력(로그)이 확인되었습니다. 현재 남아 있는 악성 파일은 없습니다. 비밀번호 변경을 권장합니다.";
                    _summary.ForeColor = Color.DarkOrange;
                    Log("[판정] 로그에서 과거 감염 이력이 확인되었습니다. 삭제할 악성 항목은 없습니다.", LogLevel.Warn);
                }
                else
                {
                    _summary.Text = "선택한 항목에서 악성 흔적이 발견되지 않았습니다.";
                    _summary.ForeColor = Color.SeaGreen;
                    Log("[판정] 선택한 항목에서 악성 흔적이 발견되지 않았습니다.", LogLevel.Ok);
                }
            }
            catch (OperationCanceledException)
            {
                Log("[!] 사용자가 점검을 중지했습니다.", LogLevel.Warn);
                _summary.Text = "점검 중지됨"; _summary.ForeColor = Color.DarkOrange;
                foreach (var i in _items.Where(i => i.Status.Text == "점검 중…")) SetStatus(i, null, "중지됨", Color.Gray);
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

        private async Task FixAsync()
        {
            var fixes = (_fixBox.Checked && _last != null) ? _last.Findings.Where(f => f.Fix != FixKind.None).ToList() : new List<Finding>();
            var plan = new StringBuilder("다음 작업을 실행합니다:\n\n");
            foreach (var d in fixes.Select(f => f.Description).Distinct()) plan.AppendLine("• " + d);
            if (fixes.Any(f => f.Fix == FixKind.DeleteDirectory)) plan.AppendLine("• 해당 브라우저 강제 종료");
            if (fixes.Any(f => f.Fix == FixKind.DeleteTbsCache)) plan.AppendLine("• NIKKE 런처 강제 종료");
            if (_cookieBox.Checked) plan.AppendLine("• 모든 브라우저 강제 종료 후 쿠키 삭제 (모든 사이트 로그아웃)");
            if (_blockBox.Checked) plan.AppendLine("• hosts 도메인 차단 및 방화벽 C2 IP 차단 (관리자 권한 요청)");
            plan.AppendLine("\n브라우저에서 작업 중인 내용이 있다면 먼저 저장해 주세요. 계속할까요?");
            if (MessageBox.Show(this, plan.ToString(), "조치 확인", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;

            bool block = _blockBox.Checked, cookies = _cookieBox.Checked;
            _cts = new CancellationTokenSource();
            UpdateButtons();
            Log("", LogLevel.Info);
            Log($"===== 조치 시작 {DateTime.Now:yyyy-MM-dd HH:mm:ss} =====", LogLevel.Header);
            int failed = 0;
            try
            {
                await Task.Run(() =>
                {
                    if (fixes.Count > 0) failed = Remediator.Fix(fixes, SafeLog);
                    if (cookies) Remediator.ClearBrowserCookies(SafeLog);
                    if (block) Remediator.ApplyBlockElevated(SafeLog);
                });
            }
            catch (Exception ex) { failed++; Log("[X] 조치 중 오류: " + ex, LogLevel.Bad); }
            finally
            {
                _cts.Dispose(); _cts = null;
            }

            Log("=================================================", LogLevel.Header);
            if (failed == 0)
            {
                Log("[완료] 조치가 끝났습니다. [점검 시작]으로 다시 점검해 결과를 확인하세요.", LogLevel.Ok);
                if (fixes.Count > 0)
                    Log("       로그인되어 있던 모든 계정의 비밀번호 변경과 브라우저 초기화를 권장합니다.", LogLevel.Warn);
                _summary.Text = "조치 완료 — 다시 점검하여 확인하세요."; _summary.ForeColor = Color.SeaGreen;
            }
            else
            {
                Log($"[주의] {failed}건의 작업이 실패했습니다. PC 재부팅 후 다시 점검·조치해 주세요.", LogLevel.Bad);
                _summary.Text = $"{failed}건 실패 — 재부팅 후 다시 시도하세요."; _summary.ForeColor = Color.Firebrick;
            }
            _last = null; // 조치 후에는 재점검을 거쳐야 다시 조치 가능
            UpdateButtons();
            if (fixes.Count > 0)
                MessageBox.Show(this, "조치가 완료되었습니다.\n\n로그인되어 있던 모든 계정의 비밀번호 변경과 브라우저 초기화를 권장합니다.",
                    "완료", MessageBoxButtons.OK, failed == 0 ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
        }

        private static void SetStatus(Item i, bool? _, string text, Color color) { i.Status.Text = text; i.Status.ForeColor = color; }

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

        private void SaveLog()
        {
            using (var d = new SaveFileDialog
            {
                Filter = "텍스트 파일 (*.txt)|*.txt",
                FileName = $"NikkeChecker_{DateTime.Now:yyyyMMdd_HHmmss}.txt",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                File.WriteAllText(d.FileName, _logBox.Text.Replace("\n", "\r\n"), new UTF8Encoding(true));
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
