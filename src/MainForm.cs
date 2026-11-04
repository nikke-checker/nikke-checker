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
using NikkeChecker.Ui;
using static NikkeChecker.I18n;

namespace NikkeChecker
{
    /// <summary>
    /// 화면 4단계: 시작 → 점검 중 → 결과 → 정리 완료.
    /// 기록(로그)은 「자세히 보기」 창에 모으고, 보고서는 그 기록을 그대로 저장한다.
    /// </summary>
    public sealed class MainForm : Form
    {
        // ---- 공통 틀 ----
        private readonly Panel _body = new Panel { Dock = DockStyle.Fill, AutoScroll = true, BackColor = Theme.Background, Padding = new Padding(28, 24, 28, 24) };
        private readonly UiStack _stack = new UiStack();
        private readonly FlowLayoutPanel _footLeft = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Left, WrapContents = false, BackColor = Theme.Card, Padding = new Padding(0, 12, 0, 0) };
        private readonly FlowLayoutPanel _footRight = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Right, WrapContents = false, FlowDirection = FlowDirection.RightToLeft, BackColor = Theme.Card };

        // ---- 기록 ----
        private readonly RichTextBox _logBox = new RichTextBox();
        private Form _logForm;

        // ---- 설정 (시작 화면의 고급 설정, 결과 화면의 정리 옵션) ----
        private readonly Dictionary<CheckId, CheckBox> _checks = new Dictionary<CheckId, CheckBox>();
        private readonly TextBox _pathBox = new TextBox();
        private readonly CheckBox _optClean = new CheckBox();
        private readonly CheckBox _optTbs = new CheckBox();
        private readonly CheckBox _optBlock = new CheckBox();
        private readonly CheckBox _optWdo = new CheckBox();

        // ---- 점검 중 화면 ----
        private readonly Dictionary<CheckId, UiStepRow> _steps = new Dictionary<CheckId, UiStepRow>();
        private UiProgress _progress;
        private Label _progressCount, _progressDetail;

        private CancellationTokenSource _cts;
        private ScanResult _last;
        private Verdict _lastVerdict;
        private string _lastReport;

        private static string WdoMarker => Path.Combine(Iocs.LocalAppData, @"NikkeChecker\offline_scan.txt");
        private bool Busy => _cts != null;

        private static readonly CheckId[] AllChecks =
        {
            CheckId.BrowserDll, CheckId.Clsid, CheckId.Processes, CheckId.LauncherData, CheckId.Temp,
            CheckId.FullScan, CheckId.InstallLogs, CheckId.Autostart, CheckId.Extra, CheckId.Protection,
        };

        /// <summary>점검 항목의 쉬운 이름.</summary>
        private static string Friendly(CheckId id)
        {
            switch (id)
            {
                case CheckId.BrowserDll: return L("브라우저에 심어진 해킹 파일", "Hacking files planted in browsers");
                case CheckId.Clsid: return L("해킹 파일을 실행시키는 등록 (레지스트리)", "Registry entries that run the hacking file");
                case CheckId.Processes: return L("지금 실행 중인 프로그램", "Programs running now");
                case CheckId.LauncherData: return L("런처 데이터 (해킹 프로그램 상태·해커 서버 접속 기록)", "Launcher data (agent state, hacker server records)");
                case CheckId.Temp: return L("임시 폴더의 빼낸 정보 파일", "Stolen-data files in the temp folder");
                case CheckId.FullScan: return L("모든 드라이브에서 해킹 파일 찾기", "Hacking files on all drives");
                case CheckId.InstallLogs: return L("니케 설치 폴더의 실행 기록", "Run records in the NIKKE install folder");
                case CheckId.Autostart: return L("해커가 따로 깔았을 수 있는 프로그램", "Programs the hacker may have installed");
                case CheckId.Extra: return L("해커 서버 연결·원격 조종 설정", "Hacker server connections and remote-control settings");
                default: return L("해커 서버 차단 상태", "Hacker server block status");
            }
        }

        /// <summary>점검 항목의 자세한 설명 (고급 설정).</summary>
        private static string Detail(CheckId id)
        {
            switch (id)
            {
                case CheckId.BrowserDll: return L("Chromium 계열 14종의 PlatformExperienceHelper\\<64자리> 폴더와 DLL", "PlatformExperienceHelper\\<64 hex> folders and DLLs in 14 Chromium browsers");
                case CheckId.Clsid: return L("HKCU CLSID {E77CC89B-…} 와 같은 수법의 다른 이름", "HKCU CLSID {E77CC89B-…} and variants");
                case CheckId.Processes: return L("악성 DLL 이 로드된 프로그램, 실행 중인 런처", "Programs with the DLL loaded, running launcher");
                case CheckId.LauncherData: return L("k2f.agent, 악성 스크립트 캐시, HSTS·네트워크 기록, 런처 로그인 프로필", "k2f.agent, script cache, HSTS/network records, login profile");
                case CheckId.Temp: return L("k2f-bcreds·k2f-keyscan·k2f_screen 파일", "k2f-bcreds, k2f-keyscan, k2f_screen files");
                case CheckId.FullScan: return L("정해진 위치 밖의 에이전트·DLL 파일 (수 분 걸릴 수 있음)", "Agent/DLL files outside known places (can take minutes)");
                case CheckId.InstallLogs: return L("debug.log 실행 기록, 다운로드 기록, 저장된 에이전트 파일", "debug.log runs, download records, saved agent files");
                case CheckId.Autostart: return L("9/27 이후 생긴 서명 없는 자동 실행 (UAC, 읽기만 함, 판정 영향 없음)", "Unsigned autostarts since 9/27 (UAC, read-only, no effect on verdict)");
                case CheckId.Extra: return L("해커 서버 연결·DNS, 브라우저 원격 조종, Defender 제외, 원격 접속, 프록시, Winlogon·IFEO·AppInit", "Server connections, DNS, browser remote control, Defender exclusions, remote access, proxy, Winlogon/IFEO/AppInit");
                default: return L("hosts 7개 도메인, 방화벽 규칙 (참고용)", "7 domains in hosts, firewall rule (reference)");
            }
        }

        public MainForm()
        {
            Text = L("NIKKE PC 런처 감염 점검", "NIKKE PC Launcher Infection Check") + " v" + Application.ProductVersion;
            Font = Theme.Font(9.5f);
            AutoScaleMode = AutoScaleMode.Font;
            BackColor = Theme.Background;
            ClientSize = new Size(820, 720);
            MinimumSize = new Size(700, 600);
            StartPosition = FormStartPosition.CenterScreen;
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

            // 머리글
            var header = new Panel { Dock = DockStyle.Top, Height = 64, BackColor = Theme.Card, Padding = new Padding(24, 0, 24, 1) };
            header.Paint += (s, e) =>
            {
                Icons.Draw(e.Graphics, IconKind.Shield, new RectangleF(24, 18, 28, 28), Theme.Foreground, 2f);
                using (var p = new Pen(Theme.Border)) e.Graphics.DrawLine(p, 0, header.Height - 1, header.Width, header.Height - 1);
            };
            var title = Layouts.Text(L("NIKKE PC 런처 감염 점검", "NIKKE PC Launcher Infection Check"), 12f, FontStyle.Bold);
            title.Location = new Point(62, 20);
            header.Controls.Add(title);
            var headRight = new FlowLayoutPanel { Dock = DockStyle.Right, AutoSize = true, WrapContents = false, BackColor = Theme.Card, Padding = new Padding(0, 16, 0, 0) };
            var lang = new UiButton { Text = En ? "한국어" : "English", Variant = ButtonVariant.Ghost, AutoSize = true, Font = Theme.Font(9f) };
            lang.Click += (s, e) => SwitchLanguage();
            var ver = Layouts.Text("v" + Application.ProductVersion, 9f, FontStyle.Regular, Theme.MutedForeground, new Padding(8, 9, 0, 0));
            headRight.Controls.AddRange(new Control[] { lang, ver });
            header.Controls.Add(headRight);

            // 바닥글
            var footer = new Panel { Dock = DockStyle.Bottom, Height = 78, BackColor = Theme.Card, Padding = new Padding(24, 16, 24, 14) };
            footer.Paint += (s, e) => { using (var p = new Pen(Theme.Border)) e.Graphics.DrawLine(p, 0, 0, footer.Width, 0); };
            footer.Controls.Add(_footLeft);
            footer.Controls.Add(_footRight);

            _body.Controls.Add(_stack);
            _body.Resize += (s, e) => FitBody();
            Controls.Add(_body);
            Controls.Add(header);
            Controls.Add(footer);

            // 기록 창 (자세히 보기)
            _logBox.Dock = DockStyle.Fill; _logBox.ReadOnly = true;
            _logBox.BackColor = Color.FromArgb(24, 24, 27); _logBox.ForeColor = Color.Gainsboro;
            _logBox.Font = Theme.Font(9f); _logBox.WordWrap = false; _logBox.DetectUrls = false; _logBox.BorderStyle = BorderStyle.None;

            BuildSettings();
            Log(L($"NIKKE PC 런처 감염 점검 v{Application.ProductVersion} — {Environment.MachineName} / {Environment.UserName}",
                  $"NIKKE PC Launcher Infection Check v{Application.ProductVersion} - {Environment.MachineName} / {Environment.UserName}"), LogLevel.Detail);
            ShowStart();
        }

        private void BuildSettings()
        {
            foreach (var id in AllChecks)
                _checks[id] = new CheckBox { Text = Friendly(id), Checked = true, AutoSize = true, Font = Theme.Font(9.5f), BackColor = Color.Transparent, Margin = new Padding(0, 6, 0, 0) };
            _pathBox.Font = Theme.Font(9.5f);
            _pathBox.BorderStyle = BorderStyle.FixedSingle;
            SetupOption(_optClean, L("발견한 해킹 흔적 지우기 (브라우저·런처·게임이 잠시 꺼집니다)", "Remove the hacking traces found (browsers, the launcher and the game close for a moment)"), true);
            SetupOption(_optTbs, L("런처 캐시 지우기 (런처를 다시 열기 전에 권장, 런처 로그인만 다시 하면 됨)", "Delete the launcher cache (recommended before reopening the launcher; you only sign in again)"), true);
            SetupOption(_optBlock, L("해커 서버 차단 (hosts·방화벽, 관리자 확인 창이 뜹니다)", "Block the hacker servers (hosts + firewall, an admin prompt appears)"), true);
            SetupOption(_optWdo, L("마지막에 Windows 백신 정밀 검사 (재부팅, 약 15분)", "Finally run a Windows Defender deep scan (restart, about 15 min)"), false);
        }

        private static void SetupOption(CheckBox c, string text, bool on)
        {
            c.Text = text; c.Checked = on; c.AutoSize = true; c.Font = Theme.Font(9.5f); c.BackColor = Color.Transparent; c.Margin = new Padding(0, 4, 0, 4);
        }

        // ------------------------------------------------------------------
        // 화면 틀 도우미
        // ------------------------------------------------------------------
        private void SetView(IEnumerable<Control> body, IEnumerable<Control> footLeft, IEnumerable<Control> footRight)
        {
            _body.SuspendLayout();
            foreach (Control c in _stack.Controls.Cast<Control>().ToList()) { _stack.Controls.Remove(c); if (!IsReused(c)) c.Dispose(); }
            _stack.Controls.AddRange(body.ToArray());
            _footLeft.Controls.Clear(); _footLeft.Controls.AddRange(footLeft.ToArray());
            _footRight.Controls.Clear(); _footRight.Controls.AddRange(footRight.ToArray());
            _body.AutoScrollPosition = new Point(0, 0);
            FitBody();
            _body.ResumeLayout(true);
        }

        // 설정 체크박스처럼 화면을 바꿔도 다시 쓰는 컨트롤은 Dispose 하지 않는다
        private bool IsReused(Control c) =>
            c.Controls.Cast<Control>().Any(IsReused) || _checks.Values.Contains(c) || c == _pathBox ||
            c == _optClean || c == _optTbs || c == _optBlock || c == _optWdo;

        private void FitBody()
        {
            // 세로 스크롤 막대가 생겨도 줄이 다시 흐르지 않게 막대 폭을 늘 빼 둔다
            int w = _body.Width - _body.Padding.Horizontal - SystemInformation.VerticalScrollBarWidth - 2;
            _stack.Location = new Point(_body.Padding.Left, _body.Padding.Top);
            _stack.FitWidth(Math.Max(200, w));
        }

        private static UiButton Button(string text, ButtonVariant v, EventHandler click, bool large = false)
        {
            var b = new UiButton { Text = text, Variant = v, Large = large, AutoSize = true, Margin = new Padding(8, 0, 0, 0) };
            if (large) b.Font = Theme.Font(11f, FontStyle.Bold);
            b.Size = b.GetPreferredSize(Size.Empty);
            if (click != null) b.Click += click;
            return b;
        }

        private static UiButton Link(string text, EventHandler click)
        {
            var b = new UiButton { Text = text, Variant = ButtonVariant.Link, AutoSize = true, Font = Theme.Font(9.5f), Margin = new Padding(0, 0, 18, 0) };
            b.Size = b.GetPreferredSize(Size.Empty);
            b.Click += click;
            return b;
        }

        private static UiCard Alert(IconKind icon, Color tone, Color fill, Color stroke, string label, string title, string description)
        {
            var card = Layouts.Card(
                Layouts.Text(label, 8.5f, FontStyle.Bold, tone, new Padding(0, 0, 0, 4)),
                Layouts.Text(title, 13f, FontStyle.Bold, Theme.Foreground, new Padding(0, 0, 0, 6)),
                Layouts.Text(description, 9.5f, FontStyle.Regular, Color.FromArgb(0x3F, 0x3F, 0x46), new Padding(0)));
            card.SetTone(fill, stroke);
            card.Icon = icon; card.IconColor = tone; card.IconSize = 28;
            card.Padding = new Padding(64, 20, 22, 20);
            card.Margin = new Padding(0, 0, 0, 18);
            return card;
        }

        private static Label Heading(string text) => Layouts.Text(text, 11f, FontStyle.Bold, Theme.Foreground, new Padding(0, 4, 0, 8));
        private static Label Muted(string text, Padding? m = null) => Layouts.Text(text, 9f, FontStyle.Regular, Theme.MutedForeground, m ?? new Padding(0, 0, 0, 4));

        // ------------------------------------------------------------------
        // 1. 시작
        // ------------------------------------------------------------------
        private void ShowStart()
        {
            var start = Button(L("점검 시작", "Start check"), ButtonVariant.Default, async (s, e) => await ScanAsync(), large: true);
            start.Margin = new Padding(0, 8, 0, 14);

            var badges = Layouts.Row(
                new UiBadge { Text = L("설치 불필요", "No install"), Variant = BadgeVariant.Outline },
                new UiBadge { Text = L("인터넷 연결 안 함", "No internet use"), Variant = BadgeVariant.Outline },
                new UiBadge { Text = L("공개 소스", "Open source"), Variant = BadgeVariant.Outline },
                new UiBadge { Text = L("점검은 아무것도 바꾸지 않음", "Checking changes nothing"), Variant = BadgeVariant.Outline });
            badges.Margin = new Padding(0, 0, 0, 24);

            var advanced = new UiCollapsible(L("고급 설정 — 점검 항목 고르기, 니케 설치 경로 지정", "Advanced - choose checks, set the NIKKE install path"));
            var adv = advanced.Content;
            adv.Controls.Add(Muted(L("점검할 항목 (기본은 전부)", "Checks to run (all by default)"), new Padding(0, 4, 0, 0)));
            foreach (var id in AllChecks)
            {
                adv.Controls.Add(_checks[id]);
                adv.Controls.Add(Muted(Detail(id), new Padding(20, 0, 0, 2)));
            }
            adv.Controls.Add(Muted(L("니케 설치 경로 (비워 두면 자동으로 찾음)", "NIKKE install path (leave empty to find it automatically)"), new Padding(0, 14, 0, 4)));
            var browse = Button(L("찾아보기…", "Browse…"), ButtonVariant.Outline, (s, e) => BrowseInstallPath());
            var pathRow = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, BackColor = Color.Transparent, Margin = new Padding(0, 0, 0, 8) };
            pathRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            pathRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            _pathBox.Dock = DockStyle.Fill; _pathBox.Margin = new Padding(0, 6, 0, 0);
            pathRow.Controls.Add(_pathBox, 0, 0);
            pathRow.Controls.Add(browse, 1, 0);
            adv.Controls.Add(pathRow);

            var note = Layouts.Card(
                Layouts.Text(L("관리자 확인 창이 한 번 뜹니다", "An administrator prompt appears once"), 9.5f, FontStyle.Bold, Theme.Foreground, new Padding(0, 0, 0, 2)),
                Muted(L("PC 전체(서비스·작업 스케줄러·Defender 설정 등)를 읽기 위해서입니다. 읽기만 하고, 아무것도 바꾸지 않습니다.",
                        "It is needed to read PC-wide settings (services, scheduled tasks, Defender settings). It only reads; nothing is changed."), new Padding(0)));
            note.SetTone(Theme.Muted, Theme.Border);
            note.Icon = IconKind.Info; note.IconColor = Theme.MutedForeground; note.IconSize = 18;
            note.Padding = new Padding(50, 14, 18, 14);
            note.Margin = new Padding(0, 16, 0, 0);

            SetView(new Control[]
            {
                Layouts.Text(L("이 PC가 니케 런처 해킹에 영향을 받았는지 확인합니다", "Check whether this PC was affected by the NIKKE launcher hack"), 18f, FontStyle.Bold, Theme.Foreground, new Padding(0, 8, 0, 8)),
                Muted(L("2026년 9월 27일 이후 NIKKE PC 런처를 켠 적이 있다면 점검하세요. 약 1~5분 걸립니다.",
                        "Check this PC if you ran the NIKKE PC launcher on or after Sep 27, 2026. It takes about 1-5 minutes."), new Padding(0, 0, 0, 12)),
                start, badges, advanced, note,
            }, new Control[0], new Control[0]);
            start.Focus();
        }

        private void BrowseInstallPath()
        {
            using (var d = new FolderBrowserDialog { Description = L("NIKKE 설치 폴더(Launcher 폴더가 들어 있는 폴더)를 선택하세요", "Select the NIKKE install folder (the folder that holds the Launcher folder)") })
                if (d.ShowDialog(this) == DialogResult.OK) _pathBox.Text = d.SelectedPath;
        }

        // ------------------------------------------------------------------
        // 2. 점검 중
        // ------------------------------------------------------------------
        private void ShowScanning(List<CheckId> ids)
        {
            _steps.Clear();
            var list = new UiStack();
            foreach (var id in ids)
            {
                var row = new UiStepRow { Text = Friendly(id) };
                row.Set(StepState.Pending, L("대기", "Waiting"));
                _steps[id] = row;
                list.Controls.Add(row);
            }
            var card = Layouts.Card(list);
            card.Padding = new Padding(1, 6, 1, 6);

            _progressCount = Layouts.Text($"0 / {ids.Count}", 10f, FontStyle.Regular, Theme.MutedForeground, new Padding(0));
            _progressCount.Tag = "keep";
            _progress = new UiProgress();
            _progressDetail = Muted(L("준비 중…", "Preparing…"), new Padding(0, 0, 0, 14));

            var stop = Button(L("중지", "Stop"), ButtonVariant.Outline, (s, e) => _cts?.Cancel());
            SetView(new Control[]
            {
                Layouts.Text(L("점검하는 중입니다…", "Checking…"), 16f, FontStyle.Bold, Theme.Foreground, new Padding(0, 4, 0, 2)),
                _progressCount, _progress, _progressDetail, card,
            }, new Control[] { Link(L("자세히 보기", "Show details"), (s, e) => ShowLog()) }, new Control[] { stop });
        }

        private void OnStepStart(CheckId id, int index, int total)
        {
            if (_steps.TryGetValue(id, out var row)) row.Set(StepState.Running, L("확인 중", "Checking"));
            if (_progressCount != null) _progressCount.Text = $"{index} / {total}";
            if (_progress != null) _progress.Value = (index - 1) * 100 / Math.Max(1, total);
        }

        private void OnStepDone(CheckId id, StepSummary s)
        {
            if (_steps.TryGetValue(id, out var row)) ApplyStep(row, id, s);
        }

        private static void ApplyStep(UiStepRow row, CheckId id, StepSummary s)
        {
            if (id == CheckId.Protection)
            {
                if (s.NotBlocked) row.Set(StepState.Review, L("차단 안 됨", "Not blocked"));
                else row.Set(StepState.Ok, L("차단됨", "Blocked"));
                return;
            }
            if (s.Worst == Severity.Critical && s.AllPast) row.Set(StepState.Warn, L($"과거 기록 {s.Count}건", $"Past record {s.Count}"));
            else if (s.Worst == Severity.Critical) row.Set(StepState.Found, L($"발견 {s.Count}건", $"Found {s.Count}"));
            else if (s.Worst == Severity.Warning) row.Set(StepState.Warn, L($"노출 {s.Count}건", $"Exposed {s.Count}"));
            else if (s.Worst == Severity.Review) row.Set(StepState.Review, L($"확인 필요 {s.Count}건", $"Check {s.Count}"));
            else if (s.Unknown) row.Set(StepState.Unknown, L("일부 확인 못 함", "Partly unchecked"));
            else row.Set(StepState.Ok, L("이상 없음", "OK"));
        }

        private async Task ScanAsync()
        {
            var ids = AllChecks.Where(id => _checks[id].Checked).ToList();
            if (ids.Count == 0) { MessageBox.Show(this, L("점검할 항목을 하나 이상 고르세요.", "Choose at least one check."), Text); return; }
            var opt = new ScanOptions
            {
                InstallPath = _pathBox.Text,
                AuditSystem = () => Remediator.RunAudit(SafeLog),
                OnStepStart = (id, i, n) => Ui(() => OnStepStart(id, i, n)),
                OnStepDone = (id, sm) => Ui(() => OnStepDone(id, sm)),
            };
            foreach (var id in ids) opt.Checks.Add(id);

            _last = null;
            _cts = new CancellationTokenSource();
            ShowScanning(ids);
            Log("", LogLevel.Info);
            Log(L($"===== 점검 시작 {DateTime.Now:yyyy-MM-dd HH:mm:ss} =====", $"===== Check started {DateTime.Now:yyyy-MM-dd HH:mm:ss} ====="), LogLevel.Header);
            try
            {
                var token = _cts.Token;
                var r = await Task.Run(() => new Scanner(SafeLog, token).Run(opt));
                _last = r;
                if (r.Installs.Count > 0 && string.IsNullOrWhiteSpace(_pathBox.Text)) _pathBox.Text = r.Installs[0];
                LogVerdict(r);
                _cts.Dispose(); _cts = null;
                ShowResult(r);
            }
            catch (OperationCanceledException)
            {
                Log(L("[!] 사용자가 점검을 중지했습니다.", "[!] The check was stopped."), LogLevel.Warn);
                _cts.Dispose(); _cts = null;
                ShowStart();
            }
            catch (Exception ex)
            {
                Log(L("[X] 점검 중 오류: ", "[X] Error during the check: ") + ex, LogLevel.Bad);
                _cts?.Dispose(); _cts = null;
                MessageBox.Show(this, L("점검 중 오류가 났습니다. 「자세히 보기」의 기록을 확인해 주세요.", "An error occurred during the check. See the log in Show details."), Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
                ShowStart();
            }
        }

        // ------------------------------------------------------------------
        // 3. 결과
        // ------------------------------------------------------------------
        private void ShowResult(ScanResult r)
        {
            _lastVerdict = r.Verdict;
            var body = new List<Control> { VerdictAlert(r.Verdict) };

            // 발견한 것: 점검 항목별 카드 (감염·노출)
            var groups = AllChecks.Where(id => id != CheckId.Protection)
                .Select(id => (id, items: r.Findings.Where(f => f.Check == id && (f.Severity == Severity.Critical || f.Severity == Severity.Warning)).ToList()))
                .Where(g => g.items.Count > 0).ToList();
            if (groups.Count > 0)
            {
                body.Add(Heading(L($"발견한 것 {groups.Count}종류", $"Found: {groups.Count} kinds")));
                foreach (var (id, items) in groups) body.Add(FindingCard(id, items));
            }

            // 확인 필요
            var review = r.Review.ToList();
            if (review.Count > 0)
            {
                var col = new UiCollapsible(L($"확인이 필요한 프로그램·설정 {review.Count}개 — 직접 설치·설정한 것이면 괜찮습니다", $"{review.Count} programs/settings to check - fine if you set them up yourself"));
                foreach (var a in review.Take(40))
                {
                    var tag = a.Hidden ? L("위험 높음: 숨겨진 명령", "HIGH RISK: hidden command") : a.File != null ? Defender.VerdictText(a.Defender) : "";
                    col.Content.Controls.Add(Layouts.Text($"[{a.Where}] {a.Name}", 9.5f, FontStyle.Bold, a.Defender == "malware" || a.Hidden ? Theme.Destructive : Theme.Foreground, new Padding(0, 6, 0, 0)));
                    col.Content.Controls.Add(Muted(a.Display + (tag.Length > 0 ? "  ·  " + tag : ""), new Padding(0, 0, 0, 2)));
                }
                col.Content.Controls.Add(Muted(L("[정리하기]를 누르면 지울 것을 직접 고르는 창이 뜹니다.", "[Clean up] opens a window where you pick what to remove."), new Padding(0, 8, 0, 0)));
                col.Margin = new Padding(0, 4, 0, 12);
                body.Add(col);
            }

            if (r.Unknown.Count > 0)
            {
                var unk = Layouts.Card(
                    Layouts.Text(L("일부 항목은 확인하지 못했습니다", "Some checks could not be completed"), 9.5f, FontStyle.Bold, Theme.Foreground, new Padding(0, 0, 0, 2)),
                    Muted(string.Join(", ", r.Unknown.Keys.Select(Friendly)) + L(" — 「자세히 보기」에 이유가 있습니다.", " - see Show details for why."), new Padding(0)));
                unk.SetTone(Theme.Muted, Theme.Border);
                unk.Icon = IconKind.Info; unk.IconColor = Theme.MutedForeground; unk.IconSize = 18; unk.Padding = new Padding(50, 14, 18, 14);
                body.Add(unk);
            }

            // 정리 옵션
            _optClean.Enabled = r.Fixable.Any() || review.Count > 0;
            _optClean.Checked = _optClean.Enabled;
            var opts = Layouts.Card(
                Layouts.Text(L("[정리하기]를 누르면", "[Clean up] will"), 10f, FontStyle.Bold, Theme.Foreground, new Padding(0, 0, 0, 4)),
                _optClean, _optTbs, _optBlock, _optWdo,
                Muted(L("지우기 전에 점검 결과를 바탕 화면에 저장합니다.", "The check result is saved to the Desktop before anything is removed."), new Padding(0, 6, 0, 0)));
            opts.Margin = new Padding(0, 6, 0, 0);
            body.Add(opts);

            bool danger = r.Verdict == Verdict.Infected;
            var clean = Button(L("정리하기", "Clean up"), danger ? ButtonVariant.Destructive : ButtonVariant.Default, async (s, e) => await FixAsync(), large: true);
            SetView(body,
                new Control[]
                {
                    Link(L("자세히 보기", "Show details"), (s, e) => ShowLog()),
                    Link(L("보고서 저장", "Save report"), (s, e) => SaveLogDialog()),
                    Link(L("다시 점검", "Check again"), (s, e) => ShowStart()),
                    Link(L("니케 완전 삭제…", "Remove NIKKE…"), async (s, e) => await UninstallAsync()),
                },
                new Control[] { clean });
        }

        private static UiCard VerdictAlert(Verdict v)
        {
            switch (v)
            {
                case Verdict.Infected:
                    return Alert(IconKind.AlertTriangle, Theme.Destructive, Theme.DestructiveBg, Theme.DestructiveBorder, L("판정: 감염", "VERDICT: INFECTED"),
                        L("해킹 프로그램이 이 PC에서 실행된 흔적이 있습니다", "The hacking program ran on this PC"),
                        L("런처가 열려 있는 동안 해커가 이 PC에서 명령을 실행할 수 있었습니다. [정리하기]로 남은 해킹 흔적을 지우고, 휴대폰 등 다른 기기로 비밀번호를 바꾸세요.",
                          "While the launcher was open, the attacker could run commands on this PC. Use [Clean up] to remove what is left, then change your passwords from another device such as your phone."));
                case Verdict.PastInfection:
                    return Alert(IconKind.Clock, Theme.Warning, Theme.WarningBg, Theme.WarningBorder, L("판정: 감염됐던 기록 (과거 기록)", "VERDICT: PAST INFECTION (records only)"),
                        L("해킹 프로그램이 전에 이 PC에서 실행됐습니다", "The hacking program ran on this PC before"),
                        L("지금 남아 있는 해킹 파일은 없습니다. 런처 기록(debug.log)에 남은 흔적이라 다시 점검해도 계속 나옵니다. 그때 비밀번호가 빠져나갔을 수 있으니 꼭 바꾸세요.",
                          "No hacking files remain now. The records stay in the launcher log (debug.log), so they show on every check. Passwords may have been stolen back then, so change them."));
                case Verdict.Exposed:
                    return Alert(IconKind.AlertTriangle, Theme.Caution, Theme.CautionBg, Theme.CautionBorder, L("판정: 노출", "VERDICT: EXPOSED"),
                        L("오염된 런처 파일이 이 PC에 들어왔습니다", "Contaminated launcher files reached this PC"),
                        L("해킹 프로그램이 실행된 기록은 찾지 못했습니다. 9월 27일 이후 런처를 켠 적이 있다면 중요한 비밀번호는 바꿔 두세요.",
                          "No record of the hacking program running was found. If you opened the launcher after Sep 27, change your important passwords."));
                case Verdict.NotFound:
                    return Alert(IconKind.Info, Theme.MutedForeground, Theme.Card, Theme.Border, L("판정: 니케를 찾지 못함", "VERDICT: NIKKE NOT FOUND"),
                        L("니케 PC 런처도, 남아 있는 해킹 흔적도 찾지 못했습니다", "No NIKKE PC launcher and no remaining traces were found"),
                        L("다른 곳에 설치했다면 「다시 점검」의 고급 설정에서 경로를 지정하세요. 런처를 이미 지웠다면 지난 기록도 함께 지워져, 그동안 감염됐었는지는 알 수 없습니다.",
                          "If it is installed elsewhere, set the path in Advanced under Check again. If you already deleted the launcher, its logs are gone too, so a past infection cannot be confirmed."));
                default:
                    return Alert(IconKind.Check, Theme.Success, Theme.SuccessBg, Theme.SuccessBorder, L("판정: 흔적 없음", "VERDICT: NO KNOWN TRACES"),
                        L("알려진 감염 흔적을 찾지 못했습니다", "No known infection traces were found"),
                        L("100% 보장은 아닙니다. 런처를 다시 열기 전에 [정리하기]로 런처 캐시를 지우고 해커 서버를 차단해 두세요.",
                          "This is not a 100% guarantee. Before opening the launcher again, use [Clean up] to delete the launcher cache and block the hacker servers."));
            }
        }

        private static string FixLine(CheckId id, bool past)
        {
            if (past) return L("지울 파일은 아닙니다. 그때 비밀번호가 빠져나갔을 수 있다는 증거입니다.", "Nothing to delete. It is evidence that passwords may have been stolen back then.");
            switch (id)
            {
                case CheckId.BrowserDll: return L("정리하면 심어진 파일을 지웁니다 (해당 브라우저가 잠시 꺼짐)", "Clean up deletes the planted files (the browser closes for a moment)");
                case CheckId.Clsid: return L("정리하면 등록을 지웁니다", "Clean up deletes the registry entries");
                case CheckId.Processes: return L("정리하면 해당 프로그램을 끕니다", "Clean up closes those programs");
                case CheckId.LauncherData: return L("정리하면 런처 캐시를 지웁니다 (런처 로그인만 다시 하면 됨)", "Clean up deletes the launcher cache (you only sign in to the launcher again)");
                case CheckId.Temp: return L("정리하면 빼낸 정보 파일을 지웁니다", "Clean up deletes the stolen-data files");
                case CheckId.FullScan: return L("정리하면 파일을 지웁니다 (일부는 직접 확인하라고 안내)", "Clean up deletes the files (some are left for you to check)");
                case CheckId.InstallLogs: return L("정리하면 저장된 에이전트 파일을 지웁니다. 실행 기록은 증거로 남깁니다.", "Clean up deletes saved agent files. Run records are kept as evidence.");
                case CheckId.Extra: return L("정리하면 해커 서버와 연결된 프로그램을 끄고 DNS 기록을 비웁니다", "Clean up closes programs connected to the hacker server and clears the DNS records");
                default: return "";
            }
        }

        private static UiCard FindingCard(CheckId id, List<Finding> items)
        {
            bool crit = items.Any(f => f.Severity == Severity.Critical);
            bool past = items.All(f => f.Past);
            var badge = new UiBadge
            {
                Text = past ? L("과거 기록", "Past record") : crit ? L("감염", "Infected") : L("노출", "Exposed"),
                Variant = past ? BadgeVariant.Warning : crit ? BadgeVariant.Destructive : BadgeVariant.Caution,
            };
            var head = Layouts.Row(badge, Layouts.Text(Friendly(id), 10.5f, FontStyle.Bold, Theme.Foreground, new Padding(0, 1, 0, 4)));
            var stack = new List<Control> { head, Muted(FixLine(id, past), new Padding(0, 0, 0, 6)) };
            foreach (var f in items.Take(3))
                stack.Add(Layouts.Text("· " + f.Title, 8.5f, FontStyle.Regular, Theme.MutedForeground, new Padding(0, 0, 0, 2)));
            if (items.Count > 3) stack.Add(Muted(L($"… 외 {items.Count - 3}건 (자세히 보기)", $"… {items.Count - 3} more (Show details)"), new Padding(0)));
            return Layouts.Card(stack.ToArray());
        }

        private void LogVerdict(ScanResult r)
        {
            Log("=================================================", LogLevel.Header);
            var v = r.Verdict;
            Log(v == Verdict.Infected ? L("[판정] 감염", "[Verdict] INFECTED")
              : v == Verdict.PastInfection ? L("[판정] 감염됐던 기록 (과거 기록)", "[Verdict] PAST INFECTION (records only)")
              : v == Verdict.Exposed ? L("[판정] 노출", "[Verdict] EXPOSED")
              : v == Verdict.NotFound ? L("[판정] NIKKE 를 찾지 못함", "[Verdict] NIKKE not found")
              : L("[판정] 흔적 없음", "[Verdict] No known traces"),
                v == Verdict.Infected || v == Verdict.PastInfection ? LogLevel.Bad : v == Verdict.Exposed || v == Verdict.NotFound ? LogLevel.Warn : LogLevel.Ok);
            if (r.Unreadable.Count > 0)
            {
                Log(L($"[참고] 읽지 못해 검사가 불완전한 파일 {r.Unreadable.Count}개 (최대 50개 표시):", $"[Note] Files that could not be fully checked: {r.Unreadable.Count} (up to 50 shown):"), LogLevel.Warn);
                foreach (var u in r.Unreadable.Distinct().Take(50)) Log("        " + u, LogLevel.Detail);
            }
        }

        // ------------------------------------------------------------------
        // 정리
        // ------------------------------------------------------------------
        private async Task FixAsync()
        {
            if (_last == null) return;
            var opt = new FixOptions { DeleteFindings = _optClean.Checked && _optClean.Enabled, AlwaysDeleteTbsCache = _optTbs.Checked, Block = _optBlock.Checked };
            var fixes = opt.DeleteFindings ? _last.Fixable.ToList() : new List<Finding>();
            var review = opt.DeleteFindings ? _last.Review.ToList() : new List<AutostartItem>();
            bool wdo = _optWdo.Checked;
            if (fixes.Count == 0 && review.Count == 0 && !opt.AlwaysDeleteTbsCache && !opt.Block && !wdo)
            {
                MessageBox.Show(this, L("할 일을 하나 이상 고르세요.", "Choose at least one action."), Text);
                return;
            }

            var plan = new StringBuilder(L("다음을 실행합니다:\n\n", "The following will be done:\n\n"));
            foreach (var d in fixes.Select(f => f.FixDescription).Where(d => d != null).Distinct().Take(20)) plan.AppendLine("• " + d);
            if (fixes.Count > 20) plan.AppendLine(L($"• … 외 {fixes.Count - 20}건", $"• … {fixes.Count - 20} more"));
            if (opt.AlwaysDeleteTbsCache) plan.AppendLine(L("• 런처 캐시(tbs_cache) 삭제", "• Delete the launcher cache (tbs_cache)"));
            if (fixes.Any(f => f.Browser != null)) plan.AppendLine(L("• 관련 브라우저 종료", "• Close the affected browsers"));
            if (fixes.Count > 0 || opt.AlwaysDeleteTbsCache) plan.AppendLine(L("• NIKKE 런처와 게임 종료", "• Close the NIKKE launcher and the game"));
            if (review.Count > 0) plan.AppendLine(L($"• 확인 필요 항목 {review.Count}개 — 다음 창에서 지울 것을 직접 고릅니다", $"• {review.Count} items to check - you pick which to remove in the next window"));
            if (opt.Block) plan.AppendLine(L("• hosts·방화벽으로 해커 서버 차단 (관리자 확인 창)", "• Block the hacker servers in hosts and the firewall (admin prompt)"));
            if (wdo) plan.AppendLine(L("• 마지막에 Windows 백신 정밀 검사 (재부팅 전에 한 번 더 묻습니다)", "• Finally a Windows Defender deep scan (you are asked again before the restart)"));
            plan.AppendLine(L("\n점검 결과를 바탕 화면에 먼저 저장합니다. 브라우저에서 하던 작업이 있으면 먼저 저장하세요. 계속할까요?",
                              "\nThe check result is saved to the Desktop first. Save any work open in your browsers. Continue?"));
            if (MessageBox.Show(this, plan.ToString(), L("정리 확인", "Confirm clean-up"), MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;

            if (review.Count > 0)
                using (var dlg = new ReviewDialog(review))
                {
                    if (dlg.ShowDialog(this) != DialogResult.OK) return;
                    opt.RemoveAutostart = dlg.Selected;
                }

            var report = SaveReport(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), ReportName()));
            if (report == null)
            {
                Log(L("[X] 보고서를 저장하지 못해 아무것도 바꾸지 않았습니다.", "[X] Could not save the report, so nothing was changed."), LogLevel.Bad);
                MessageBox.Show(this, L("점검 결과를 저장하지 못해 정리를 취소했습니다.\n\n바탕 화면의 공간과 권한을 확인한 뒤 다시 시도해 주세요.",
                                        "The check result could not be saved, so the clean-up was canceled.\n\nCheck Desktop space and permissions, then try again."),
                                L("정리 취소", "Clean-up canceled"), MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            _lastReport = report;
            Log(L($"[+] 정리 전 보고서 저장: {report}", $"[+] Report saved before clean-up: {report}"), LogLevel.Action);
            foreach (var a in opt.RemoveAutostart)
                Log(L($"    지우기로 고른 항목: [{a.Where}] {a.Name} — {a.Display}", $"    Item chosen for removal: [{a.Where}] {a.Name} - {a.Display}"), LogLevel.Detail);

            // 정리하는 동안: 바닥글을 진행 상태로
            var busy = Button(L("정리하는 중…", "Cleaning up…"), ButtonVariant.Default, null, large: true);
            busy.Enabled = false;
            _footRight.Controls.Clear(); _footRight.Controls.Add(busy);
            _footLeft.Controls.Clear(); _footLeft.Controls.Add(Link(L("자세히 보기", "Show details"), (s, e) => ShowLog()));

            _cts = new CancellationTokenSource();
            Log("", LogLevel.Info);
            Log(L($"===== 정리 시작 {DateTime.Now:yyyy-MM-dd HH:mm:ss} =====", $"===== Clean-up started {DateTime.Now:yyyy-MM-dd HH:mm:ss} ====="), LogLevel.Header);
            FixOutcome outcome;
            try { outcome = await Task.Run(() => Remediator.Fix(fixes, opt, SafeLog)); }
            catch (Exception ex) { outcome = new FixOutcome { Failed = 1 }; Log(L("[X] 정리 중 오류: ", "[X] Error during clean-up: ") + ex, LogLevel.Bad); }
            finally { _cts.Dispose(); _cts = null; }

            Log(outcome.NeedsReboot ? L("[재시작 필요] 사용 중인 파일이 있어 일부를 지우지 못했습니다.", "[Restart needed] Some files are in use and could not be deleted.")
              : outcome.Failed > 0 ? L($"[주의] {outcome.Failed}건이 실패했습니다.", $"[Note] {outcome.Failed} tasks failed.")
              : L("[완료] 정리가 끝났습니다.", "[Done] Clean-up finished."), outcome.Failed > 0 || outcome.NeedsReboot ? LogLevel.Bad : LogLevel.Ok);
            SaveReport(report);   // 정리 결과까지 담아 같은 보고서를 갱신
            int removed = fixes.Select(f => f.FixDescription).Distinct().Count() + opt.RemoveAutostart.Count;
            _last = null;
            ShowDone(outcome, removed, opt.Block);
            if (wdo) await OfferOfflineScanAsync(report);
        }

        // ------------------------------------------------------------------
        // 4. 정리 완료
        // ------------------------------------------------------------------
        private void ShowDone(FixOutcome o, int removed, bool blocked)
        {
            var body = new List<Control>();
            if (o.NeedsReboot)
                body.Add(Alert(IconKind.AlertTriangle, Theme.Destructive, Theme.DestructiveBg, Theme.DestructiveBorder, L("재시작 필요", "RESTART NEEDED"),
                    L("Windows를 재시작한 뒤 이 프로그램을 한 번 더 실행하세요", "Restart Windows, then run this program once more"),
                    L("사용 중인 파일이 있어 일부를 지우지 못했습니다. 해킹 파일을 실행시키는 등록은 지웠으므로, 재시작하면 지울 수 있습니다.",
                      "Some files are in use and could not be deleted. The registry entry that runs them is gone, so they can be deleted after a restart.")));
            else if (o.Failed > 0)
                body.Add(Alert(IconKind.AlertTriangle, Theme.Warning, Theme.WarningBg, Theme.WarningBorder, L("일부 실패", "PARTLY FAILED"),
                    L($"{o.Failed}건을 처리하지 못했습니다", $"{o.Failed} tasks could not be completed"),
                    L("PC를 재시작한 뒤 다시 점검·정리해 주세요. 무엇이 실패했는지는 「자세히 보기」에 있습니다.", "Restart the PC and check again. Show details lists what failed.")));
            else
                body.Add(Alert(IconKind.Check, Theme.Success, Theme.SuccessBg, Theme.SuccessBorder, L("정리 완료", "CLEAN-UP DONE"),
                    removed > 0 ? L($"해킹 흔적 {removed}건을 정리했습니다", $"{removed} traces were removed") + (blocked ? L(" · 해커 서버를 막았습니다", " · hacker servers blocked") : "")
                                : (blocked ? L("런처 캐시를 정리하고 해커 서버를 막았습니다", "The launcher cache was cleaned and hacker servers blocked") : L("정리를 마쳤습니다", "Clean-up finished")),
                    L("다시 점검해서 결과를 확인할 수 있습니다.", "You can check again to confirm.")));
            if (_lastReport != null)
                body.Add(Muted(L("점검 결과 파일: ", "Result file: ") + _lastReport, new Padding(0, 0, 0, 14)));

            bool infected = _lastVerdict == Verdict.Infected || _lastVerdict == Verdict.PastInfection;
            var todo = new List<(string, string)>
            {
                (L("비밀번호 바꾸기", "Change passwords"), L("니케(레벨 인피니트) → 구글·네이버·카카오 → 디스코드·스팀 → 은행 순서로. 브라우저에 저장해 둔 비밀번호도.", "Level Infinite (NIKKE), then Google, Discord, Steam, banks. Also every password saved in your browsers.")),
                (L("「모든 기기에서 로그아웃」", "\"Sign out of all devices\""), L("빼낸 쿠키는 비밀번호 없이도 로그인에 쓰일 수 있습니다.", "Stolen cookies can sign in without the password.")),
            };
            if (infected)
            {
                todo.Add((L("2단계 인증 켜기", "Turn on 2-step verification"), L("중요한 계정부터.", "Important accounts first.")));
                todo.Add((L("코인 지갑 옮기기 (해당되면)", "Move crypto (if any)"), L("새 복구 문구로 만든 새 지갑으로.", "To a new wallet with a new recovery phrase.")));
                todo.Add((L("API 키·액세스 토큰 새로 발급", "Reissue API keys and access tokens"), L("이 PC에서 쓰거나 저장한 키·토큰 (GitHub·SSH·클라우드 등)은 폐기하고 새로 받으세요.", "Revoke and reissue any key or token used or saved on this PC (GitHub, SSH, cloud, ...).")));
                todo.Add((L("백신 전체 검사", "Full antivirus scan"), L("백신을 최신으로 업데이트한 뒤 전체 검사와 Windows 보안 오프라인 검사를 하세요.", "Update your antivirus, then run a full scan and a Microsoft Defender offline scan.")));
                todo.Add((L("다른 Windows 계정도 점검", "Check other Windows accounts"), L("이 PC를 쓰는 다른 계정으로 로그인해 한 번 더 실행하세요.", "Sign in to each other account on this PC and run this tool again.")));
            }
            else if (_lastVerdict != Verdict.Exposed)
                todo = todo.Take(1).Select(t => (t.Item1, L("9월 27일 15:41 이후 런처를 켠 적이 있다면 중요한 비밀번호는 바꿔 두는 게 안전합니다.", "If you used the launcher after Sep 27 15:41 (UTC+9), changing important passwords is the safe choice."))).ToList();

            body.Add(Heading(L("해야 할 일", "What to do next") ));
            body.Add(Muted(L("휴대폰 등 다른 기기에서 하세요. 이 프로그램이 대신할 수 없는 일입니다.", "Do these from another device such as your phone. This program cannot do them for you."), new Padding(0, 0, 0, 8)));
            var items = new List<Control>();
            foreach (var (t, d) in todo)
            {
                items.Add(new CheckBox { Text = t, AutoSize = true, Font = Theme.Font(10f, FontStyle.Bold), BackColor = Color.Transparent, Margin = new Padding(0, 8, 0, 0) });
                items.Add(Muted(d, new Padding(20, 0, 0, 4)));
            }
            body.Add(Layouts.Card(items.ToArray()));

            var notice = Layouts.Card(Layouts.Text(L("레벨 인피니트가 11월 4일 수정을 발표했지만, 해커가 어떻게 들어왔는지는 아직 알려지지 않았습니다. 차단은 그대로 두고, 런처를 다시 열기 전에 런처 캐시를 지우세요. 가장 확실한 방법은 Windows 재설치입니다 (이 프로그램은 알려진 흔적만 지웁니다).",
                                                    "Level Infinite announced a fix on Nov 4, but how the attacker got in is still unknown. Keep the blocks, and delete the launcher cache before opening the launcher again. Reinstalling Windows is the safest fix (this program removes only known traces)."),
                                                  9f, FontStyle.Regular, Theme.Caution, new Padding(0)));
            notice.SetTone(Theme.CautionBg, Theme.CautionBorder);
            body.Add(notice);

            SetView(body,
                new Control[]
                {
                    Link(L("자세히 보기", "Show details"), (s, e) => ShowLog()),
                    Link(L("니케 완전 삭제…", "Remove NIKKE…"), async (s, e) => await UninstallAsync()),
                },
                new Control[]
                {
                    Button(L("다시 점검해서 확인", "Check again"), ButtonVariant.Default, async (s, e) => await ScanAsync(), large: true),
                    Button(L("닫기", "Close"), ButtonVariant.Outline, (s, e) => Close(), large: true),
                });
        }

        // ------------------------------------------------------------------
        // Defender 오프라인 검사 / 니케 완전 삭제
        // ------------------------------------------------------------------
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
            var q = L("Windows 백신(Defender) 오프라인 검사로 PC 전체를 한 번 더 검사합니다. 이름이 알려진 다른 해킹 도구를 찾아 지웁니다.\n\n" +
                      "Windows가 꺼진 상태에서 하는 검사라 재부팅이 필요합니다. 재부팅하면 검사 화면이 자동으로 뜨고, 약 15분 뒤 Windows로 돌아옵니다.\n\n" +
                      "저장하지 않은 작업이 있으면 먼저 저장하세요. 지금 재부팅해서 검사할까요?",
                      "The Windows Defender offline scan checks the whole PC once more and removes other known hacking tools.\n\n" +
                      "It runs while Windows is off, so the PC must restart. The scan screen appears by itself, and Windows starts again after about 15 minutes.\n\n" +
                      "Save any unsaved work first. Restart now for the scan?");
            if (MessageBox.Show(this, q, L("Windows 백신 정밀 검사", "Windows Defender deep scan"), MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
            {
                Log(L("[-] 오프라인 검사를 하지 않았습니다.", "[-] Offline scan not started."), LogLevel.Detail);
                return;
            }
            var lines = new List<string>();
            Logger capture = (m, l) => { lines.Add(m); SafeLog(m, l); };
            _cts = new CancellationTokenSource();
            try { await Task.Run(() => Remediator.RunElevated(new List<string> { "WDO" }, capture, out _)); }
            finally { _cts.Dispose(); _cts = null; }
            if (lines.Any(l => l.Contains("[WDO] started")))
            {
                try { Directory.CreateDirectory(Path.GetDirectoryName(WdoMarker)); File.WriteAllText(WdoMarker, DateTime.Now.ToString("s")); } catch { }
            }
            else MessageBox.Show(this, string.Join("\n", lines.Where(l => !l.StartsWith("[*]")).Take(4)), L("Windows 백신 정밀 검사", "Windows Defender deep scan"), MessageBoxButtons.OK, MessageBoxIcon.Information);
            SaveReport(report);
        }

        /// <summary>NIKKE 완전 삭제 (선택, 두 번 확인). 계정·진행 상황은 서버에 있어 지워지지 않는다.</summary>
        private async Task UninstallAsync()
        {
            if (Busy) return;
            var q1 = L("니케를 계속 하실 분은 [아니요]를 누르세요. 게임은 그대로 둡니다.\n\n" +
                       "니케를 이 PC에서 완전히 삭제하실 분만 [예]를 누르세요. 다음을 지웁니다:\n" +
                       "  • 설치 폴더 (게임·런처)\n  • 런처 데이터 폴더\n  • 게임 데이터 폴더 (AppData\\LocalLow, 약 5GB)\n  • 내려받은 설치 파일 (nikkeminiloader…exe)\n" +
                       "  • 「설치된 앱」 항목, nikkelauncher:// 연결, 게임 설정\n  • 바로가기 (바탕 화면·시작 메뉴)\n\n" +
                       "계정과 게임 진행은 니케 서버에 있어 지워지지 않습니다. [예]를 누르면 지울 목록을 보여 주고 한 번 더 묻습니다.",
                       "Keep playing NIKKE? Press [No]. The game is left as it is.\n\n" +
                       "Only if you want NIKKE removed from this PC completely, press [Yes]. It deletes:\n" +
                       "  • install folder (game + launcher)\n  • launcher data folder\n  • game data folder (AppData\\LocalLow, about 5 GB)\n  • downloaded installer (nikkeminiloader...exe)\n" +
                       "  • Installed apps entry, nikkelauncher:// link, game settings\n  • shortcuts (Desktop, Start menu)\n\n" +
                       "Your account and progress stay on the NIKKE servers. [Yes] shows the list and asks once more.");
            if (MessageBox.Show(this, q1, L("니케 완전 삭제 (선택)", "Remove NIKKE completely (optional)"), MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                return;
            var installs = _last?.Installs.ToList() ?? new List<string>();
            var typed = _pathBox.Text.Trim().Trim('"');
            if (installs.Count == 0 && typed.Length > 0 && InstallLocator.IsInstall(typed)) installs.Add(typed);
            var plan = await Task.Run(() => Uninstaller.Plan(installs));
            if (plan.Count == 0)
            {
                MessageBox.Show(this, L("지울 니케 파일·등록이 없습니다.", "Nothing of NIKKE is left to remove."), L("니케 완전 삭제", "Remove NIKKE"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            var list = new StringBuilder(L("지울 항목:\n\n", "To be removed:\n\n"));
            foreach (var f in plan.Folders) list.AppendLine("• " + f);
            foreach (var f in plan.Files) list.AppendLine(L("• 설치 파일: ", "• installer: ") + f);
            if (plan.Links.Count > 0) list.AppendLine(L($"• 바로가기 {plan.Links.Count}개", $"• {plan.Links.Count} shortcut(s)"));
            foreach (var k in plan.UserKeys) list.AppendLine("• HKCU\\" + k);
            foreach (var k in plan.MachineKeys) list.AppendLine("• HKLM\\" + k.Substring(3));
            list.AppendLine(L("\n지운 뒤에는 되돌릴 수 없습니다. 정말 삭제할까요?", "\nThis cannot be undone. Really delete all of it?"));
            if (MessageBox.Show(this, list.ToString(), L("니케 완전 삭제 — 마지막 확인", "Remove NIKKE - final confirmation"), MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                return;
            var report = SaveReport(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), ReportName()));
            if (report == null) { Log(L("[X] 보고서를 저장하지 못해 아무것도 지우지 않았습니다.", "[X] Could not save the report, so nothing was deleted."), LogLevel.Bad); return; }

            _cts = new CancellationTokenSource();
            Log("", LogLevel.Info);
            Log(L($"===== 니케 완전 삭제 (사용자 선택) {DateTime.Now:yyyy-MM-dd HH:mm:ss} =====", $"===== Remove NIKKE (user choice) {DateTime.Now:yyyy-MM-dd HH:mm:ss} ====="), LogLevel.Header);
            int failed;
            try
            {
                failed = await Task.Run(() =>
                {
                    int fl = Uninstaller.Execute(plan, SafeLog, out var elevated);
                    if (elevated.Count > 0) fl += Remediator.RunElevated(elevated, SafeLog, out _);
                    return fl;
                });
            }
            finally { _cts.Dispose(); _cts = null; }
            Log(failed > 0 ? L("[주의] 일부 삭제 실패. PC를 재시작한 뒤 다시 실행하세요.", "[Note] Some items could not be removed. Restart the PC and run again.")
                           : L("[완료] 니케 삭제 완료. 재설치는 공식 홈페이지에서 런처를 새로 받으세요.", "[Done] NIKKE removed. To reinstall, get a new launcher from the official website."),
                failed > 0 ? LogLevel.Bad : LogLevel.Ok);
            SaveReport(report);
            MessageBox.Show(this, failed > 0 ? L("일부를 지우지 못했습니다. PC를 재시작한 뒤 다시 실행하세요.", "Some items could not be removed. Restart the PC and run again.")
                                             : L("니케를 이 PC에서 지웠습니다.", "NIKKE was removed from this PC."),
                L("니케 완전 삭제", "Remove NIKKE"), MessageBoxButtons.OK, failed > 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
        }

        // ------------------------------------------------------------------
        // 기록 · 보고서 · 언어
        // ------------------------------------------------------------------
        private void ShowLog()
        {
            if (_logForm == null || _logForm.IsDisposed)
            {
                _logForm = new Form
                {
                    Text = L("자세히 보기 — 점검 기록", "Details - check log"), Size = new Size(900, 600), StartPosition = FormStartPosition.CenterParent,
                    ShowInTaskbar = false, Font = Font, BackColor = Theme.Card,
                };
                _logForm.FormClosing += (s, e) => { if (e.CloseReason == CloseReason.UserClosing) { e.Cancel = true; _logForm.Hide(); } };
                var foot = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 56, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(12, 10, 12, 10), BackColor = Theme.Card };
                foot.Controls.Add(Button(L("닫기", "Close"), ButtonVariant.Outline, (s, e) => _logForm.Hide()));
                foot.Controls.Add(Button(L("보고서 저장", "Save report"), ButtonVariant.Default, (s, e) => SaveLogDialog()));
                _logForm.Controls.Add(_logBox);
                _logForm.Controls.Add(foot);
            }
            if (!_logForm.Visible) _logForm.Show(this);
            _logForm.Activate();
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

        private static string ReportName() => L("NikkeChecker_보고서_", "NikkeChecker_report_") + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".txt";

        private void Ui(Action a)
        {
            if (IsDisposed) return;
            try { BeginInvoke(a); } catch { }
        }

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
                case LogLevel.Header: c = Color.FromArgb(125, 211, 252); break;
                case LogLevel.Ok: c = Color.FromArgb(134, 239, 172); break;
                case LogLevel.Warn: c = Color.FromArgb(253, 224, 71); break;
                case LogLevel.Bad: c = Color.FromArgb(252, 165, 165); break;
                case LogLevel.Action: c = Color.FromArgb(110, 231, 183); break;
                case LogLevel.Detail: c = Color.FromArgb(161, 161, 170); break;
                default: c = Color.Gainsboro; break;
            }
            _logBox.SelectionStart = _logBox.TextLength;
            _logBox.SelectionLength = 0;
            _logBox.SelectionColor = c;
            _logBox.AppendText(msg + Environment.NewLine);
            _logBox.ScrollToCaret();
            // 점검 중 화면의 진행 글자: 최근 진행 기록 한 줄
            if (_progressDetail != null && !_progressDetail.IsDisposed && Busy && msg.Trim().Length > 0 && (level == LogLevel.Detail || level == LogLevel.Header))
                _progressDetail.Text = msg.Trim().Length > 110 ? msg.Trim().Substring(0, 110) + "…" : msg.Trim();
        }

        private string SaveReport(string path)
        {
            var text = _logBox.Text.Replace("\r\n", "\n").Replace("\n", "\r\n");
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
                if (d.ShowDialog(this) == DialogResult.OK) SaveReport(d.FileName);
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (Busy && MessageBox.Show(this, L("작업이 진행 중입니다. 종료할까요?", "A task is running. Close anyway?"), L("확인", "Confirm"), MessageBoxButtons.YesNo) != DialogResult.Yes)
            { e.Cancel = true; return; }
            _cts?.Cancel();
            base.OnFormClosing(e);
        }
    }

    /// <summary>「확인 필요」 항목 중 정리할 것을 고르는 창. Defender 가 악성으로 확인한 것만 미리 체크된다.</summary>
    internal sealed class ReviewDialog : Form
    {
        private readonly CheckedListBox _list = new CheckedListBox();
        private readonly List<AutostartItem> _items;

        public List<AutostartItem> Selected => _list.CheckedIndices.Cast<int>().Select(i => _items[i]).ToList();

        public ReviewDialog(List<AutostartItem> items)
        {
            _items = items;
            Text = L("확인이 필요한 프로그램·설정", "Programs and settings to check");
            Font = Theme.Font(9.5f);
            BackColor = Theme.Card;
            ClientSize = new Size(920, 480);
            MinimumSize = new Size(640, 360);
            StartPosition = FormStartPosition.CenterParent;
            MinimizeBox = MaximizeBox = false;

            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new Padding(20), BackColor = Theme.Card };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            Controls.Add(root);

            var intro = Layouts.Stack(
                Layouts.Text(L("직접 설치·설정한 게 아닌 것만 체크하세요", "Tick only what you did NOT install or set up yourself"), 11f, FontStyle.Bold),
                Layouts.Text(L("9월 27일 이후 생겼고 제작사 서명이 없는 자동 실행 프로그램과, 해커가 쓸 수 있는 설정입니다. Windows 백신이 악성으로 확인한 것은 미리 체크되어 있습니다.\n" +
                               "자동 실행: 등록을 끊고 파일을 지웁니다 (Windows·Program Files 안 파일은 등록만 끊음). 설정: 끄거나 Windows 기본값으로 되돌립니다. 브라우저: 끄기만 합니다.",
                               "Autostart programs new since Sep 27 without a publisher signature, and settings a hacker could use. Items Windows Defender confirmed as malware are ticked already.\n" +
                               "Autostarts: unregistered and their files deleted (files in Windows or Program Files are only unregistered). Settings: turned off or restored to the Windows default. Browsers: only closed."),
                               9f, FontStyle.Regular, Theme.MutedForeground, new Padding(0, 0, 0, 10)));
            intro.Dock = DockStyle.Fill;
            root.Controls.Add(intro);
            Shown += (s, e) => intro.FitWidth(root.ClientSize.Width - root.Padding.Horizontal);

            _list.Dock = DockStyle.Fill; _list.CheckOnClick = true; _list.HorizontalScrollbar = true; _list.IntegralHeight = false; _list.BorderStyle = BorderStyle.FixedSingle;
            foreach (var it in items)
            {
                var tag = it.Hidden ? L("위험 높음: 숨겨진 명령", "HIGH RISK: hidden command") : it.File != null ? Defender.VerdictText(it.Defender) : "";
                _list.Items.Add($"[{it.Where}] {it.Name}  —  {it.Display}" + (it.Date != "-" ? $"  ({L("생긴 날", "created")} {it.Date})" : "") + (tag.Length > 0 ? $"  [{tag}]" : ""), it.Defender == "malware");
            }
            root.Controls.Add(_list);

            var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, FlowDirection = FlowDirection.RightToLeft, BackColor = Theme.Card, Padding = new Padding(0, 12, 0, 0) };
            var cancel = new UiButton { Text = L("정리 취소", "Cancel clean-up"), Variant = ButtonVariant.Outline, AutoSize = true, DialogResult = DialogResult.Cancel, Margin = new Padding(8, 0, 0, 0) };
            var ok = new UiButton { Text = L("계속 (체크한 것만 정리)", "Continue (fix ticked only)"), Variant = ButtonVariant.Default, AutoSize = true, DialogResult = DialogResult.OK, Margin = new Padding(8, 0, 0, 0) };
            cancel.Size = cancel.GetPreferredSize(Size.Empty); ok.Size = ok.GetPreferredSize(Size.Empty);
            buttons.Controls.AddRange(new Control[] { ok, cancel });
            root.Controls.Add(buttons);
            AcceptButton = ok; CancelButton = cancel;
        }
    }
}
