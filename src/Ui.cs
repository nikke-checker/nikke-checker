using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Linq;
using System.Windows.Forms;

namespace NikkeChecker.Ui
{
    /// <summary>shadcn/ui 느낌의 색·글꼴·모양 (zinc 무채색, 1px 테두리, 둥근 모서리).</summary>
    public static class Theme
    {
        public static readonly Color Background = Color.FromArgb(0xFA, 0xFA, 0xFA);
        public static readonly Color Card = Color.White;
        public static readonly Color Muted = Color.FromArgb(0xF4, 0xF4, 0xF5);
        public static readonly Color Border = Color.FromArgb(0xE4, 0xE4, 0xE7);
        public static readonly Color Input = Color.FromArgb(0xD4, 0xD4, 0xD8);
        public static readonly Color Foreground = Color.FromArgb(0x09, 0x09, 0x0B);
        public static readonly Color MutedForeground = Color.FromArgb(0x63, 0x63, 0x6B);   // zinc-500 보다 진하게 (대비 4.5:1 이상)
        public static readonly Color Primary = Color.FromArgb(0x18, 0x18, 0x1B);
        public static readonly Color PrimaryHover = Color.FromArgb(0x3F, 0x3F, 0x46);
        public static readonly Color Ring = Color.FromArgb(0xA1, 0xA1, 0xAA);

        public static readonly Color Destructive = Color.FromArgb(0xDC, 0x26, 0x26);
        public static readonly Color DestructiveHover = Color.FromArgb(0xB9, 0x1C, 0x1C);
        public static readonly Color DestructiveBg = Color.FromArgb(0xFE, 0xF2, 0xF2);
        public static readonly Color DestructiveBorder = Color.FromArgb(0xFE, 0xCA, 0xCA);

        public static readonly Color Warning = Color.FromArgb(0xB4, 0x53, 0x09);
        public static readonly Color WarningBg = Color.FromArgb(0xFF, 0xF7, 0xED);
        public static readonly Color WarningBorder = Color.FromArgb(0xFE, 0xD7, 0xAA);

        public static readonly Color Caution = Color.FromArgb(0x85, 0x4D, 0x0E);
        public static readonly Color CautionBg = Color.FromArgb(0xFE, 0xFC, 0xE8);
        public static readonly Color CautionBorder = Color.FromArgb(0xFD, 0xE6, 0x8A);

        public static readonly Color Success = Color.FromArgb(0x15, 0x80, 0x3D);
        public static readonly Color SuccessBg = Color.FromArgb(0xF0, 0xFD, 0xF4);
        public static readonly Color SuccessBorder = Color.FromArgb(0xBB, 0xF7, 0xD0);

        public static readonly Color Info = Color.FromArgb(0x1D, 0x4E, 0xD8);

        public const int Radius = 8;

        public static string FontName => I18n.En ? "Segoe UI" : "Malgun Gothic";
        public static Font Font(float size, FontStyle style = FontStyle.Regular) => new Font(FontName, size, style);

        public static GraphicsPath Round(RectangleF r, float radius)
        {
            var p = new GraphicsPath();
            float d = Math.Min(radius * 2, Math.Min(r.Width, r.Height));
            if (d <= 0) { p.AddRectangle(r); return p; }
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }

        public static Color ParentBack(Control c)
        {
            for (var p = c.Parent; p != null; p = p.Parent)
                if (p.BackColor != Color.Transparent) return p.BackColor;
            return Background;
        }
    }

    // ----------------------------------------------------------------------
    public enum IconKind { None, Shield, Check, Alert, AlertTriangle, Circle, Spinner, ChevronRight, ChevronDown, Info, X, Clock }

    public static class Icons
    {
        /// <summary>선 아이콘 (lucide 느낌, 24 단위 좌표를 size 에 맞춰 그림).</summary>
        public static void Draw(Graphics g, IconKind kind, RectangleF r, Color color, float stroke = 2f, float spin = 0)
        {
            if (kind == IconKind.None) return;
            var state = g.Save();
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TranslateTransform(r.X, r.Y);
            g.ScaleTransform(r.Width / 24f, r.Height / 24f);
            using (var pen = new Pen(color, stroke) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
            {
                switch (kind)
                {
                    case IconKind.Shield:
                        g.DrawLines(pen, new[] { new PointF(12, 3), new PointF(20, 6), new PointF(20, 12) });
                        g.DrawBezier(pen, 20, 12, 20, 17, 16.5f, 20, 12, 21);
                        g.DrawBezier(pen, 12, 21, 7.5f, 20, 4, 17, 4, 12);
                        g.DrawLines(pen, new[] { new PointF(4, 12), new PointF(4, 6), new PointF(12, 3) });
                        g.DrawLines(pen, new[] { new PointF(9, 12), new PointF(11, 14), new PointF(15, 10) });
                        break;
                    case IconKind.Check:
                        g.DrawLines(pen, new[] { new PointF(5, 12.5f), new PointF(10, 17), new PointF(19, 7) });
                        break;
                    case IconKind.Alert:
                        g.DrawEllipse(pen, 3, 3, 18, 18);
                        g.DrawLine(pen, 12, 7.5f, 12, 13);
                        g.DrawLine(pen, 12, 16.5f, 12.01f, 16.5f);
                        break;
                    case IconKind.AlertTriangle:
                        g.DrawPolygon(pen, new[] { new PointF(12, 3), new PointF(21.5f, 20), new PointF(2.5f, 20) });
                        g.DrawLine(pen, 12, 9.5f, 12, 13.5f);
                        g.DrawLine(pen, 12, 16.8f, 12.01f, 16.8f);
                        break;
                    case IconKind.Circle:
                        g.DrawEllipse(pen, 4, 4, 16, 16);
                        break;
                    case IconKind.Spinner:
                        g.DrawArc(pen, 4, 4, 16, 16, spin, 270);
                        break;
                    case IconKind.ChevronRight:
                        g.DrawLines(pen, new[] { new PointF(9, 6), new PointF(15, 12), new PointF(9, 18) });
                        break;
                    case IconKind.ChevronDown:
                        g.DrawLines(pen, new[] { new PointF(6, 9), new PointF(12, 15), new PointF(18, 9) });
                        break;
                    case IconKind.Info:
                        g.DrawEllipse(pen, 3, 3, 18, 18);
                        g.DrawLine(pen, 12, 11, 12, 16.5f);
                        g.DrawLine(pen, 12, 7.5f, 12.01f, 7.5f);
                        break;
                    case IconKind.X:
                        g.DrawLine(pen, 7, 7, 17, 17); g.DrawLine(pen, 17, 7, 7, 17);
                        break;
                    case IconKind.Clock:
                        g.DrawEllipse(pen, 3, 3, 18, 18);
                        g.DrawLines(pen, new[] { new PointF(12, 7), new PointF(12, 12), new PointF(15.5f, 14) });
                        break;
                }
            }
            g.Restore(state);
        }
    }

    // ----------------------------------------------------------------------
    public enum ButtonVariant { Default, Outline, Ghost, Destructive, Link, Secondary }

    /// <summary>shadcn Button: default / outline / ghost / destructive / link / secondary.</summary>
    public class UiButton : Control, IButtonControl
    {
        private bool _hover, _down;
        public ButtonVariant Variant { get; set; } = ButtonVariant.Default;
        public IconKind Icon { get; set; } = IconKind.None;
        public bool Large { get; set; }
        public DialogResult DialogResult { get; set; }

        public UiButton()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer |
                     ControlStyles.ResizeRedraw | ControlStyles.Selectable | ControlStyles.StandardClick | ControlStyles.SupportsTransparentBackColor, true);
            TabStop = true;
            Cursor = Cursors.Hand;
            AccessibleRole = AccessibleRole.PushButton;
            Font = Theme.Font(9.5f, FontStyle.Bold);
            Margin = new Padding(0);
        }

        public void NotifyDefault(bool value) { }
        public void PerformClick() { if (Enabled) OnClick(EventArgs.Empty); }

        protected override void OnClick(EventArgs e)
        {
            base.OnClick(e);
            if (DialogResult != DialogResult.None && FindForm() is Form f) f.DialogResult = DialogResult;
        }

        public override Size GetPreferredSize(Size proposed)
        {
            var sz = TextRenderer.MeasureText(Text ?? "", Font, Size.Empty, TextFormatFlags.SingleLine | TextFormatFlags.NoPadding);
            int padX = Variant == ButtonVariant.Link ? 0 : (Large ? 28 : 16);
            int h = Variant == ButtonVariant.Link ? sz.Height + 4 : (Large ? 46 : 36);
            int icon = Icon != IconKind.None ? (int)(Font.Height * 1.1f) + 6 : 0;
            return new Size(sz.Width + padX * 2 + icon, h);
        }

        protected override void OnTextChanged(EventArgs e) { base.OnTextChanged(e); if (AutoSize) Size = GetPreferredSize(Size.Empty); Invalidate(); }
        protected override void OnFontChanged(EventArgs e) { base.OnFontChanged(e); if (AutoSize) Size = GetPreferredSize(Size.Empty); }
        protected override void OnMouseEnter(EventArgs e) { _hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { _hover = false; _down = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnMouseDown(MouseEventArgs e) { _down = true; Invalidate(); base.OnMouseDown(e); }
        protected override void OnMouseUp(MouseEventArgs e) { _down = false; Invalidate(); base.OnMouseUp(e); }
        protected override void OnGotFocus(EventArgs e) { Invalidate(); base.OnGotFocus(e); }
        protected override void OnLostFocus(EventArgs e) { Invalidate(); base.OnLostFocus(e); }
        protected override void OnEnabledChanged(EventArgs e) { Invalidate(); base.OnEnabledChanged(e); }

        protected override bool IsInputKey(Keys keyData) => keyData == Keys.Enter || keyData == Keys.Space || base.IsInputKey(keyData);
        protected override void OnKeyUp(KeyEventArgs e)
        {
            base.OnKeyUp(e);
            if (e.KeyCode == Keys.Enter || e.KeyCode == Keys.Space) PerformClick();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Theme.ParentBack(this));
            var r = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
            Color bg = Color.Transparent, fg = Theme.Foreground, border = Color.Transparent;
            switch (Variant)
            {
                case ButtonVariant.Default: bg = _hover ? Theme.PrimaryHover : Theme.Primary; fg = Color.White; break;
                case ButtonVariant.Destructive: bg = _hover ? Theme.DestructiveHover : Theme.Destructive; fg = Color.White; break;
                case ButtonVariant.Secondary: bg = _hover ? Theme.Border : Theme.Muted; break;
                case ButtonVariant.Outline: bg = _hover ? Theme.Muted : Theme.Card; border = Theme.Input; break;
                case ButtonVariant.Ghost: bg = _hover ? Theme.Muted : Color.Transparent; break;
                case ButtonVariant.Link: fg = _hover ? Theme.Foreground : Theme.Info; break;
            }
            if (!Enabled) { bg = bg == Color.Transparent ? bg : Color.FromArgb(110, bg); fg = Color.FromArgb(120, fg); }
            if (_down && bg != Color.Transparent) bg = ControlPaint.Dark(bg, 0.05f);
            using (var path = Theme.Round(r, 6))
            {
                if (bg != Color.Transparent) using (var b = new SolidBrush(bg)) g.FillPath(b, path);
                if (border != Color.Transparent) using (var p = new Pen(border)) g.DrawPath(p, path);
                if (Focused && ShowFocusCues)
                    using (var ring = Theme.Round(new RectangleF(1.5f, 1.5f, Width - 3.5f, Height - 3.5f), 6))
                    using (var p = new Pen(Theme.Ring, 2f)) g.DrawPath(p, ring);
            }
            var flags = TextFormatFlags.SingleLine | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding;
            var textSize = TextRenderer.MeasureText(g, Text ?? "", Font, Size.Empty, flags);
            int iconW = Icon != IconKind.None ? (int)(Font.Height * 1.1f) : 0;
            int total = textSize.Width + (iconW > 0 ? iconW + 6 : 0);
            int x = Variant == ButtonVariant.Link ? 0 : (Width - total) / 2;
            if (iconW > 0)
            {
                Icons.Draw(g, Icon, new RectangleF(x, (Height - iconW) / 2f, iconW, iconW), fg, 2f);
                x += iconW + 6;
            }
            TextRenderer.DrawText(g, Text ?? "", Font, new Rectangle(x, 0, Width - x, Height), fg, flags | TextFormatFlags.Left);
            if (Variant == ButtonVariant.Link && _hover)
                using (var p = new Pen(fg)) g.DrawLine(p, x, Height - 3, x + textSize.Width, Height - 3);
        }
    }

    // ----------------------------------------------------------------------
    /// <summary>shadcn Card / Alert 바탕: 둥근 모서리, 1px 테두리, 흰 바탕.</summary>
    public class UiCard : Panel
    {
        public Color Fill { get; set; } = Theme.Card;
        public Color Stroke { get; set; } = Theme.Border;
        public IconKind Icon { get; set; } = IconKind.None;
        public Color IconColor { get; set; } = Theme.Foreground;
        public int IconSize { get; set; } = 22;

        public UiCard()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            Padding = new Padding(20, 16, 20, 16);
            BackColor = Fill;
            Margin = new Padding(0, 0, 0, 12);
        }

        protected override void OnPaintBackground(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.Clear(Theme.ParentBack(this));
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using (var path = Theme.Round(new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f), Theme.Radius))
            {
                using (var b = new SolidBrush(Fill)) g.FillPath(b, path);
                using (var p = new Pen(Stroke)) g.DrawPath(p, path);
            }
            if (Icon != IconKind.None)
                Icons.Draw(g, Icon, new RectangleF(Padding.Left - IconSize - 12, Padding.Top + 1, IconSize, IconSize), IconColor, 2f);
        }

        public void SetTone(Color fill, Color stroke) { Fill = fill; Stroke = stroke; BackColor = fill; Invalidate(); }
    }

    // ----------------------------------------------------------------------
    public enum BadgeVariant { Default, Destructive, Warning, Caution, Success, Outline, Secondary }

    /// <summary>shadcn Badge.</summary>
    public class UiBadge : Control
    {
        public BadgeVariant Variant { get; set; }

        public UiBadge()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            Font = Theme.Font(8.25f, FontStyle.Bold);
            AccessibleRole = AccessibleRole.StaticText;
            Margin = new Padding(0, 2, 12, 0);
        }

        public override Size GetPreferredSize(Size proposed)
        {
            var sz = TextRenderer.MeasureText(Text ?? "", Font, Size.Empty, TextFormatFlags.SingleLine | TextFormatFlags.NoPadding);
            return new Size(sz.Width + 18, sz.Height + 6);
        }

        protected override void OnTextChanged(EventArgs e) { base.OnTextChanged(e); Size = GetPreferredSize(Size.Empty); Invalidate(); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Theme.ParentBack(this));
            Color bg, fg, border = Color.Transparent;
            switch (Variant)
            {
                case BadgeVariant.Destructive: bg = Theme.Destructive; fg = Color.White; break;
                case BadgeVariant.Warning: bg = Theme.WarningBg; fg = Theme.Warning; border = Theme.WarningBorder; break;
                case BadgeVariant.Caution: bg = Theme.CautionBg; fg = Theme.Caution; border = Theme.CautionBorder; break;
                case BadgeVariant.Success: bg = Theme.SuccessBg; fg = Theme.Success; border = Theme.SuccessBorder; break;
                case BadgeVariant.Outline: bg = Theme.Card; fg = Theme.Foreground; border = Theme.Border; break;
                case BadgeVariant.Secondary: bg = Theme.Muted; fg = Theme.Foreground; break;
                default: bg = Theme.Primary; fg = Color.White; break;
            }
            using (var path = Theme.Round(new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f), (Height - 1) / 2f))
            {
                using (var b = new SolidBrush(bg)) g.FillPath(b, path);
                if (border != Color.Transparent) using (var p = new Pen(border)) g.DrawPath(p, path);
            }
            TextRenderer.DrawText(g, Text ?? "", Font, ClientRectangle, fg, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine);
        }
    }

    // ----------------------------------------------------------------------
    /// <summary>shadcn Progress.</summary>
    public class UiProgress : Control
    {
        private int _value;
        public int Value { get => _value; set { _value = Math.Max(0, Math.Min(100, value)); Invalidate(); } }

        public UiProgress()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            Height = 8;
            AccessibleRole = AccessibleRole.ProgressBar;
            Margin = new Padding(0, 4, 0, 8);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Theme.ParentBack(this));
            using (var track = Theme.Round(new RectangleF(0, 0, Width - 1, Height - 1), (Height - 1) / 2f))
            using (var b = new SolidBrush(Theme.Muted)) g.FillPath(b, track);
            float w = (Width - 1) * _value / 100f;
            if (w >= Height)
                using (var fill = Theme.Round(new RectangleF(0, 0, w, Height - 1), (Height - 1) / 2f))
                using (var b = new SolidBrush(Theme.Primary)) g.FillPath(b, fill);
            AccessibleDescription = _value + "%";
        }
    }

    // ----------------------------------------------------------------------
    public enum StepState { Pending, Running, Ok, Found, Warn, Review, Unknown, Skipped }

    /// <summary>점검 단계 한 줄: 상태 아이콘 + 이름 + 결과 글자.</summary>
    public class UiStepRow : Control
    {
        private static readonly Timer Spin = new Timer { Interval = 60 };
        private static float _angle;
        private static readonly List<UiStepRow> Running = new List<UiStepRow>();
        static UiStepRow() { Spin.Tick += (s, e) => { _angle = (_angle + 24) % 360; foreach (var r in Running.ToList()) r.Invalidate(); }; }

        private StepState _state;
        public string Status { get; private set; } = "";

        public StepState State => _state;

        public UiStepRow()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            Height = 40;
            Font = Theme.Font(10f);
            AccessibleRole = AccessibleRole.ListItem;
            Margin = new Padding(0);
        }

        public void Set(StepState state, string status)
        {
            _state = state; Status = status ?? "";
            AccessibleName = Text + " — " + Status;
            if (state == StepState.Running) { if (!Running.Contains(this)) Running.Add(this); Spin.Start(); }
            else { Running.Remove(this); if (Running.Count == 0) Spin.Stop(); }
            Invalidate();
        }

        protected override void Dispose(bool disposing) { Running.Remove(this); base.Dispose(disposing); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            var bg = _state == StepState.Running ? Theme.Muted : Theme.ParentBack(this);
            g.Clear(bg);
            IconKind icon; Color ic, sc; bool bold = false;
            switch (_state)
            {
                case StepState.Running: icon = IconKind.Spinner; ic = Theme.Foreground; sc = Theme.Foreground; break;
                case StepState.Ok: icon = IconKind.Check; ic = Theme.Success; sc = Theme.Success; break;
                case StepState.Found: icon = IconKind.Alert; ic = Theme.Destructive; sc = Theme.Destructive; bold = true; break;
                case StepState.Warn: icon = IconKind.AlertTriangle; ic = Theme.Warning; sc = Theme.Warning; bold = true; break;
                case StepState.Review: icon = IconKind.Info; ic = Theme.Warning; sc = Theme.Warning; break;
                case StepState.Unknown: icon = IconKind.Info; ic = Theme.MutedForeground; sc = Theme.MutedForeground; break;
                case StepState.Skipped: icon = IconKind.Circle; ic = Theme.Border; sc = Theme.MutedForeground; break;
                default: icon = IconKind.Circle; ic = Theme.Input; sc = Theme.MutedForeground; break;
            }
            int pad = 16, isz = 18;
            Icons.Draw(g, icon, new RectangleF(pad, (Height - isz) / 2f, isz, isz), ic, 2.2f, _angle);
            var nameColor = _state == StepState.Pending || _state == StepState.Skipped ? Theme.MutedForeground : Theme.Foreground;
            using (var sf = Theme.Font(9f, bold ? FontStyle.Bold : FontStyle.Regular))
            {
                var ssz = TextRenderer.MeasureText(g, Status, sf, Size.Empty, TextFormatFlags.SingleLine);
                TextRenderer.DrawText(g, Status, sf, new Rectangle(Width - pad - ssz.Width, 0, ssz.Width + 2, Height), sc,
                    TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.Right);
                var nameRect = new Rectangle(pad + isz + 12, 0, Width - (pad + isz + 12) - ssz.Width - pad - 12, Height);
                TextRenderer.DrawText(g, Text ?? "", Font, nameRect, nameColor, TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis);
            }
        }
    }

    // ----------------------------------------------------------------------
    /// <summary>위에서 아래로 쌓고 자식 폭을 맞춰 주는 세로 스택 (shadcn 의 flex-col gap).</summary>
    public class UiStack : FlowLayoutPanel
    {
        public UiStack()
        {
            FlowDirection = FlowDirection.TopDown;
            WrapContents = false;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            Margin = new Padding(0);
            Padding = new Padding(0);
            BackColor = Color.Transparent;
        }

        /// <summary>자식 폭을 이 너비로 맞춘다 (Label 은 줄바꿈 폭).</summary>
        public void FitWidth(int width)
        {
            SuspendLayout();
            foreach (Control c in Controls)
            {
                if (c is UiBadge || (c is UiButton b && b.AutoSize) || "keep".Equals(c.Tag)) continue;
                int w = Math.Max(10, width - c.Margin.Horizontal);
                if (c is Label l && l.AutoSize) l.MaximumSize = new Size(w, 0);
                else if (c is CheckBox cb)
                {
                    // 긴 옵션 글자는 폭 안에서 줄바꿈
                    cb.AutoSize = false;
                    cb.Width = w;
                    var sz = TextRenderer.MeasureText(cb.Text, cb.Font, new Size(w - 24, 0), TextFormatFlags.WordBreak);
                    cb.Height = Math.Max(cb.Font.Height + 8, sz.Height + 6);
                    cb.CheckAlign = ContentAlignment.TopLeft;
                    cb.TextAlign = ContentAlignment.TopLeft;
                }
                else c.Width = w;
                if (c is UiCard card) Layouts.FitCard(card);
                if (c is UiStack s) s.FitWidth(w);
                if (c is UiCollapsible col) col.FitWidth(w);
            }
            ResumeLayout(true);
        }
    }

    public static class Layouts
    {
        /// <summary>카드 안 스택의 폭을 카드 안쪽 폭에 맞추고, 카드 높이를 내용에 맞춘다.</summary>
        public static void FitCard(UiCard card)
        {
            int inner = card.Width - card.Padding.Horizontal;
            foreach (Control c in card.Controls)
            {
                c.Left = card.Padding.Left; c.Top = card.Padding.Top;
                if (c is UiStack s)
                {
                    s.FitWidth(inner);
                    s.PerformLayout();
                    s.Size = new Size(inner, s.GetPreferredSize(new Size(inner, 0)).Height);
                }
                else c.Width = inner;
            }
            int h = card.Controls.Cast<Control>().Select(c => c.Bottom).DefaultIfEmpty(card.Padding.Top).Max();
            card.Height = h + card.Padding.Bottom;
        }

        public static Label Text(string text, float size = 9.5f, FontStyle style = FontStyle.Regular, Color? color = null, Padding? margin = null) =>
            new Label
            {
                Text = text, AutoSize = true, Font = Theme.Font(size, style), ForeColor = color ?? Theme.Foreground,
                BackColor = Color.Transparent, Margin = margin ?? new Padding(0, 0, 0, 6), UseMnemonic = false,
            };

        public static UiStack Stack(params Control[] children)
        {
            var s = new UiStack();
            s.Controls.AddRange(children);
            return s;
        }

        public static UiCard Card(params Control[] children)
        {
            var card = new UiCard();
            var s = Stack(children);
            card.Controls.Add(s);
            return card;
        }

        public static FlowLayoutPanel Row(params Control[] children)
        {
            var r = new FlowLayoutPanel { FlowDirection = FlowDirection.LeftToRight, WrapContents = false, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Margin = new Padding(0), BackColor = Color.Transparent, Tag = "keep" };
            r.Controls.AddRange(children);
            return r;
        }
    }

    // ----------------------------------------------------------------------
    /// <summary>shadcn Collapsible: 머리글 버튼 + 펼치는 내용.</summary>
    public class UiCollapsible : UiStack
    {
        private readonly UiButton _header = new UiButton { Variant = ButtonVariant.Ghost, AutoSize = true, Icon = IconKind.ChevronRight };
        public UiStack Content { get; } = new UiStack();
        public bool Expanded { get; private set; }

        public UiCollapsible(string title)
        {
            _header.Text = title;
            _header.Font = Theme.Font(9.5f);
            _header.Click += (s, e) => Toggle();
            _header.AccessibleRole = AccessibleRole.OutlineButton;
            Content.Visible = false;
            Content.Margin = new Padding(8, 4, 0, 0);
            Controls.Add(_header);
            Controls.Add(Content);
        }

        public void Toggle()
        {
            Expanded = !Expanded;
            Content.Visible = Expanded;
            _header.Icon = Expanded ? IconKind.ChevronDown : IconKind.ChevronRight;
            _header.Invalidate();
            Parent?.PerformLayout();
        }

        public new void FitWidth(int width) => Content.FitWidth(Math.Max(10, width - Content.Margin.Horizontal));
    }
}
