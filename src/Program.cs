using System;
using System.Windows.Forms;

namespace NikkeChecker
{
    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            // 승격된 하위 프로세스: hosts/방화벽 차단만 수행하고 종료
            if (args.Length >= 2 && args[0] == "--apply-block")
                return Remediator.RunBlockMode(args[1]);

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
            return 0;
        }
    }
}
