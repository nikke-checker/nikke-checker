using System;
using System.Linq;
using System.Windows.Forms;

namespace NikkeChecker
{
    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            I18n.Init(args, Application.ExecutablePath);

            // 승격된 하위 프로세스: 관리자 작업만 수행하고 종료
            if (args.Length >= 3 && args[0] == "--elevated")
                return Remediator.RunElevatedMode(args[1], args[2]);
            if (args.Length >= 3 && args[0] == "--audit")
                return Remediator.RunAuditMode(args[1], args[2]);

            Native.SuppressDriveErrorDialogs();
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
            return 0;
        }
    }
}
