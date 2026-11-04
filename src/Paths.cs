using System;
using System.IO;
using System.Linq;

namespace NikkeChecker
{
    /// <summary>
    /// 시스템 경로는 환경 변수가 아니라 Windows API(알려진 폴더)로 얻는다 (햄찌 v4.2).
    /// 사용자 권한 악성코드가 HKCU\Environment 로 ProgramFiles 등을 바꿔 관리자 작업을 엉뚱한 곳으로 돌리지 못하게 하기 위함.
    /// 외부 프로그램도 System32 전체 경로로 실행한다 (실행 파일과 같은 폴더의 가짜 sc.exe 등이 대신 실행되지 않게).
    /// </summary>
    public static class Paths
    {
        public static string Windows => Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        public static string System32 => Environment.GetFolderPath(Environment.SpecialFolder.System);
        public static string Sys(string exe) => Path.Combine(System32, exe);

        public static string[] ProgramFilesDirs => new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        }.Where(p => !string.IsNullOrEmpty(p)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

        public static bool IsInside(string path, string root)
        {
            if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(root)) return false;
            try
            {
                var p = Path.GetFullPath(path).TrimEnd('\\');
                var r = Path.GetFullPath(root).TrimEnd('\\');
                return p.Equals(r, StringComparison.OrdinalIgnoreCase) || p.StartsWith(r + "\\", StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        /// <summary>Windows·Program Files 안 파일 — 정상 프로그램일 수 있어 자동으로 지우지 않는다.</summary>
        public static bool IsProtected(string path) =>
            IsInside(path, Windows) || ProgramFilesDirs.Any(r => IsInside(path, r));
    }
}
