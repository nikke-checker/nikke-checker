using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace NikkeChecker
{
    /// <summary>
    /// 화면 언어. 우선순위: --lang 인자 > 실행 파일 이름에 _EN > 한국어 Windows(표시 언어 또는 시스템 코드 페이지 949) > 영어.
    /// 한국어가 아닌 Windows 의 기본 글꼴에는 한글이 없어 네모로 깨지므로 그런 PC 에서는 영어로 보인다.
    /// </summary>
    public static class I18n
    {
        public static bool En { get; private set; }
        public static string Code => En ? "en" : "ko";

        public static void Init(string[] args, string exePath)
        {
            int i = Array.FindIndex(args, a => a.Equals("--lang", StringComparison.OrdinalIgnoreCase));
            if (i >= 0 && i + 1 < args.Length) { En = args[i + 1].Equals("en", StringComparison.OrdinalIgnoreCase); return; }
            var name = Path.GetFileNameWithoutExtension(exePath ?? "") ?? "";
            if (name.EndsWith("_EN", StringComparison.OrdinalIgnoreCase)) { En = true; return; }
            bool korean = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "ko";
            try { korean |= Encoding.Default.CodePage == 949; } catch { }
            En = !korean;
        }

        public static void Set(bool en) => En = en;

        /// <summary>한국어/영어 중 현재 언어의 문장.</summary>
        public static string L(string ko, string en) => En ? en : ko;
    }
}
