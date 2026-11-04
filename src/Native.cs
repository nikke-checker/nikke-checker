using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace NikkeChecker
{
    internal static class Native
    {
        private const uint TH32CS_SNAPMODULE = 0x00000008;
        private const uint TH32CS_SNAPMODULE32 = 0x00000010;
        private const int ERROR_BAD_LENGTH = 24;
        private static readonly IntPtr InvalidHandle = new IntPtr(-1);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct MODULEENTRY32W
        {
            public uint dwSize;
            public uint th32ModuleID;
            public uint th32ProcessID;
            public uint GlblcntUsage;
            public uint ProccntUsage;
            public IntPtr modBaseAddr;
            public uint modBaseSize;
            public IntPtr hModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExePath;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool Module32FirstW(IntPtr snapshot, ref MODULEENTRY32W entry);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool Module32NextW(IntPtr snapshot, ref MODULEENTRY32W entry);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll")]
        private static extern uint SetErrorMode(uint mode);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WIN32_FIND_DATAW
        {
            public uint dwFileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime, ftLastAccessTime, ftLastWriteTime;
            public uint nFileSizeHigh, nFileSizeLow, dwReserved0, dwReserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string cFileName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string cAlternateFileName;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr FindFirstFileExW(string name, int infoLevel, out WIN32_FIND_DATAW data, int searchOp, IntPtr filter, int flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool FindNextFileW(IntPtr h, out WIN32_FIND_DATAW data);

        [DllImport("kernel32.dll")]
        private static extern bool FindClose(IntPtr h);

        /// <summary>
        /// 폴더 아래 모든 파일 이름을 빠르게 훑는다. 정션·심볼릭 링크 폴더는 따라가지 않는다.
        /// 반환값: 확인한 파일 수.
        /// </summary>
        public static long WalkFileNames(string root, string[] skipDirs, Action<string, string> onFile,
            System.Threading.CancellationToken ct, Action<long> progress)
        {
            const uint FILE_ATTRIBUTE_DIRECTORY = 0x10, FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
            const int FindExInfoBasic = 1, FIND_FIRST_EX_LARGE_FETCH = 2;
            long files = 0;
            var stack = new Stack<string>();
            stack.Push(root.TrimEnd('\\'));
            while (stack.Count > 0)
            {
                ct.ThrowIfCancellationRequested();
                var dir = stack.Pop();
                var h = FindFirstFileExW(@"\\?\" + dir + @"\*", FindExInfoBasic, out var fd, 0, IntPtr.Zero, FIND_FIRST_EX_LARGE_FETCH);
                if (h == InvalidHandle) continue;
                try
                {
                    do
                    {
                        var n = fd.cFileName;
                        if (n == "." || n == "..") continue;
                        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
                        {
                            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) continue;
                            var sub = dir + "\\" + n;
                            bool skip = false;
                            foreach (var s in skipDirs) if (string.Equals(sub, s, StringComparison.OrdinalIgnoreCase)) { skip = true; break; }
                            if (!skip) stack.Push(sub);
                        }
                        else
                        {
                            files++;
                            onFile(dir, n);
                            if ((files & 0xFFF) == 0) progress?.Invoke(files);
                        }
                    } while (FindNextFileW(h, out fd));
                }
                finally { FindClose(h); }
            }
            return files;
        }

        /// <summary>빈 카드 리더/광학 드라이브 접근 시 "디스크 없음" 대화상자가 뜨지 않게 한다.</summary>
        public static void SuppressDriveErrorDialogs()
        {
            try { SetErrorMode(0x0001 /*SEM_FAILCRITICALERRORS*/ | 0x8000 /*SEM_NOOPENFILEERRORBOX*/); } catch { }
        }

        /// <summary>프로세스에 로드된 모듈 경로 목록. 접근이 거부되면 null.</summary>
        public static List<string> GetModulePaths(int pid)
        {
            IntPtr snap = InvalidHandle;
            for (int attempt = 0; attempt < 3; attempt++)
            {
                snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, (uint)pid);
                if (snap != InvalidHandle) break;
                if (Marshal.GetLastWin32Error() != ERROR_BAD_LENGTH) return null;
            }
            if (snap == InvalidHandle) return null;

            var list = new List<string>();
            try
            {
                var e = new MODULEENTRY32W { dwSize = (uint)Marshal.SizeOf(typeof(MODULEENTRY32W)) };
                if (!Module32FirstW(snap, ref e)) return list;
                do { if (!string.IsNullOrEmpty(e.szExePath)) list.Add(e.szExePath); }
                while (Module32NextW(snap, ref e));
            }
            finally { CloseHandle(snap); }
            return list;
        }
    }
}
