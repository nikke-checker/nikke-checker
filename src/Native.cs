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
