using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace NikkeChecker
{
    public enum SigStatus { Valid, NotSigned, Invalid, Unknown }

    /// <summary>
    /// Authenticode 서명 확인 (WinVerifyTrust). 파일에 서명이 없으면 Windows 카탈로그 서명도 확인한다
    /// (Windows 기본 파일 대부분은 카탈로그로 서명되어 있어, 파일 자체 서명만 보면 "서명 없음"으로 잘못 보인다).
    /// 인증서 폐기 확인은 하지 않는다 (네트워크 접속 없음).
    /// </summary>
    public static class Signature
    {
        private static readonly Guid GenericVerifyV2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        private const uint WTD_UI_NONE = 2, WTD_REVOKE_NONE = 0, WTD_CHOICE_FILE = 1, WTD_CHOICE_CATALOG = 2;
        private const uint WTD_STATEACTION_VERIFY = 1, WTD_STATEACTION_CLOSE = 2;
        private const uint WTD_REVOCATION_CHECK_NONE = 0x10, WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;
        private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
        private const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
        private const int TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_CATALOG_INFO
        {
            public uint cbStruct;
            public uint dwCatalogVersion;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszCatalogFilePath;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberTag;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberFilePath;
            public IntPtr hMemberFile;
            public IntPtr pbCalculatedFileHash;
            public uint cbCalculatedFileHash;
            public IntPtr pcCatalogContext;
            public IntPtr hCatAdmin;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pInfo;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CATALOG_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile;
        }

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
        private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem,
            [MarshalAs(UnmanagedType.LPWStr)] string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile, ref uint pcbHash, byte[] pbHash, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

        [DllImport("wintrust.dll")]
        private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

        [DllImport("wintrust.dll")]
        private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

        public static SigStatus Check(string path)
        {
            try
            {
                if (!File.Exists(path)) return SigStatus.Unknown;
                int rc = VerifyEmbedded(path);
                if (rc == 0) return SigStatus.Valid;
                if (rc != TRUST_E_NOSIGNATURE && rc != TRUST_E_SUBJECT_FORM_UNKNOWN && rc != TRUST_E_PROVIDER_UNKNOWN)
                    return SigStatus.Invalid;
                foreach (var alg in new[] { "SHA256", "SHA1" })
                {
                    var c = VerifyCatalog(path, alg);
                    if (c == SigStatus.Valid || c == SigStatus.Invalid) return c;
                }
                return SigStatus.NotSigned;
            }
            catch { return SigStatus.Unknown; }
        }

        private static int Verify(uint choice, object info)
        {
            var pInfo = Marshal.AllocHGlobal(Marshal.SizeOf(info));
            try
            {
                Marshal.StructureToPtr(info, pInfo, false);
                var data = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)),
                    dwUIChoice = WTD_UI_NONE,
                    fdwRevocationChecks = WTD_REVOKE_NONE,
                    dwUnionChoice = choice,
                    pInfo = pInfo,
                    dwStateAction = WTD_STATEACTION_VERIFY,
                    dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
                };
                var action = GenericVerifyV2;
                int rc = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
                data.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(IntPtr.Zero, ref action, ref data);
                return rc;
            }
            finally
            {
                Marshal.DestroyStructure(pInfo, info.GetType());
                Marshal.FreeHGlobal(pInfo);
            }
        }

        private static int VerifyEmbedded(string path) =>
            Verify(WTD_CHOICE_FILE, new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)),
                pcwszFilePath = path,
            });

        private static SigStatus VerifyCatalog(string path, string alg)
        {
            if (!CryptCATAdminAcquireContext2(out var admin, IntPtr.Zero, alg, IntPtr.Zero, 0)) return SigStatus.Unknown;
            IntPtr catInfo = IntPtr.Zero;
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    var h = fs.SafeFileHandle.DangerousGetHandle();
                    uint size = 0;
                    CryptCATAdminCalcHashFromFileHandle2(admin, h, ref size, null, 0);
                    if (size == 0 || size > 64) return SigStatus.Unknown;
                    var hash = new byte[size];
                    if (!CryptCATAdminCalcHashFromFileHandle2(admin, h, ref size, hash, 0)) return SigStatus.Unknown;

                    catInfo = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, IntPtr.Zero);
                    if (catInfo == IntPtr.Zero) return SigStatus.NotSigned;
                    var ci = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf(typeof(CATALOG_INFO)) };
                    if (!CryptCATCatalogInfoFromContext(catInfo, ref ci, 0)) return SigStatus.Unknown;

                    var pHash = Marshal.AllocHGlobal(hash.Length);
                    try
                    {
                        Marshal.Copy(hash, 0, pHash, hash.Length);
                        int rc = Verify(WTD_CHOICE_CATALOG, new WINTRUST_CATALOG_INFO
                        {
                            cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_CATALOG_INFO)),
                            pcwszCatalogFilePath = ci.wszCatalogFile,
                            pcwszMemberTag = string.Concat(hash.Select(b => b.ToString("X2"))),
                            pcwszMemberFilePath = path,
                            hMemberFile = h,
                            pbCalculatedFileHash = pHash,
                            cbCalculatedFileHash = size,
                            hCatAdmin = admin,
                        });
                        return rc == 0 ? SigStatus.Valid : SigStatus.Invalid;
                    }
                    finally { Marshal.FreeHGlobal(pHash); }
                }
            }
            catch { return SigStatus.Unknown; }
            finally
            {
                if (catInfo != IntPtr.Zero) CryptCATAdminReleaseCatalogContext(admin, catInfo, 0);
                CryptCATAdminReleaseContext(admin, 0);
            }
        }
    }
}
