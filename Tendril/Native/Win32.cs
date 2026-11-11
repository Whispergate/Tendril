using System;
using System.Runtime.InteropServices;

namespace Tendril.Native
{
    public static class Win32
    {
        // --- Registry ---
        public const uint HKEY_LOCAL_MACHINE = 0x80000002;
        public const uint HKEY_CURRENT_USER = 0x80000001;

        public const int KEY_READ = 0x20019;
        public const int KEY_WRITE = 0x20006;
        public const int KEY_ALL_ACCESS = 0xF003F;
        public const int KEY_WOW64_64KEY = 0x0100;

        public const int REG_SZ = 1;
        public const int REG_DWORD = 4;
        public const int REG_BINARY = 3;

        public const int REG_OPTION_NON_VOLATILE = 0;

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int RegOpenKeyEx(
            uint hKey, string subKey, int options, int samDesired, out IntPtr phkResult);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int RegCreateKeyEx(
            uint hKey, string subKey, int reserved, string lpClass, int dwOptions,
            int samDesired, IntPtr lpSecurityAttributes, out IntPtr phkResult, out int lpdwDisposition);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int RegSetValueEx(
            IntPtr hKey, string lpValueName, int reserved, int dwType, byte[] lpData, int cbData);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int RegSetValueEx(
            IntPtr hKey, string lpValueName, int reserved, int dwType, ref int lpData, int cbData);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int RegDeleteValue(IntPtr hKey, string lpValueName);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int RegDeleteKeyEx(uint hKey, string subKey, int samDesired, int reserved);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int RegCloseKey(IntPtr hKey);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int RegQueryValueEx(
            IntPtr hKey, string lpValueName, IntPtr lpReserved,
            out int lpType, IntPtr lpData, ref int lpcbData);

        // --- Process / Token ---
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(
            IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation,
            int TokenInformationLength, out int ReturnLength);

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool ConvertSidToStringSid(IntPtr pSID, out IntPtr ptrSid);

        [DllImport("kernel32.dll")]
        public static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("shell32.dll", SetLastError = true)]
        public static extern int SHGetFolderPath(IntPtr hwndOwner, int nFolder, IntPtr hToken,
            uint dwFlags, [Out] System.Text.StringBuilder pszPath);

        // CSIDL values
        public const int CSIDL_STARTUP = 0x0007;            // <user>\Start Menu\Programs\Startup
        public const int CSIDL_COMMON_STARTUP = 0x0018;     // All Users\Start Menu\Programs\Startup

        // Task Scheduler Security Descriptor value name - removing this hides the task
        public const string TASK_SD_VALUE = "SD";

        // --- Integrity check ---
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeName(
            string lpSystemName, IntPtr lpLuid,
            System.Text.StringBuilder lpName, ref int cchName);

        // Token access rights
        public const uint TOKEN_QUERY = 0x0008;
        public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;

        // TOKEN_INFORMATION_CLASS
        public const int TokenIntegrityLevel = 25;

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_MANDATORY_LABEL
        {
            public SID_AND_ATTRIBUTES Label;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern IntPtr GetSidSubAuthority(IntPtr pSid, uint nSubAuthority);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern IntPtr GetSidSubAuthorityCount(IntPtr pSid);

        // Integrity levels
        public const int SECURITY_MANDATORY_LOW_RID = 0x1000;
        public const int SECURITY_MANDATORY_MEDIUM_RID = 0x2000;
        public const int SECURITY_MANDATORY_HIGH_RID = 0x3000;
        public const int SECURITY_MANDATORY_SYSTEM_RID = 0x4000;
    }
}
