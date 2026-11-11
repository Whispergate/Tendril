using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Tendril.Utilities
{
    public static class RegistryUtils
    {
        /// <summary>Get a single registry value.</summary>
        public static string GetRegValue(string hive, string path, string valueName)
        {
            try
            {
                RegistryKey root = HiveToKey(hive);
                if (root == null) return null;
                using (var key = root.OpenSubKey(path))
                {
                    if (key == null) return null;
                    object val = key.GetValue(valueName);
                    return val != null ? val.ToString() : null;
                }
            }
            catch { return null; }
        }

        /// <summary>Get all values under a registry path.</summary>
        public static Dictionary<string, object> GetRegValues(string hive, string path)
        {
            try
            {
                RegistryKey root = HiveToKey(hive);
                if (root == null) return null;
                using (var key = root.OpenSubKey(path))
                {
                    if (key == null) return null;
                    return key.GetValueNames().ToDictionary(n => n, n => key.GetValue(n));
                }
            }
            catch { return null; }
        }

        /// <summary>Get subkey names.</summary>
        public static string[] GetRegSubkeys(string hive, string path)
        {
            try
            {
                RegistryKey root = HiveToKey(hive);
                if (root == null) return new string[0];
                using (var key = root.OpenSubKey(path))
                {
                    return key != null ? key.GetSubKeyNames() : new string[0];
                }
            }
            catch { return new string[0]; }
        }

        /// <summary>Set a string registry value.</summary>
        public static bool SetRegValue(string hive, string path, string valueName, string data)
        {
            try
            {
                RegistryKey root = HiveToKey(hive);
                if (root == null) return false;
                using (var key = root.CreateSubKey(path))
                {
                    if (key == null) return false;
                    key.SetValue(valueName, data, RegistryValueKind.String);
                    return true;
                }
            }
            catch { return false; }
        }

        /// <summary>Set a DWORD registry value.</summary>
        public static bool SetRegDword(string hive, string path, string valueName, int data)
        {
            try
            {
                RegistryKey root = HiveToKey(hive);
                if (root == null) return false;
                using (var key = root.CreateSubKey(path))
                {
                    if (key == null) return false;
                    key.SetValue(valueName, data, RegistryValueKind.DWord);
                    return true;
                }
            }
            catch { return false; }
        }

        /// <summary>Delete a registry value.</summary>
        public static bool DeleteRegValue(string hive, string path, string valueName)
        {
            try
            {
                RegistryKey root = HiveToKey(hive);
                if (root == null) return false;
                using (var key = root.OpenSubKey(path, true))
                {
                    if (key == null) return false;
                    key.DeleteValue(valueName, false);
                    return true;
                }
            }
            catch { return false; }
        }

        /// <summary>Delete a registry subkey tree.</summary>
        public static bool DeleteRegKeyTree(string hive, string path)
        {
            try
            {
                RegistryKey root = HiveToKey(hive);
                if (root == null) return false;
                root.DeleteSubKeyTree(path, false);
                return true;
            }
            catch { return false; }
        }

        /// <summary>Check if current user can write to a registry key.</summary>
        public static bool IsModifiableKey(string hive, string path)
        {
            try
            {
                RegistryKey root = HiveToKey(hive);
                if (root == null) return false;
                using (var key = root.OpenSubKey(path, RegistryKeyPermissionCheck.ReadWriteSubTree))
                {
                    return key != null;
                }
            }
            catch { return false; }
        }

        /// <summary>Check if a registry path exists.</summary>
        public static bool KeyExists(string hive, string path)
        {
            try
            {
                RegistryKey root = HiveToKey(hive);
                if (root == null) return false;
                using (var key = root.OpenSubKey(path))
                {
                    return key != null;
                }
            }
            catch { return false; }
        }

        private static RegistryKey HiveToKey(string hive)
        {
            switch (hive.ToUpper())
            {
                case "HKLM": return Registry.LocalMachine;
                case "HKCU": return Registry.CurrentUser;
                case "HKU":  return Registry.Users;
                case "HKCR": return Registry.ClassesRoot;
                default:     return null;
            }
        }
    }
}
