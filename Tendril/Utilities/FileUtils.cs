using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Tendril.Utilities
{
    public static class FileUtils
    {
        /// <summary>Check if a path is writable by the current user.</summary>
        public static bool IsWritable(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            try
            {
                FileSystemRights[] modifyRights = {
                    FileSystemRights.FullControl,
                    FileSystemRights.Modify,
                    FileSystemRights.Write,
                    FileSystemRights.WriteData
                };

                string target = path;
                if (File.Exists(path))
                    target = Path.GetDirectoryName(path);

                if (!Directory.Exists(target)) return false;

                var rules = Directory.GetAccessControl(target)
                    .GetAccessRules(true, true, typeof(SecurityIdentifier));
                var identity = WindowsIdentity.GetCurrent();

                foreach (FileSystemAccessRule rule in rules)
                {
                    if (identity.Groups.Contains(rule.IdentityReference) ||
                        rule.IdentityReference == identity.User)
                    {
                        foreach (var right in modifyRights)
                        {
                            if ((right & rule.FileSystemRights) == right &&
                                rule.AccessControlType == AccessControlType.Allow)
                                return true;
                        }
                    }
                }
            }
            catch { }
            return false;
        }

        /// <summary>Recursively find files matching glob patterns (semicolon-separated).</summary>
        public static List<string> FindFiles(string path, string patterns)
        {
            var files = new List<string>();
            try
            {
                foreach (string pattern in patterns.Split(';'))
                {
                    if (!string.IsNullOrEmpty(pattern.Trim()))
                        files.AddRange(Directory.GetFiles(path, pattern.Trim(), SearchOption.TopDirectoryOnly));
                }
                foreach (var dir in Directory.GetDirectories(path))
                    files.AddRange(FindFiles(dir, patterns));
            }
            catch (UnauthorizedAccessException) { }
            catch (PathTooLongException) { }
            return files;
        }

        /// <summary>Get the user startup folder path.</summary>
        public static string GetUserStartupFolder()
        {
            return Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        }

        /// <summary>Get the common (all users) startup folder path.</summary>
        public static string GetCommonStartupFolder()
        {
            return Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
        }
    }
}
