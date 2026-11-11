using System;
using System.Collections.Generic;
using System.Management;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using Tendril.Core;
using Tendril.Utilities;

namespace Tendril.Modules
{
    /// <summary>
    /// Service Binary / Unquoted Path Hijack (T1574.010 / T1574.009)
    ///
    /// Combines two SharpUp primitives into one persistence module:
    ///   1. Services whose binary path is writable - replace the EXE directly.
    ///   2. Services with unquoted paths containing spaces - plant an EXE at
    ///      an intermediate path segment (e.g. C:\Program.exe).
    ///
    /// Check mode enumerates all exploitable services. Install mode is
    /// intentionally not automated - it reports the exact path to drop and
    /// the operator handles the binary swap to avoid bricking a production box.
    /// </summary>
    public class ServiceBinaryHijack : ITendril
    {
        public string Name { get { return "ServiceBinaryHijack"; } }
        public string Description { get { return "Services with writable binaries or unquoted paths (recon + guidance)"; } }
        public string MitreId { get { return "T1574.010"; } }
        public bool RequiresAdmin { get { return false; } }
        public bool IsReconOnly { get { return true; } }

        public TendrilResult Install(Dictionary<string, string> options)
        {
            return new TendrilResult(ResultStatus.Failed, Name, "Recon-only - use 'check' to enumerate, then manually place the binary");
        }

        public TendrilResult Remove(Dictionary<string, string> options)
        {
            return new TendrilResult(ResultStatus.Failed, Name, "Recon-only - nothing to remove");
        }

        public List<TendrilResult> Check()
        {
            var results = new List<TendrilResult>();

            try
            {
                // --- Writable service binaries ---
                var wmiData = new ManagementObjectSearcher(@"root\cimv2", "SELECT * FROM win32_service");
                foreach (ManagementObject svc in wmiData.Get())
                {
                    if (svc["PathName"] == null) continue;
                    string raw = svc["PathName"].ToString();

                    Match m = Regex.Match(raw, @"^\W*([a-z]:\\.+?(\.(exe|dll|sys)))\W*", RegexOptions.IgnoreCase);
                    string binPath = m.Groups[1].Value;
                    if (string.IsNullOrEmpty(binPath)) continue;

                    if (FileUtils.IsWritable(binPath))
                    {
                        results.Add(new TendrilResult(ResultStatus.Warning, Name,
                            string.Format("Writable service binary: {0}", svc["Name"]))
                            .WithMeta("Service", svc["Name"].ToString())
                            .WithMeta("State", (svc["State"] ?? "").ToString())
                            .WithMeta("StartMode", (svc["StartMode"] ?? "").ToString())
                            .WithMeta("BinaryPath", binPath)
                            .WithMeta("Type", "WritableBinary"));
                    }
                }
            }
            catch (Exception ex)
            {
                results.Add(new TendrilResult(ResultStatus.Failed, Name, "WMI query failed: " + ex.Message));
            }

            // --- Unquoted service paths ---
            try
            {
                RegistryKey services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
                if (services != null)
                {
                    foreach (string subkey in services.GetSubKeyNames())
                    {
                        try
                        {
                            RegistryKey svcKey = services.OpenSubKey(subkey);
                            if (svcKey == null) continue;
                            string path = ((string)svcKey.GetValue("ImagePath", "")).Trim();
                            if (string.IsNullOrEmpty(path)) continue;

                            // Skip quoted and paths without spaces before .exe
                            if (path.StartsWith("\"") || path.StartsWith("'")) continue;
                            int exeIdx = path.ToLower().IndexOf(".exe");
                            if (exeIdx < 0) continue;
                            string exePortion = path.Substring(0, exeIdx + 4);
                            if (!exePortion.Contains(" ")) continue;

                            // Check each intermediate path for writability
                            string[] parts = exePortion.Split(' ');
                            string current = "";
                            for (int i = 0; i < parts.Length - 1; i++)
                            {
                                current += (i > 0 ? " " : "") + parts[i];
                                string plantPath = current + ".exe";
                                string plantDir = System.IO.Path.GetDirectoryName(plantPath);

                                if (!string.IsNullOrEmpty(plantDir) && FileUtils.IsWritable(plantDir))
                                {
                                    int startType = (int)svcKey.GetValue("Start", 4);
                                    string startName = startType == 2 ? "Automatic" : startType == 3 ? "Manual" : "Other";

                                    results.Add(new TendrilResult(ResultStatus.Warning, Name,
                                        string.Format("Unquoted path hijack: {0}", subkey))
                                        .WithMeta("Service", subkey)
                                        .WithMeta("ImagePath", path)
                                        .WithMeta("PlantAt", plantPath)
                                        .WithMeta("StartMode", startName)
                                        .WithMeta("Type", "UnquotedPath"));
                                }
                            }
                        }
                        catch { continue; }
                    }
                }
            }
            catch (Exception ex)
            {
                results.Add(new TendrilResult(ResultStatus.Failed, Name, "Registry enum failed: " + ex.Message));
            }

            return results;
        }
    }
}
