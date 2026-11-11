using System;
using System.Collections.Generic;
using System.IO;
using Tendril.Core;
using Tendril.Utilities;

namespace Tendril.Modules
{
    /// <summary>
    /// %PATH% DLL Planting (T1574.007)
    ///
    /// Based on SharpUp's HijackablePaths. Enumerates writable directories in
    /// the system %PATH%. Any application that loads a DLL by name without a
    /// full path will search %PATH% - a planted DLL in a writable PATH dir
    /// gets loaded by every such process.
    ///
    /// Recon-only: reports writable dirs. The operator chooses which DLL to plant.
    /// </summary>
    public class PathDllPlant : ITendril
    {
        public string Name { get { return "PathDllPlant"; } }
        public string Description { get { return "Writable directories in system %PATH% - DLL planting targets"; } }
        public string MitreId { get { return "T1574.007"; } }
        public bool RequiresAdmin { get { return false; } }
        public bool IsReconOnly { get { return true; } }

        public TendrilResult Install(Dictionary<string, string> options)
        {
            return new TendrilResult(ResultStatus.Failed, Name, "Recon-only - use 'check' to enumerate, then plant manually");
        }

        public TendrilResult Remove(Dictionary<string, string> options)
        {
            return new TendrilResult(ResultStatus.Failed, Name, "Recon-only - nothing to remove");
        }

        public List<TendrilResult> Check()
        {
            var results = new List<TendrilResult>();

            // System PATH from registry (not the process-level PATH which may differ)
            string sysPath = RegistryUtils.GetRegValue("HKLM",
                @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", "Path");

            if (string.IsNullOrEmpty(sysPath))
            {
                results.Add(new TendrilResult(ResultStatus.Failed, Name, "Could not read system PATH"));
                return results;
            }

            foreach (string dir in sysPath.Split(';'))
            {
                string folder = dir.Trim();
                if (string.IsNullOrEmpty(folder)) continue;

                // Expand environment variables
                folder = Environment.ExpandEnvironmentVariables(folder);

                if (!Directory.Exists(folder)) continue;

                if (FileUtils.IsWritable(folder))
                {
                    results.Add(new TendrilResult(ResultStatus.Warning, Name,
                        string.Format("Writable PATH directory: {0}", folder))
                        .WithMeta("Directory", folder));
                }
            }

            // Also check user PATH
            string userPath = RegistryUtils.GetRegValue("HKCU", @"Environment", "Path");
            if (!string.IsNullOrEmpty(userPath))
            {
                foreach (string dir in userPath.Split(';'))
                {
                    string folder = Environment.ExpandEnvironmentVariables(dir.Trim());
                    if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) continue;

                    if (FileUtils.IsWritable(folder))
                    {
                        results.Add(new TendrilResult(ResultStatus.Info, Name,
                            string.Format("Writable user PATH directory: {0}", folder))
                            .WithMeta("Directory", folder)
                            .WithMeta("Scope", "User"));
                    }
                }
            }

            return results;
        }
    }
}
