using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Tendril.Core;
using Tendril.Utilities;

namespace Tendril.Modules
{
    /// <summary>
    /// DLL Sideload Enumeration (T1574.001 / T1574.002) - Recon Only
    ///
    /// Scans running processes for loaded DLLs that are:
    ///   1. Not in the KnownDLLs list
    ///   2. Not in C:\Windows\
    ///   3. Writable by the current user
    ///
    /// Also scans common program directories for signed EXEs in writable locations,
    /// which are candidates for DLL sideloading persistence. Combined with a
    /// scheduled task or service that launches the signed EXE, this gives persistence
    /// inside a trusted binary - the DLL proxies legitimate exports while running payload.
    ///
    /// Observed: APT28 PixyNetLoader DLL proxying (2026), Akira/Qilin ransomware.
    /// </summary>
    public class DllSideloadEnum : ITendril
    {
        public string Name { get { return "DllSideloadEnum"; } }
        public string Description { get { return "Enumerate DLL sideload/hijack opportunities on running processes"; } }
        public string MitreId { get { return "T1574.002"; } }
        public bool RequiresAdmin { get { return false; } }
        public bool IsReconOnly { get { return true; } }

        private const string KnownDllsPath = @"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDlls";

        public TendrilResult Install(Dictionary<string, string> options)
        {
            return new TendrilResult(ResultStatus.Failed, Name, "Recon-only module - use 'check' action");
        }

        public TendrilResult Remove(Dictionary<string, string> options)
        {
            return new TendrilResult(ResultStatus.Failed, Name, "Recon-only module - nothing to remove");
        }

        public List<TendrilResult> Check()
        {
            var results = new List<TendrilResult>();

            // Build KnownDLLs set
            var knownDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var knownDllValues = RegistryUtils.GetRegValues("HKLM", KnownDllsPath);
            if (knownDllValues != null)
            {
                foreach (var kv in knownDllValues)
                {
                    if (kv.Value != null)
                        knownDlls.Add(kv.Value.ToString().ToLower());
                }
            }

            // Track unique findings to avoid duplicates
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (Process proc in Process.GetProcesses())
            {
                try
                {
                    foreach (ProcessModule mod in proc.Modules)
                    {
                        string modName = mod.ModuleName.ToLower();
                        string filePath = mod.FileName.ToLower();

                        // Skip non-DLLs, KnownDLLs, and Windows system DLLs
                        if (!modName.EndsWith(".dll")) continue;
                        if (knownDlls.Contains(modName)) continue;
                        if (filePath.Contains(@"\windows\")) continue;

                        // Check if the DLL is writable
                        if (!FileUtils.IsWritable(mod.FileName)) continue;

                        string key = filePath + "|" + proc.ProcessName;
                        if (seen.Contains(key)) continue;
                        seen.Add(key);

                        var result = new TendrilResult(ResultStatus.Info, Name,
                            string.Format("Writable DLL: {0}", mod.FileName))
                            .WithMeta("DLL", mod.FileName)
                            .WithMeta("Process", proc.ProcessName)
                            .WithMeta("PID", proc.Id.ToString());

                        // Extra flag if in Program Files (may be false positive)
                        if (filePath.Contains(@"\program files"))
                            result.WithMeta("Note", "Program Files - verify manually");

                        results.Add(result);
                    }
                }
                catch { continue; } // Access denied for some processes
            }

            // Also check for writable directories with signed executables
            string[] searchPaths = {
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)),
            };

            foreach (string searchPath in searchPaths)
            {
                if (!Directory.Exists(searchPath)) continue;
                try
                {
                    foreach (string exe in Directory.GetFiles(searchPath, "*.exe", SearchOption.AllDirectories))
                    {
                        if (!FileUtils.IsWritable(Path.GetDirectoryName(exe))) continue;

                        // Check if the EXE is signed (basic check via presence of Authenticode)
                        try
                        {
                            var cert = System.Security.Cryptography.X509Certificates
                                .X509Certificate.CreateFromSignedFile(exe);
                            if (cert != null)
                            {
                                results.Add(new TendrilResult(ResultStatus.Info, Name,
                                    string.Format("Signed EXE in writable dir: {0}", exe))
                                    .WithMeta("EXE", exe)
                                    .WithMeta("Signer", cert.Subject)
                                    .WithMeta("Directory", Path.GetDirectoryName(exe))
                                    .WithMeta("SideloadCandidate", "true"));
                            }
                        }
                        catch { /* not signed or can't verify - skip */ }
                    }
                }
                catch { }
            }

            return results;
        }
    }
}
