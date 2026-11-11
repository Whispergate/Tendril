using System;
using System.Collections.Generic;
using Tendril.Core;

namespace Tendril.Utilities
{
    public static class OutputUtils
    {
        public static void PrintBanner()
        {
            Console.WriteLine(@"
  ______               __     _ __
 /_  __/__  ____  ____/ /____(_) /
  / / / _ \/ __ \/ __  / ___/ / / 
 / / /  __/ / / / /_/ / /  / / /  
/_/  \___/_/ /_/\__,_/_/  /_/_/   
                                   
   Modular Persistence Toolkit
");
        }

        public static void PrintModuleList(IEnumerable<ITendril> modules)
        {
            Console.WriteLine("{0,-22} {1,-14} {2,-6} {3}", "Module", "MITRE ID", "Admin", "Description");
            Console.WriteLine(new string('-', 90));
            foreach (var m in modules)
            {
                string admin = m.RequiresAdmin ? "Yes" : "No";
                string name = m.IsReconOnly ? m.Name + " *" : m.Name;
                Console.WriteLine("{0,-22} {1,-14} {2,-6} {3}", name, m.MitreId, admin, m.Description);
            }
            Console.WriteLine();
            Console.WriteLine("  * = recon-only module (no install/remove)");
        }

        public static void PrintResult(TendrilResult result)
        {
            string prefix;
            switch (result.Status)
            {
                case ResultStatus.Success: prefix = "[+]"; break;
                case ResultStatus.Failed:  prefix = "[-]"; break;
                case ResultStatus.Warning: prefix = "[!]"; break;
                default:                   prefix = "[*]"; break;
            }
            Console.WriteLine("{0} [{1}] {2}", prefix, result.Module, result.Message);
            foreach (var kv in result.Metadata)
            {
                Console.WriteLine("    {0}: {1}", kv.Key, kv.Value);
            }
        }

        public static void PrintResults(List<TendrilResult> results)
        {
            if (results == null || results.Count == 0)
            {
                Console.WriteLine("[*] No results.");
                return;
            }
            foreach (var r in results)
                PrintResult(r);
        }

        public static void PrintModuleInfo(ITendril module)
        {
            Console.WriteLine("  Name        : {0}", module.Name);
            Console.WriteLine("  Description : {0}", module.Description);
            Console.WriteLine("  MITRE ATT&CK: {0}", module.MitreId);
            Console.WriteLine("  Admin       : {0}", module.RequiresAdmin ? "Required" : "Not required");
            Console.WriteLine("  Type        : {0}", module.IsReconOnly ? "Recon only" : "Install / Check / Remove");
        }
    }
}
