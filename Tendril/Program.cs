using System;
using System.Collections.Generic;
using System.Linq;
using Tendril.Core;
using Tendril.Utilities;

namespace Tendril
{
    class Program
    {
        static void Main(string[] args)
        {
            OutputUtils.PrintBanner();

            if (args.Length == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help")
            {
                Usage();
                return;
            }

            string action = args[0].ToLower();

            switch (action)
            {
                case "list":
                    ModuleRegistry.Initialize();
                    OutputUtils.PrintModuleList(ModuleRegistry.GetAll());
                    break;

                case "check":
                    RunCheck(args);
                    break;

                case "install":
                    RunInstall(args);
                    break;

                case "remove":
                    RunRemove(args);
                    break;

                case "info":
                    RunInfo(args);
                    break;

                default:
                    Console.WriteLine("[-] Unknown action: {0}", action);
                    Usage();
                    break;
            }
        }

        static void RunCheck(string[] args)
        {
            ModuleRegistry.Initialize();

            if (args.Length > 1)
            {
                // Check a specific module
                var module = ModuleRegistry.Get(args[1]);
                if (module == null)
                {
                    Console.WriteLine("[-] Module not found: {0}", args[1]);
                    return;
                }
                Console.WriteLine("[*] Running check: {0}", module.Name);
                OutputUtils.PrintResults(module.Check());
            }
            else
            {
                // Check all modules
                Console.WriteLine("[*] Running all checks ({0} modules)...\n", ModuleRegistry.Count);
                foreach (var module in ModuleRegistry.GetAll())
                {
                    Console.WriteLine("--- {0} ({1}) ---", module.Name, module.MitreId);
                    var results = module.Check();
                    if (results.Count == 0)
                        Console.WriteLine("    No findings.");
                    else
                        OutputUtils.PrintResults(results);
                    Console.WriteLine();
                }
            }
        }

        static void RunInstall(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("[-] Usage: Tendril.exe install <module> [/option:value ...]");
                return;
            }

            ModuleRegistry.Initialize();
            var module = ModuleRegistry.Get(args[1]);
            if (module == null)
            {
                Console.WriteLine("[-] Module not found: {0}", args[1]);
                return;
            }

            if (module.IsReconOnly)
            {
                Console.WriteLine("[-] {0} is a recon-only module - use 'check' instead.", module.Name);
                return;
            }

            var options = ParseOptions(args, 2);
            Console.WriteLine("[*] Installing: {0} ({1})", module.Name, module.MitreId);
            var result = module.Install(options);
            OutputUtils.PrintResult(result);
        }

        static void RunRemove(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("[-] Usage: Tendril.exe remove <module> [/option:value ...]");
                return;
            }

            ModuleRegistry.Initialize();
            var module = ModuleRegistry.Get(args[1]);
            if (module == null)
            {
                Console.WriteLine("[-] Module not found: {0}", args[1]);
                return;
            }

            if (module.IsReconOnly)
            {
                Console.WriteLine("[-] {0} is a recon-only module - nothing to remove.", module.Name);
                return;
            }

            var options = ParseOptions(args, 2);
            Console.WriteLine("[*] Removing: {0}", module.Name);
            var result = module.Remove(options);
            OutputUtils.PrintResult(result);
        }

        static void RunInfo(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("[-] Usage: Tendril.exe info <module>");
                return;
            }

            ModuleRegistry.Initialize();
            var module = ModuleRegistry.Get(args[1]);
            if (module == null)
            {
                Console.WriteLine("[-] Module not found: {0}", args[1]);
                return;
            }

            OutputUtils.PrintModuleInfo(module);
        }

        /// <summary>
        /// Parse /key:value options from argument array starting at the given index.
        /// Supports: /key:value, /key=value, /key (boolean flag set to "true")
        /// </summary>
        static Dictionary<string, string> ParseOptions(string[] args, int startIndex)
        {
            var options = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = startIndex; i < args.Length; i++)
            {
                string arg = args[i];
                if (!arg.StartsWith("/")) continue;

                arg = arg.Substring(1); // strip leading /

                int sepIdx = arg.IndexOfAny(new char[] { ':', '=' });
                if (sepIdx > 0)
                {
                    string key = arg.Substring(0, sepIdx);
                    string value = arg.Substring(sepIdx + 1);
                    options[key] = value;
                }
                else
                {
                    options[arg] = "true";
                }
            }
            return options;
        }

        static void Usage()
        {
            ModuleRegistry.Initialize();
            int count = ModuleRegistry.Count;

            Console.WriteLine(@"Usage:
  Tendril.exe list                             List all modules
  Tendril.exe check [module]                   Enumerate persistence (all or specific)
  Tendril.exe install <module> [/opt:val ...]  Install persistence
  Tendril.exe remove <module> [/opt:val ...]   Remove persistence
  Tendril.exe info <module>                    Show module details

Common options:
  /payload:<path>     Payload executable or command
  /name:<string>      Persistence entry name
  /clsid:<guid>       COM CLSID (ComHijack)
  /target:<exe>       Target process (IFEOInjection)
  /hive:<HKCU|HKLM>   Registry hive (RegistryRunKey)
  /trigger:<logon|boot> Task trigger type (GhostTask)
  /variant:<type>     Module-specific variant
  /fileless:true      Use fileless payload stash (RegistryRunKey)

Adding modules:
  Create a class in Tendril.Modules implementing ITendril.
  It will be auto-discovered at runtime - no registration needed.");

            Console.WriteLine("\nLoaded {0} module(s).", count);
        }
    }
}
