using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace Tendril.Core
{
    /// <summary>
    /// Discovers all ITendril implementations via reflection.
    /// Drop a new class into Tendril.Modules implementing ITendril and it
    /// appears automatically - no registration code needed.
    /// </summary>
    public static class ModuleRegistry
    {
        private static readonly Dictionary<string, ITendril> _modules = new Dictionary<string, ITendril>(StringComparer.OrdinalIgnoreCase);
        private static bool _initialized = false;

        public static void Initialize()
        {
            if (_initialized) return;

            var moduleTypes = Assembly.GetExecutingAssembly().GetTypes()
                .Where(t => typeof(ITendril).IsAssignableFrom(t)
                         && !t.IsInterface
                         && !t.IsAbstract
                         && t.Namespace == "Tendril.Modules");

            foreach (var type in moduleTypes)
            {
                try
                {
                    var instance = (ITendril)Activator.CreateInstance(type);
                    _modules[instance.Name] = instance;
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[!] Failed to load module {0}: {1}", type.Name, ex.Message);
                }
            }

            _initialized = true;
        }

        public static ITendril Get(string name)
        {
            Initialize();
            ITendril module;
            return _modules.TryGetValue(name, out module) ? module : null;
        }

        public static IEnumerable<ITendril> GetAll()
        {
            Initialize();
            return _modules.Values.OrderBy(m => m.Name);
        }

        public static int Count
        {
            get
            {
                Initialize();
                return _modules.Count;
            }
        }
    }
}
