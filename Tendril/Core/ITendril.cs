using System.Collections.Generic;

namespace Tendril.Core
{
    /// <summary>
    /// Contract for all persistence modules. Implement this interface in a class
    /// under Tendril.Modules and it will be auto-discovered at runtime.
    /// </summary>
    public interface ITendril
    {
        /// <summary>Short module name used on the CLI (e.g. "ComHijack").</summary>
        string Name { get; }

        /// <summary>One-line description shown in the module list.</summary>
        string Description { get; }

        /// <summary>MITRE ATT&CK technique ID (e.g. "T1546.015").</summary>
        string MitreId { get; }

        /// <summary>True if the technique requires elevated privileges.</summary>
        bool RequiresAdmin { get; }

        /// <summary>True if this module is recon-only (no install/remove).</summary>
        bool IsReconOnly { get; }

        /// <summary>
        /// Install persistence using the given options.
        /// Common option keys: "payload", "name", "clsid", "target", "trigger", etc.
        /// </summary>
        TendrilResult Install(Dictionary<string, string> options);

        /// <summary>
        /// Remove a previously installed persistence mechanism.
        /// </summary>
        TendrilResult Remove(Dictionary<string, string> options);

        /// <summary>
        /// Enumerate existing instances of this persistence type on the system.
        /// Returns one TendrilResult per discovered instance.
        /// </summary>
        List<TendrilResult> Check();
    }
}
