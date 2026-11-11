using System.Collections.Generic;

namespace Tendril.Core
{
    public enum ResultStatus
    {
        Success,
        Failed,
        Info,       // informational finding from Check()
        Warning     // partial success or needs attention
    }

    public class TendrilResult
    {
        public ResultStatus Status { get; set; }
        public string Module { get; set; }
        public string Message { get; set; }
        public Dictionary<string, string> Metadata { get; set; }

        public TendrilResult()
        {
            Metadata = new Dictionary<string, string>();
        }

        public TendrilResult(ResultStatus status, string module, string message)
        {
            Status = status;
            Module = module;
            Message = message;
            Metadata = new Dictionary<string, string>();
        }

        public TendrilResult WithMeta(string key, string value)
        {
            Metadata[key] = value;
            return this;
        }
    }
}
