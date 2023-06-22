using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.WindowsAzure.GuestAgent.Plugins.CustomScriptHandler
{
    public class Constants
    {
        public const string PluginName = "eBpfExtension";
        public const string HandlerEnvironmentFile = "HandlerEnvironment.json";
        public const string HandlerLogFile = PluginName + ".log";
        public const string Lang_EnUs = "en-US";

        public const int StatusCodeOk = 0;
        public const int StatusCodeDisabled = 1;
        public const string StatusFileSuffix = ".status";
    }
}
