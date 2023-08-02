using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.WindowsAzure.GuestAgent.Plugins.eBPF
{
    public class TopLevelHandlerManifest
    {
        public string version { get; set; }
        public HandlerManifest handlerManifest { get; set; }
    }

    public class HandlerManifest
    {
        public string installCommand { get; set; }
        public string uninstallCommand { get; set; }
        public string updateCommand { get; set; }
        public string enableCommand { get; set; }
        public string disableCommand { get; set; }
        public string resetCommand { get; set; }
        public bool rebootAfterInstall { get; set; }
        public bool reportHeartbeat { get; set; }
        public string updateMode { get; set; }
        public bool supportsMultipleExtensions { get; set; }
        public bool continueOnUpdateFailure { get; set; }
    }
}
