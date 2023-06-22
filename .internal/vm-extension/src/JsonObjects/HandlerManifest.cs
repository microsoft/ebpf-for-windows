using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.WindowsAzure.GuestAgent.Plugins
{
    public class TopLevelHandlerManifest
    {
        public string Version { get; set; }
        public HandlerManifest HandlerManifest { get; set; }
    }

    public class HandlerManifest
    {
        public string InstallCommand { get; set; }
        public string UninstallCommand { get; set; }
        public string UpdateCommand { get; set; }
        public string EnableCommand { get; set; }
        public string DisableCommand { get; set; }
        public bool RebootAfterInstall { get; set; }
        public bool ReportHeartbeat { get; set; }
    }
}
