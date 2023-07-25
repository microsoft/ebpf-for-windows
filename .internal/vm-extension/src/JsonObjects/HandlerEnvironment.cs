using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.WindowsAzure.GuestAgent.Plugins
{
    [DataContract]
    public class TopLevelHandlerEnvironment
    {
        [DataMember(Name = "version")]
        public string Version { get; set; }

        [DataMember(Name = "handlerEnvironment")]
        public HandlerEnvironment HandlerEnvironment { get; set; }

        public override string ToString()
        {
            return string.Format("Version: {0}, HandlerEnvironment: [{1}]", Version, HandlerEnvironment.ToString());
        }
    }

    [DataContract(Name = "handlerEnvironment")]
    public class HandlerEnvironment
    {
        [DataMember(Name = "logFolder")]
        public string LogFolder { get; set; }

        [DataMember(Name = "configFolder")]
        public string ConfigFolder { get; set; }

        [DataMember(Name = "statusFolder")]
        public string StatusFolder { get; set; }

        [DataMember(Name = "heartbeatFile")]
        public string HeartbeatFile { get; set; }

        public override string ToString()
        {
            return string.Format("LogFolder: \"{0}\", ConfigFolder: \"{1}\", StatusFolder: \"{2}\", HeartbeatFile: \"{3}\"", LogFolder, ConfigFolder, StatusFolder, HeartbeatFile);
        }
    }
}
