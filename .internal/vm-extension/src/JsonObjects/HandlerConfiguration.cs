using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.WindowsAzure.GuestAgent.Plugins.eBPF.CustomScriptHandler
{
    [DataContract]
    public class TopLevelHandlerConfiguration
    {
        [DataMember(Name = "runtimeSettings")]
        public IList<RuntimeSetting> RuntimeSettings { get; set; }

        public override string ToString()
        {
            return "[" + string.Join(", ", RuntimeSettings) + "]";
        }
    }

    [DataContract]
    public class RuntimeSetting
    {
        [DataMember(Name = "handlerSettings")]
        public HandlerSettings HandlerSettings { get; set; }

        public override string ToString()
        {
            return "{" + HandlerSettings.ToString() + "}";
        }
    }

    [DataContract]
    public class HandlerSettings
    {
        [DataMember(Name = "protectedSettingsCertThumbprint")]
        public string ProtectedSettingsCertThumbprint { get; set; }

        [DataMember(Name = "protectedSettings")]
        public string ProtectedSettings { get; set; }

        [DataMember(Name = "publicSettings")]
        public PublicSettings PublicSettings { get; set; }

        public override string ToString()
        {
            return "ProtectedSettingsCertThumbprint: <REDACTED> Thumbprint length = " + ProtectedSettingsCertThumbprint?.Length +
                        ", ProtectedSettings: <REDACTED> ProtectedSettings length = " + ProtectedSettings?.Length +
                        ", PublicSettings: " + PublicSettings;
        }
    }

    [DataContract]
    public class ProtectedSettings
    {
        [DataMember(Name = "storageAccountName")]
        public string StorageAccountName { get; set; }

        [DataMember(Name = "storageAccountKey")]
        public string StorageAccountKey { get; set; }

        public override string ToString()
        {
            return "StorageAccountName: " + StorageAccountName + ", StorageAccountKey: " + StorageAccountKey;
        }
    }

    [DataContract]
    public class PublicSettings
    {
        [DataMember(Name = "fileUris")]
        public IList<string> FileUris { get; set; }

        [DataMember(Name = "commandToExecute")]
        public string CommandToExecute { get; set; }

        public override string ToString()
        {
            return "FileUris: [" + string.Join(", ", FileUris) + "], CommandToExecute: " + CommandToExecute;
        }
    }
}
