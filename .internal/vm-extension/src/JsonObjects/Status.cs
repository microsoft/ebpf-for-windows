using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.WindowsAzure.GuestAgent.Plugins.eBPF
{
    [DataContract]
    public class TopLevelStatus
    {
        [DataMember(Name = "version")]
        public string Version { get; set; }

        [DataMember(Name = "timestampUTC")]
        public DateTime TimestampUTC { get; set; }

        [DataMember(Name = "status")]
        public StatusObj Status { get; set; }
    }

    [DataContract]
    public class StatusObj
    {
        [DataMember(Name = "name", EmitDefaultValue = false, IsRequired = false)]
        public string Name { get; set; }

        [DataMember(Name = "operation", EmitDefaultValue = false, IsRequired = false)]
        public string Operation { get; set; }

        [DataMember(Name = "configurationAppliedTime", EmitDefaultValue = false, IsRequired = false)]
        public DateTime ConfigurationAppliedTime { get; set; }

        [IgnoreDataMember]
        public StatusEnum Status { get; set; }

        // workaround for serializing/deserializing an enum by its name
        [DataMember(Name = "status")]
        public string StatusString
        {
            get { return Enum.GetName(typeof(StatusEnum), this.Status); }
            set { this.Status = (StatusEnum)Enum.Parse(typeof(StatusEnum), value, false); }
        }

        [DataMember(Name = "code")]
        public int Code { get; set; }

        [DataMember(Name = "message", EmitDefaultValue = false, IsRequired = false)]
        public StatusMessage Message { get; set; }

        [DataMember(Name = "formattedMessage")]
        public FormattedMessage FormattedMessage { get; set; }

        [DataMember(Name = "substatus")]
        public IList<SubstatusObj> Substatus { get; set; }
    }

    [DataContract]
    public enum StatusEnum
    {
        // Current version of the DataContractJsonSerializer ignores the EnumMember annotation
        [EnumMember(Value = "success")]
        success,
        [EnumMember(Value = "transitioning")]
        transitioning,
        [EnumMember(Value = "warning")]
        warning,
        [EnumMember(Value = "error")]
        error
    }

    [DataContract]
    public class StatusMessage
    {
        [DataMember(Name = "id")]
        public string Id { get; set; }

        [DataMember(Name = "params")]
        public IList<object> Params { get; set; }
    }

    [DataContract]
    public class FormattedMessage
    {
        [DataMember(Name = "lang")]
        public string Lang { get; set; }

        [DataMember(Name = "message")]
        public string Message { get; set; }
    }

    [DataContract]
    public class SubstatusObj
    {
        [DataMember(Name = "name", EmitDefaultValue = false, IsRequired = false)]
        public string Name { get; set; }

        [IgnoreDataMember]
        public StatusEnum Status { get; set; }

        // workaround for serializing/deserializing an enum by its name
        [DataMember(Name = "status")]
        public string StatusString
        {
            get { return Enum.GetName(typeof(StatusEnum), this.Status); }
            set { this.Status = (StatusEnum)Enum.Parse(typeof(StatusEnum), value, true); }
        }

        [DataMember(Name = "code")]
        public int Code { get; set; }

        [DataMember(Name = "message", EmitDefaultValue = false, IsRequired = false)]
        public StatusMessage Message { get; set; }

        [DataMember(Name = "formattedMessage")]
        public FormattedMessage FormattedMessage { get; set; }
    }
}
