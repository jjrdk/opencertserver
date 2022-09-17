namespace OpenCertServer.Acme.Abstractions.HttpModel.Requests
{
    using System.Runtime.Serialization;
    using System.Text.Json.Serialization;
    using Model.Exceptions;

    [DataContract]
    public sealed class AcmeRawPostRequest
    {
        private string? _header;
        private string? _signature;
        
        [DataMember(Name = "protected")]
        [JsonPropertyName("protected")]
        public string Header
        {
            get { return _header ?? throw new NotInitializedException(); }
            set { _header = value; }
        }

        [JsonPropertyName("payload")]
        public string? Payload { get; set; } 
        
        [JsonPropertyName("signature")]
        public string Signature
        {
            get { return _signature ?? throw new NotInitializedException(); }
            set { _signature = value; }
        }
    }
}
