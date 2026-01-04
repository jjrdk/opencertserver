namespace OpenCertServer.Acme.Abstractions.HttpModel.Requests;

using System.Runtime.Serialization;
using System.Text.Json.Serialization;
using Model.Exceptions;

[DataContract]
public sealed class AcmeRawPostRequest
{
    [DataMember(Name = "protected")]
    [JsonPropertyName("protected")]
    public string Header
    {
        get { return field ?? throw new NotInitializedException(); }
        set;
    }

    [JsonPropertyName("payload")]
    public string? Payload { get; set; }

    [JsonPropertyName("signature")]
    public string Signature
    {
        get { return field ?? throw new NotInitializedException(); }
        set;
    }
}
