namespace OpenCertServer.Acme.Abstractions.HttpModel.Requests;

using System.Collections.Generic;

public sealed class CreateOrGetAccount
{
    public List<string>? Contact { get; set; }

    public bool TermsOfServiceAgreed { get; set; }
    public bool OnlyReturnExisting { get; set; }
}