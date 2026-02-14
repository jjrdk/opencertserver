using OpenCertServer.Acme.Abstractions.Exceptions;

namespace OpenCertServer.Acme.Abstractions.Model;

using System;
using System.Collections.Generic;
using System.Linq;

public sealed class AcmeError
{
    private string? _type;
    private string? _detail;

    private AcmeError()
    {
    }

    public AcmeError(
        string type,
        string detail,
        Identifier? identifier = null,
        IEnumerable<AcmeError>? subErrors = null)
    {
        Type = type;

        if (!type.Contains(":"))
        {
            Type = "urn:ietf:params:acme:error:" + type;
        }

        Detail = detail;
        Identifier = identifier;
        SubErrors = subErrors?.ToList();
    }

    public string Type
    {
        get { return _type ?? throw new NotInitializedException(); }
        private set { _type = value; }
    }

    public string Detail
    {
        get { return _detail ?? throw new NotInitializedException(); }
        set { _detail = value; }
    }

    public Identifier? Identifier { get; }

    public List<AcmeError>? SubErrors { get; }
}
