using Microsoft.AspNetCore.Mvc;

namespace OpenCertServer.Ca.Server.Handlers;

using Microsoft.AspNetCore.Http;
using OpenCertServer.Ca.Utils.Ca;

public static class CrlHandler
{
    public static Task<IResult> Handle(ICertificateAuthority ca)
    {
        return HandleProfile("", ca);
    }

    public static async Task<IResult> HandleProfile([FromRoute] string profileName, ICertificateAuthority ca)
    {
        var crl = await ca.GetRevocationList(profileName);
        return Results.Bytes(crl, "application/pkix-crl");
    }
}
