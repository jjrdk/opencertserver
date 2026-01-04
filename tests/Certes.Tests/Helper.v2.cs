using System;
using System.Net.Http;
using Certes.Acme;
using Certes.Acme.Resource;
using Microsoft.IdentityModel.Tokens;
using Directory = Certes.Acme.Resource.Directory;

namespace Certes;

public static partial class Helper
{
    public static readonly Directory MockDirectoryV2 = new(
        new Uri("http://acme.d/newNonce"),
        new Uri("http://acme.d/newAccount"),
        new Uri("http://acme.d/newOrder"),
        new Uri("http://acme.d/revokeCert"),
        new Uri("http://acme.d/keyChange"),
        new DirectoryMeta(new Uri("http://acme.d/tos"), null, null, false));

    public static IKey GetKeyV2(string algo = SecurityAlgorithms.EcdsaSha256)
        => KeyFactory.FromPem(algo.GetTestKey());

    public static IAcmeHttpClient CreateHttp(Uri dirUri, HttpClient http)
        => new AcmeHttpClient(dirUri, http);
}