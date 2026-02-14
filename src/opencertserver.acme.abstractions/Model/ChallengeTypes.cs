using System.Collections.Immutable;

namespace OpenCertServer.Acme.Abstractions.Model;

public static class ChallengeTypes
{
    public const string Http01 = "http-01";
    public const string Dns01 = "dns-01";

    public static readonly ImmutableArray<string> AllTypes = [Http01, Dns01];
}
