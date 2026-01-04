namespace OpenCertServer.Acme.AspNetClient.Certes;

using global::CertesSlim.Acme;
using Persistence;

public sealed class PlacedOrder
{
    public ChallengeDto[] Challenges { get; }
    public IOrderContext Order { get; }
    public IChallengeContext[] ChallengeContexts { get; }

    public PlacedOrder(
        ChallengeDto[]? challenges,
        IOrderContext order,
        IChallengeContext[] challengeContexts)
    {
        Challenges = challenges ?? [];
        Order = order;
        ChallengeContexts = challengeContexts;
    }
}