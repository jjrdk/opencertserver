using Microsoft.IdentityModel.Tokens;

namespace CertesSlim;

internal class KeyChange
{
    public Uri Account { get; set; } = null!;

    public JsonWebKey OldKey { get; set; } = null!;
}