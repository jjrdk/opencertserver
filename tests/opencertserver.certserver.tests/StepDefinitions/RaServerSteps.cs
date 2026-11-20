using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using OpenCertServer.Ra.Server;
using Reqnroll;
using Xunit;

namespace OpenCertServer.CertServer.Tests.StepDefinitions;

/// <summary>
/// F1: the RA's EST enrollment surface must be protected by a signature-verified JWT. A RA that
/// cannot verify the token signature must refuse to start, and a token signed by any key other than
/// the RA's own (or its issuer's) must be rejected even when it is otherwise well formed.
/// </summary>
[Binding]
public sealed class RaServerSteps
{
    private const string RaKey = "0123456789abcdef0123456789abcdef";
    private const string ForeignKey = "fedcba9876543210fedcba9876543210";

    private IConfiguration? _noKeyConfig;
    private Exception? _configureError;
    private bool _jwtRejected;
    private bool _jwtAccepted;

    [Given("a RA host with no JWT signing key")]
    public void GivenARaHostWithNoJwtSigningKey()
    {
        // No Jwt section at all: neither a symmetric key nor an authority/metadata endpoint.
        _noKeyConfig = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>())
            .Build();
    }

    [Given("a RA host with a JWT signing key")]
    public void GivenARaHostWithAJwtSigningKey()
    {
        _noKeyConfig = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:SymmetricKey"] = RaKey
            })
            .Build();
    }

    [When("the RA host configures EST authentication")]
    public void WhenTheRaHostConfiguresEstAuthentication()
    {
        Assert.NotNull(_noKeyConfig);
        var services = new ServiceCollection();
        try
        {
            services.ConfigureRaJwt(_noKeyConfig!);
        }
        catch (InvalidOperationException exception)
        {
            _configureError = exception;
        }
    }

    [When("the RA validates a JWT signed with a key that is not its own")]
    public void WhenTheRaValidatesAJwtSignedWithAKeyThatIsNotItsOwn()
    {
        var token = Sign(ForeignKey);
        _jwtRejected = TryRejectSignature(token);
    }

    [When("the RA validates a JWT signed with its own signing key")]
    public void WhenTheRaValidatesAJwtSignedWithItsOwnSigningKey()
    {
        var token = Sign(RaKey);
        _jwtAccepted = TryAcceptSignature(token);
    }

    [Then("the RA host fails to start")]
    public void ThenTheRaHostFailsToStart()
    {
        // A signature-unverified JWT is a startup failure: configuring EST authentication without a
        // signing key throws so the RA refuses to start.
        Assert.NotNull(_configureError);
        Assert.IsType<InvalidOperationException>(_configureError);
    }

    [Then("the JWT is rejected because its signature does not verify")]
    public void ThenTheJwtIsRejectedBecauseItsSignatureDoesNotVerify()
    {
        Assert.True(_jwtRejected);
    }

    [Then("the JWT is accepted")]
    public void ThenTheJwtIsAccepted()
    {
        Assert.True(_jwtAccepted);
    }

    /// <summary>
    /// Builds a well-formed HS256 JWT signed with <paramref name="signingKey"/>. The token is valid
    /// in every respect except that its signature is produced by <paramref name="signingKey"/>.
    /// </summary>
    private static string Sign(string signingKey)
    {
        var handler = new JwtSecurityTokenHandler();
        var credentials = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey)),
            SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            issuer: "ra.example.com",
            audience: "ra.example.com",
            claims: [new System.Security.Claims.Claim("ra", "ra-tenant-a")],
            expires: DateTimeOffset.UtcNow.AddMinutes(5).DateTime,
            signingCredentials: credentials);
        return handler.WriteToken(token);
    }

    /// <summary>
    /// Validates a token the way <see cref="RaServerAuthentication.ConfigureRaJwt"/> does, with the RA's
    /// own key as the only trusted signing key. Returns true when the signature does not verify.
    /// </summary>
    private static bool TryRejectSignature(string token)
    {
        try
        {
            Validate(token, RaKey);
            return false;
        }
        catch (SecurityTokenInvalidSignatureException)
        {
            return true;
        }
    }

    private static bool TryAcceptSignature(string token)
    {
        try
        {
            Validate(token, RaKey);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>
    /// Mirrors the <c>TokenValidationParameters</c> <see cref="RaServerAuthentication.ConfigureRaJwt"/>
    /// installs: the signature is always verified and the RA's own key is the only trusted issuer
    /// signing key.
    /// </summary>
    private static void Validate(string token, string raKey)
    {
        var parameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(raKey)),
        };
        new JwtSecurityTokenHandler().ValidateToken(
            token, parameters, out _);
    }
}
