namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using CertesSlim.Acme.Resource;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenCertServer.Acme.Server.Configuration;
using OpenCertServer.Acme.Server.Stores;
using Reqnroll;
using Xunit;
using Model = OpenCertServer.Acme.Abstractions.Model;

public sealed partial class ApplianceUpgradeSteps
{
    private byte[]? _externalAccountKey;

    private void ConfigureExternalAccountKey(JsonObject config)
    {
        _externalAccountKey = RandomNumberGenerator.GetBytes(32);
        config["AcmeServer"]!["ExternalAccountKey"] = new JsonObject
        {
            ["native-test"] = new JsonObject { ["MacKey"] = Base64UrlEncoder.Encode(_externalAccountKey) }
        };
    }

    [Then("external-account-bound ACME state survives store reloads")]
    public async Task NativeAcmeState()
    {
        using var key = RSA.Create(2048);
        var parameters = key.ExportParameters(false);
        var jwk = new JsonObject
        {
            ["kty"] = "RSA", ["n"] = Base64UrlEncoder.Encode(parameters.Modulus!),
            ["e"] = Base64UrlEncoder.Encode(parameters.Exponent!)
        };
        var accountEndpoint = $"https://localhost:{_port}/new-account";
        var payload = new JsonObject { ["termsOfServiceAgreed"] = true };
        var rejected = await AcmePost(accountEndpoint, payload.ToJsonString(), key, jwk, null);
        Assert.Equal(400, rejected.Status);
        Assert.True(JsonNode.Parse(rejected.Body)!["type"]!.GetValue<string>()
            .EndsWith(":malformed", StringComparison.Ordinal), rejected.Body);
        Assert.Contains("externalAccountBinding", rejected.Body);
        var bindingHeader = Encode(new JsonObject
            { ["alg"] = "HS256", ["kid"] = "native-test", ["url"] = accountEndpoint }.ToJsonString());
        var bindingPayload = Encode(jwk.ToJsonString());
        payload["externalAccountBinding"] = new JsonObject
        {
            ["protected"] = bindingHeader, ["payload"] = bindingPayload,
            ["signature"] = Base64UrlEncoder.Encode(HMACSHA256.HashData(_externalAccountKey!,
                Encoding.ASCII.GetBytes(bindingHeader + "." + bindingPayload)))
        };
        var created = await AcmePost(accountEndpoint, payload.ToJsonString(), key, jwk, null);
        Assert.True(created.Status == 201, created.Body);
        var accountUrl = created.Location;
        Assert.NotEmpty(accountUrl);
        var account = await AcmePost(accountUrl, "", key, jwk, accountUrl);
        Assert.True(account.Status == 200, account.Body);
        Assert.Equal("valid", JsonNode.Parse(account.Body)!["status"]!.GetValue<string>());
        var orderEndpoint = $"https://localhost:{_port}/new-order";
        var order = await AcmePost(orderEndpoint,
            """{"identifiers":[{"type":"dns","value":"host.example.test"}]}""", key, jwk, accountUrl);
        Assert.True(order.Status == 201, order.Body);
        var reloaded = await AcmePost(order.Location, "", key, jwk, accountUrl);
        Assert.True(reloaded.Status == 200, reloaded.Body);
        Assert.Equal("pending", JsonNode.Parse(reloaded.Body)!["status"]!.GetValue<string>());
        var ordersUrl = JsonNode.Parse(account.Body)!["orders"]!.GetValue<string>();
        var orders = await AcmePost(ordersUrl, "", key, jwk, accountUrl);
        Assert.True(orders.Status == 200, orders.Body);
        Assert.Equal(order.Location, JsonNode.Parse(orders.Body)!["orders"]![0]!.GetValue<string>());
    }

    private async Task<(int Status, string Body, string Location)> AcmePost(
        string url,
        string payload,
        RSA key,
        JsonObject jwk,
        string? accountUrl)
    {
        var headers = Path.Combine(_directory, "acme-headers.txt");
        var body = Path.Combine(_directory, "acme-body.txt");
        var request = Path.Combine(_directory, "acme-request.json");
        var nonce = await Execute("curl",
        [
            "--silent", "--show-error", "--noproxy", "*", "--max-time", "10",
            "--cacert", Path.Combine(_directory, "tls.pem"), "--tlsv1.3",
            "--dump-header", headers, "--output", body, $"https://localhost:{_port}/new-nonce"
        ]);
        Assert.True(nonce.ExitCode == 0, nonce.Error);
        var header = new JsonObject
        {
            ["alg"] = "RS256", ["nonce"] = ReadHeader(headers, "Replay-Nonce"), ["url"] = url
        };
        if (accountUrl is null) header["jwk"] = jwk.DeepClone();
        else header["kid"] = accountUrl;
        var protectedHeader = Encode(header.ToJsonString());
        var encodedPayload = Encode(payload);
        var signature = key.SignData(Encoding.ASCII.GetBytes(protectedHeader + "." + encodedPayload),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        File.WriteAllText(request, new JsonObject
        {
            ["protected"] = protectedHeader, ["payload"] = encodedPayload,
            ["signature"] = Base64UrlEncoder.Encode(signature)
        }.ToJsonString());
        var result = await Execute("curl",
        [
            "--silent", "--show-error", "--noproxy", "*", "--max-time", "30",
            "--cacert", Path.Combine(_directory, "tls.pem"), "--tlsv1.3",
            "--header", "Content-Type: application/jose+json", "--data-binary", "@" + request,
            "--dump-header", headers, "--output", body, "--write-out", "%{http_code}", url
        ]);
        Assert.True(result.ExitCode == 0, result.Error);
        return (int.Parse(result.Output), File.ReadAllText(body), ReadHeader(headers, "Location"));
    }

    private static string Encode(string value) => Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(value));

    private static string ReadHeader(string path, string name) =>
        File.ReadLines(path).FirstOrDefault(line => line.StartsWith(name + ":", StringComparison.OrdinalIgnoreCase))
            ?[(name.Length + 1)..].Trim() ?? "";

    [Then("the appliance ACME file store round-trips account and order aggregates")]
    public async Task AcmeFileRoundTrip()
    {
        var options = Options.Create(new FileStoreOptions { BasePath = _directory });
        var accounts = new AccountStore(options);
        var orders = new OrderStore(options, NullLogger<OrderStore>.Instance);
        using var key = RSA.Create(2048);
        var account = new Model.Account(JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(key)),
                ["mailto:operator@example.test"], DateTimeOffset.UtcNow, "external-account")
            { AccountUri = "https://ca.example.test/acme/account/test" };
        await accounts.SaveAccount(account, default);
        var loadedAccount = await new AccountStore(options).LoadAccount(account.AccountId, default);
        Assert.NotNull(loadedAccount);
        Assert.Equal(account.AccountId, loadedAccount.AccountId);
        Assert.Equal(account.ExternalAccountId, loadedAccount.ExternalAccountId);
        Assert.Equal(account.Jwk.N, loadedAccount.Jwk.N);
        Assert.Equal(account.Contacts, loadedAccount.Contacts);
        Assert.Equal(account.AccountUri, loadedAccount.AccountUri);
        Assert.Equal(account.Version, loadedAccount.Version);
        var order = new Model.Order(account,
            [new Identifier { Type = IdentifierType.Dns, Value = "host.example.test" }], "rsa");
        var authorization = new Model.Authorization(order, order.Identifiers[0], DateTimeOffset.UtcNow.AddDays(1));
        var challenge = new Model.Challenge(authorization, ChallengeTypes.Http01) { ExtraData = "evidence" };
        challenge.SetStatus(ChallengeStatus.Processing);
        await orders.SaveOrder(order, default);
        var loaded = await new OrderStore(options, NullLogger<OrderStore>.Instance).LoadOrder(order.OrderId, default);
        Assert.NotNull(loaded);
        Assert.Equal(order.OrderId, loaded.OrderId);
        Assert.Equal(account.AccountId, loaded.AccountId);
        Assert.Equal(order.Version, loaded.Version);
        Assert.Equal("rsa", loaded.Profile);
        var loadedAuthorization = Assert.Single(loaded.Authorizations);
        var loadedChallenge = Assert.Single(loadedAuthorization.Challenges);
        Assert.Equal(authorization.AuthorizationId, loadedAuthorization.AuthorizationId);
        Assert.Equal(challenge.ChallengeId, loadedChallenge.ChallengeId);
        Assert.Equal(challenge.Token, loadedChallenge.Token);
        Assert.Equal(ChallengeStatus.Processing, loadedChallenge.Status);
        Assert.Equal("evidence", loadedChallenge.ExtraData);
        Assert.Same(loaded, loadedAuthorization.Order);
        Assert.Same(loadedAuthorization, loadedChallenge.Authorization);
    }

    [Then("a persisted ACME nonce can only be consumed once concurrently")]
    public async Task AtomicNonceConsumption()
    {
        var store = new NonceStore(Options.Create(new FileStoreOptions { BasePath = _directory }));
        var nonce = new Model.Nonce(Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32)));
        await store.SaveNonceAsync(nonce, default);
        var attempts = Enumerable.Range(0, 20)
            .Select(_ => Task.Run(() => store.TryRemoveNonceAsync(nonce, default)));
        Assert.Single(await Task.WhenAll(attempts), consumed => consumed);
    }
}
