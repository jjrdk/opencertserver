namespace OpenCertServer.Contrib.Intune.Tests;

using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;

/// <summary>How the fake Intune answers <c>validateRequest</c>.</summary>
public enum IntuneBehaviour
{
    Allow,
    Refuse,
    Unreachable,
    Throttle
}

/// <summary>How the fake Graph answers directory lookups.</summary>
public enum GraphBehaviour
{
    Answer,
    Throttle,
    Unreachable
}

/// <summary>
/// Entra, Graph and the Intune SCEP validation service in one <see cref="HttpMessageHandler"/> -
/// a fake, not a container: the Intune side is four small JSON endpoints, and what a fake
/// cannot say about the real service is for the end-to-end phase against a real tenant.
/// </summary>
public sealed class FakeIntune : HttpMessageHandler
{
    public const string Tenant = "contoso.test";
    public static readonly Uri ValidationService = new("https://intune.fake/scep/");

    public IntuneBehaviour Intune { get; set; } = IntuneBehaviour.Allow;

    public GraphBehaviour Graph { get; set; } = GraphBehaviour.Answer;

    public string RefusalCode { get; set; } = "ChallengeExpired";

    /// <summary>Users known to the fake directory: UPN → enabled.</summary>
    public ConcurrentDictionary<string, bool> Users { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Intune managed device ids that still exist.</summary>
    public ConcurrentDictionary<string, byte> ManagedDevices { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>The name Intune shows for a managed device id; a device without an entry has none.</summary>
    public ConcurrentDictionary<string, string> DeviceNames { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Entra devices: deviceId → enabled.</summary>
    public ConcurrentDictionary<string, bool> EntraDevices { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Every call, in order: (path, body as JSON or null).</summary>
    public ConcurrentQueue<(string Path, JsonNode? Body, string? ApiVersion)> Calls { get; } = new();

    public int TokenRequests;

    /// <summary>Set when the app authenticates with a certificate: every token request must carry a valid assertion signed by it.</summary>
    public X509Certificate2? AppCertificate { get; set; }

    public int TokenRequestsWithAssertion;

    /// <summary>When set, Graph lookups wait here - to hold a sync in progress.</summary>
    public SemaphoreSlim? GraphGate { get; set; }

    public IEnumerable<JsonNode?> CallsTo(string action) =>
        Calls.Where(c => c.Path.EndsWith(action, StringComparison.OrdinalIgnoreCase)).Select(c => c.Body);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var path = request.RequestUri!.GetLeftPart(UriPartial.Path);
        JsonNode? body = null;
        if (request.Content is not null && request.Content.Headers.ContentType?.MediaType == "application/json")
        {
            body = JsonNode.Parse(await request.Content.ReadAsStringAsync(cancellationToken));
        }

        request.Headers.TryGetValues("api-version", out var versions);
        Calls.Enqueue((request.RequestUri.PathAndQuery, body, versions?.FirstOrDefault()));

        if (path.EndsWith("/oauth2/v2.0/token", StringComparison.Ordinal))
        {
            Interlocked.Increment(ref TokenRequests);
            var form = (await request.Content!.ReadAsStringAsync(cancellationToken))
                .Split('&')
                .Select(p => p.Split('=', 2))
                .ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p.Length > 1 ? p[1] : ""));
            if (AppCertificate is not null)
            {
                if (!form.TryGetValue("client_assertion", out var assertion)
                    || form.GetValueOrDefault("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                    || !AssertionIsValid(assertion, form["client_id"], request.RequestUri))
                {
                    return Json(HttpStatusCode.Unauthorized, new { error = "invalid_client" });
                }

                Interlocked.Increment(ref TokenRequestsWithAssertion);
            }
            else if (form.GetValueOrDefault("client_secret") != "test-secret")
            {
                return Json(HttpStatusCode.Unauthorized, new { error = "invalid_client" });
            }

            return Json(HttpStatusCode.OK, new { access_token = "token-for-" + form["scope"], expires_in = 3600 });
        }

        if (request.RequestUri.Host == "graph.microsoft.com")
        {
            return await GraphAnswer(request, cancellationToken);
        }

        if (request.RequestUri.Host == ValidationService.Host)
        {
            return IntuneAnswer(request.RequestUri.AbsolutePath);
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    private HttpResponseMessage IntuneAnswer(string path)
    {
        if (path.EndsWith("/ScepActions/validateRequest", StringComparison.OrdinalIgnoreCase))
        {
            return Intune switch
            {
                IntuneBehaviour.Allow => Json(HttpStatusCode.OK, new { code = "Success", errorDescription = "" }),
                IntuneBehaviour.Refuse => Json(HttpStatusCode.OK, new { code = RefusalCode, errorDescription = "The challenge is not valid." }),
                IntuneBehaviour.Throttle => Json(HttpStatusCode.TooManyRequests, new { error = "throttled" }),
                _ => throw new HttpRequestException("intune.fake: connection refused")
            };
        }

        if (path.EndsWith("/ScepActions/successNotification", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith("/ScepActions/failureNotification", StringComparison.OrdinalIgnoreCase))
        {
            return Json(HttpStatusCode.OK, new { code = "Success", errorDescription = "" });
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    private async Task<HttpResponseMessage> GraphAnswer(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var path = request.RequestUri!.AbsolutePath;
        if (path.Contains("/servicePrincipals/appId=0000000a-0000-0000-c000-000000000000/endpoints", StringComparison.Ordinal))
        {
            return Json(HttpStatusCode.OK, new
            {
                value = new object[]
                {
                    new { providerName = "SomethingElse", uri = "https://other.fake/" },
                    new { providerName = "ScepRequestValidationFEService", uri = ValidationService.ToString().TrimEnd('/') }
                }
            });
        }

        if (GraphGate is not null)
        {
            await GraphGate.WaitAsync(cancellationToken);
            GraphGate.Release();
        }

        switch (Graph)
        {
            case GraphBehaviour.Throttle:
                return Json(HttpStatusCode.TooManyRequests, new { error = "throttled" });
            case GraphBehaviour.Unreachable:
                throw new HttpRequestException("graph.microsoft.com: connection refused");
        }

        var query = request.RequestUri.Query;
        if (path.StartsWith("/v1.0/users/", StringComparison.Ordinal))
        {
            var upn = Uri.UnescapeDataString(path["/v1.0/users/".Length..]);
            return Users.TryGetValue(upn, out var enabled)
                ? Json(HttpStatusCode.OK, new { accountEnabled = enabled })
                : Json(HttpStatusCode.NotFound, new { error = new { code = "Request_ResourceNotFound" } });
        }

        if (path.StartsWith("/v1.0/deviceManagement/managedDevices/", StringComparison.Ordinal))
        {
            var id = Uri.UnescapeDataString(path["/v1.0/deviceManagement/managedDevices/".Length..]);
            // Graph returns exactly what $select names - a lookup asking for the id must not see the name.
            return ManagedDevices.ContainsKey(id)
                ? query.Contains("deviceName", StringComparison.Ordinal)
                    ? Json(HttpStatusCode.OK, new { deviceName = DeviceNames.GetValueOrDefault(id) })
                    : Json(HttpStatusCode.OK, new { id })
                : Json(HttpStatusCode.NotFound, new { error = new { code = "ResourceNotFound" } });
        }

        if (path == "/v1.0/devices")
        {
            var filter = Uri.UnescapeDataString(query);
            var start = filter.IndexOf('\'') + 1;
            var deviceId = filter[start..filter.IndexOf('\'', start)];
            return EntraDevices.TryGetValue(deviceId, out var enabled)
                ? Json(HttpStatusCode.OK, new { value = new object[] { new { accountEnabled = enabled } } })
                : Json(HttpStatusCode.OK, new { value = Array.Empty<object>() });
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    // RS256 over header.claims, x5t = SHA-1 thumbprint, aud = the token endpoint, iss = sub = client id.
    private bool AssertionIsValid(string jwt, string clientId, Uri tokenEndpoint)
    {
        var parts = jwt.Split('.');
        if (parts.Length != 3)
        {
            return false;
        }

        using var header = JsonDocument.Parse(FromBase64Url(parts[0]));
        using var claims = JsonDocument.Parse(FromBase64Url(parts[1]));
        var expectedX5t = Convert.ToBase64String(AppCertificate!.GetCertHash(System.Security.Cryptography.HashAlgorithmName.SHA1))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        if (header.RootElement.GetProperty("alg").GetString() != "RS256"
            || header.RootElement.GetProperty("x5t").GetString() != expectedX5t
            || claims.RootElement.GetProperty("aud").GetString() != tokenEndpoint.ToString()
            || claims.RootElement.GetProperty("iss").GetString() != clientId
            || claims.RootElement.GetProperty("sub").GetString() != clientId
            || claims.RootElement.GetProperty("exp").GetInt64() < DateTimeOffset.UtcNow.ToUnixTimeSeconds())
        {
            return false;
        }

        using var rsa = AppCertificate.GetRSAPublicKey()!;
        return rsa.VerifyData(
            System.Text.Encoding.UTF8.GetBytes(parts[0] + "." + parts[1]),
            FromBase64Url(parts[2]),
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);
    }

    private static byte[] FromBase64Url(string text)
    {
        var padded = text.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '='));
    }

    private static HttpResponseMessage Json(HttpStatusCode status, object payload) =>
        new(status) { Content = JsonContent.Create(payload, options: new JsonSerializerOptions(JsonSerializerDefaults.Web)) };
}
