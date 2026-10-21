namespace OpenCertServer.Contrib.Intune;

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

/// <summary>What a directory lookup for the revocation sync found.</summary>
public enum DirectoryState
{
    /// <summary>The object exists and is enabled.</summary>
    Present,

    /// <summary>The object exists but is disabled.</summary>
    Disabled,

    /// <summary>The object no longer exists.</summary>
    Missing
}

/// <summary>Intune answered, and said no (for example <c>ChallengeExpired</c>).</summary>
public sealed class IntuneRefusedException(string code, string description)
    : Exception($"Intune refused: {code}: {description}")
{
    public string Code { get; } = code;

    public string Description { get; } = description;
}

/// <summary>
/// Graph could not say for sure - unreachable, throttled (429), or an unexpected status.
/// The sync treats this as "unknown" and revokes nothing.
/// </summary>
public sealed class GraphUnavailableException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>What the success notification tells Intune about the issued certificate.</summary>
public sealed record IntuneIssuedInfo(
    string Thumbprint,
    string SerialNumber,
    DateTimeOffset ExpiresUtc,
    string IssuingAuthority);

/// <summary>The three SCEP calls of the Intune validation service, plus the Graph lookups the revocation sync needs.</summary>
public interface IIntuneClient
{
    /// <summary>
    /// Asks Intune whether the request (transaction id and CSR with the embedded challenge)
    /// is one it handed out. Returns normally when allowed; throws
    /// <see cref="IntuneRefusedException"/> when Intune says no, and
    /// <see cref="HttpRequestException"/> or <see cref="TaskCanceledException"/> when it
    /// could not be asked.
    /// </summary>
    Task ValidateRequest(string transactionId, string csrBase64, CancellationToken cancellationToken);

    Task NotifySuccess(string transactionId, string csrBase64, IntuneIssuedInfo issued, CancellationToken cancellationToken);

    Task NotifyFailure(string transactionId, string csrBase64, long hResult, string description, CancellationToken cancellationToken);

    Task<DirectoryState> GetUserState(string userPrincipalName, CancellationToken cancellationToken);

    Task<DirectoryState> GetManagedDeviceState(string intuneDeviceId, CancellationToken cancellationToken);

    /// <summary>
    /// The name Intune shows for a managed device (<c>deviceName</c>), for an inventory that
    /// lists certificates by device. Null when the device no longer exists or has no name;
    /// throws <see cref="GraphUnavailableException"/> when Graph could not say. Same
    /// permission as <see cref="GetManagedDeviceState"/>.
    /// </summary>
    Task<string?> GetManagedDeviceName(string intuneDeviceId, CancellationToken cancellationToken);

    Task<DirectoryState> GetEntraDeviceState(string entraDeviceId, CancellationToken cancellationToken);
}

/// <summary>
/// Talks to Entra (client credentials), Microsoft Graph (service discovery, directory
/// lookups) and the Intune SCEP validation service, following Microsoft's reference
/// (Intune-Resource-Access, CsrValidation) without its library.
/// </summary>
public sealed partial class IntuneClient : IIntuneClient
{
    private const string IntuneAppId = "0000000a-0000-0000-c000-000000000000";
    private const string ValidationServiceName = "ScepRequestValidationFEService";
    private const string ValidationApiVersion = "2018-02-20";

    private static readonly TimeSpan DiscoveryCacheFor = TimeSpan.FromHours(1);
    private static readonly TimeSpan TokenSafetyMargin = TimeSpan.FromMinutes(2);

    private readonly HttpClient _http;
    private readonly IntuneOptions _options;
    private readonly string? _clientSecret;
    private readonly ClientAssertion? _assertion;
    private readonly ILogger<IntuneClient> _logger;
    private readonly TimeProvider _time;
    private readonly SemaphoreSlim _tokenLock = new(1, 1);
    private readonly Dictionary<string, (string Token, DateTimeOffset Expires)> _tokens = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _discoveryLock = new(1, 1);
    private Uri? _validationEndpoint;
    private DateTimeOffset _discoveredAt;

    public IntuneClient(HttpClient http, IntuneOptions options, ILogger<IntuneClient> logger, TimeProvider? time = null)
    {
        _http = http;
        _options = options;
        _clientSecret = options.ResolveClientSecret();
        _assertion = options.UsesCertificate ? ClientAssertion.Load(options) : null;
        _logger = logger;
        _time = time ?? TimeProvider.System;
        _http.Timeout = options.Timeout;
        if (options.ValidationEndpoint is not null)
        {
            _validationEndpoint = options.ValidationEndpoint;
            _discoveredAt = DateTimeOffset.MaxValue;
        }
    }

    public Task ValidateRequest(string transactionId, string csrBase64, CancellationToken cancellationToken) =>
        PostToIntune(
            "ScepActions/validateRequest",
            JsonContent.Create(
                new ValidateEnvelope(new ValidateBody(transactionId, csrBase64, _options.CallerInfo)),
                IntuneJsonContext.Default.ValidateEnvelope),
            transactionId,
            cancellationToken);

    public Task NotifySuccess(
        string transactionId,
        string csrBase64,
        IntuneIssuedInfo issued,
        CancellationToken cancellationToken) =>
        PostToIntune(
            "ScepActions/successNotification",
            JsonContent.Create(
                new SuccessEnvelope(new SuccessBody(
                    transactionId,
                    csrBase64,
                    issued.Thumbprint,
                    issued.SerialNumber,
                    issued.ExpiresUtc.UtcDateTime.ToString("O"),
                    issued.IssuingAuthority,
                    _options.CallerInfo,
                    _options.CallerInfo,
                    issued.IssuingAuthority)),
                IntuneJsonContext.Default.SuccessEnvelope),
            transactionId,
            cancellationToken);

    public Task NotifyFailure(
        string transactionId,
        string csrBase64,
        long hResult,
        string description,
        CancellationToken cancellationToken) =>
        PostToIntune(
            "ScepActions/failureNotification",
            JsonContent.Create(
                new FailureEnvelope(new FailureBody(
                    transactionId,
                    csrBase64,
                    hResult,
                    description.Length <= 255 ? description : description[..255],
                    _options.CallerInfo)),
                IntuneJsonContext.Default.FailureEnvelope),
            transactionId,
            cancellationToken);

    public async Task<DirectoryState> GetUserState(string userPrincipalName, CancellationToken cancellationToken)
    {
        var (status, body) = await GraphGet(
                $"v1.0/users/{Uri.EscapeDataString(userPrincipalName)}?$select=accountEnabled",
                cancellationToken)
            .ConfigureAwait(false);
        return status switch
        {
            HttpStatusCode.NotFound => DirectoryState.Missing,
            HttpStatusCode.OK => ReadEnabled(body) ? DirectoryState.Present : DirectoryState.Disabled,
            _ => throw new GraphUnavailableException($"Graph users: HTTP {(int)status}")
        };
    }

    public async Task<DirectoryState> GetManagedDeviceState(string intuneDeviceId, CancellationToken cancellationToken)
    {
        var (status, _) = await GraphGet(
                $"v1.0/deviceManagement/managedDevices/{Uri.EscapeDataString(intuneDeviceId)}?$select=id",
                cancellationToken)
            .ConfigureAwait(false);
        return status switch
        {
            HttpStatusCode.NotFound => DirectoryState.Missing,
            HttpStatusCode.OK => DirectoryState.Present,
            _ => throw new GraphUnavailableException($"Graph managedDevices: HTTP {(int)status}")
        };
    }

    public async Task<string?> GetManagedDeviceName(string intuneDeviceId, CancellationToken cancellationToken)
    {
        var (status, body) = await GraphGet(
                $"v1.0/deviceManagement/managedDevices/{Uri.EscapeDataString(intuneDeviceId)}?$select=deviceName",
                cancellationToken)
            .ConfigureAwait(false);
        if (status == HttpStatusCode.NotFound)
        {
            return null;
        }

        if (status != HttpStatusCode.OK)
        {
            throw new GraphUnavailableException($"Graph managedDevices: HTTP {(int)status}");
        }

        using var document = JsonDocument.Parse(body);
        return document.RootElement.TryGetProperty("deviceName", out var name)
               && name.ValueKind == JsonValueKind.String
               && name.GetString() is { Length: > 0 } text
            ? text
            : null;
    }

    public async Task<DirectoryState> GetEntraDeviceState(string entraDeviceId, CancellationToken cancellationToken)
    {
        var filter = Uri.EscapeDataString($"deviceId eq '{entraDeviceId}'");
        var (status, body) = await GraphGet($"v1.0/devices?$filter={filter}&$select=accountEnabled", cancellationToken)
            .ConfigureAwait(false);
        if (status != HttpStatusCode.OK)
        {
            throw new GraphUnavailableException($"Graph devices: HTTP {(int)status}");
        }

        using var document = JsonDocument.Parse(body);
        if (!document.RootElement.TryGetProperty("value", out var values) || values.GetArrayLength() == 0)
        {
            return DirectoryState.Missing;
        }

        var first = values[0];
        return first.TryGetProperty("accountEnabled", out var enabled) && enabled.ValueKind == JsonValueKind.False
            ? DirectoryState.Disabled
            : DirectoryState.Present;
    }

    private static bool ReadEnabled(string body)
    {
        using var document = JsonDocument.Parse(body);
        return !(document.RootElement.TryGetProperty("accountEnabled", out var enabled)
                 && enabled.ValueKind == JsonValueKind.False);
    }

    private async Task PostToIntune(string action, JsonContent payload, string transactionId, CancellationToken cancellationToken)
    {
        var endpoint = await DiscoverValidationEndpoint(cancellationToken).ConfigureAwait(false);
        // The reference library asks for the scope exactly as "<resource>//.default".
        var token = await GetToken($"{_options.IntuneResource}/.default", cancellationToken).ConfigureAwait(false);

        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(endpoint, action));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.TryAddWithoutValidation("api-version", ValidationApiVersion);
        request.Headers.TryAddWithoutValidation("client-request-id", Guid.NewGuid().ToString());
        request.Content = payload;

        HttpResponseMessage response;
        try
        {
            response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException)
        {
            ForgetEndpoint();
            throw;
        }

        using (response)
        {
            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                ForgetEndpoint();
                throw new HttpRequestException(
                    $"Intune {action} (transaction {transactionId}): HTTP {(int)response.StatusCode}: {Truncate(body)}",
                    null,
                    response.StatusCode);
            }

            IntuneReply? reply;
            try
            {
                reply = JsonSerializer.Deserialize(body, IntuneJsonContext.Default.IntuneReply);
            }
            catch (JsonException ex)
            {
                throw new HttpRequestException($"Intune {action}: unreadable reply: {Truncate(body)}", ex);
            }

            if (reply is null || !string.Equals(reply.Code, "Success", StringComparison.OrdinalIgnoreCase))
            {
                throw new IntuneRefusedException(reply?.Code ?? "(no code)", reply?.ErrorDescription ?? "(no description)");
            }
        }
    }

    private async Task<(HttpStatusCode Status, string Body)> GraphGet(string path, CancellationToken cancellationToken)
    {
        string token;
        try
        {
            token = await GetToken($"{_options.GraphBase}.default", cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            throw new GraphUnavailableException($"Graph token: {ex.Message}", ex);
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(_options.GraphBase, path));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.TryAddWithoutValidation("ConsistencyLevel", "eventual");
        try
        {
            using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            return (response.StatusCode, body);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            throw new GraphUnavailableException($"Graph {path}: {ex.Message}", ex);
        }
    }

    private async Task<Uri> DiscoverValidationEndpoint(CancellationToken cancellationToken)
    {
        await _discoveryLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_validationEndpoint is not null && _time.GetUtcNow() - _discoveredAt < DiscoveryCacheFor)
            {
                return _validationEndpoint;
            }

            var (status, body) = await GraphGet(
                    $"v1.0/servicePrincipals/appId={IntuneAppId}/endpoints",
                    cancellationToken)
                .ConfigureAwait(false);
            if (status != HttpStatusCode.OK)
            {
                throw new HttpRequestException($"Intune service discovery: HTTP {(int)status}: {Truncate(body)}", null, status);
            }

            using var document = JsonDocument.Parse(body);
            if (document.RootElement.TryGetProperty("value", out var endpoints))
            {
                foreach (var endpoint in endpoints.EnumerateArray())
                {
                    var name = endpoint.TryGetProperty("providerName", out var provider) && provider.ValueKind == JsonValueKind.String
                        ? provider.GetString()
                        : endpoint.TryGetProperty("serviceName", out var service) ? service.GetString() : null;
                    if (!string.Equals(name, ValidationServiceName, StringComparison.OrdinalIgnoreCase)
                        || !endpoint.TryGetProperty("uri", out var uri)
                        || uri.GetString() is not { Length: > 0 } address)
                    {
                        continue;
                    }

                    _validationEndpoint = new Uri(address.TrimEnd('/') + "/");
                    _discoveredAt = _time.GetUtcNow();
                    LogDiscovered(_logger, _validationEndpoint);
                    return _validationEndpoint;
                }
            }

            throw new HttpRequestException(
                $"{ValidationServiceName} not found among the Intune service principal endpoints - check the Intune licence and the app permissions.");
        }
        finally
        {
            _discoveryLock.Release();
        }
    }

    private void ForgetEndpoint()
    {
        if (_options.ValidationEndpoint is not null)
        {
            return;
        }

        _validationEndpoint = null;
    }

    private async Task<string> GetToken(string scope, CancellationToken cancellationToken)
    {
        await _tokenLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_tokens.TryGetValue(scope, out var cached) && cached.Expires - _time.GetUtcNow() > TokenSafetyMargin)
            {
                return cached.Token;
            }

            var endpoint = new Uri(_options.LoginBase, $"{Uri.EscapeDataString(_options.TenantId)}/oauth2/v2.0/token");
            var form = new List<KeyValuePair<string, string>>
            {
                new("grant_type", "client_credentials"),
                new("client_id", _options.ClientId),
                new("scope", scope)
            };
            if (_assertion is not null)
            {
                // Certificate credential (RFC 7523): a JWT signed with the app's key, audience
                // the token endpoint - no secret leaves the server.
                form.Add(new("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
                form.Add(new("client_assertion", _assertion.Create(_options.ClientId, endpoint, _time.GetUtcNow())));
            }
            else
            {
                form.Add(new("client_secret", _clientSecret!));
            }

            using var content = new FormUrlEncodedContent(form);
            using var response = await _http.PostAsync(endpoint, content, cancellationToken).ConfigureAwait(false);
            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException(
                    $"Token request for {scope}: HTTP {(int)response.StatusCode}: {Truncate(body)}",
                    null,
                    response.StatusCode);
            }

            var reply = JsonSerializer.Deserialize(body, IntuneJsonContext.Default.TokenReply);
            if (reply?.AccessToken is not { Length: > 0 } token)
            {
                throw new HttpRequestException("Token reply carries no access_token.");
            }

            _tokens[scope] = (token, _time.GetUtcNow().AddSeconds(reply.ExpiresIn));
            return token;
        }
        finally
        {
            _tokenLock.Release();
        }
    }

    private static string Truncate(string text) => text.Length <= 400 ? text : text[..400];

    [LoggerMessage(LogLevel.Information, "Intune SCEP validation service discovered at {Endpoint}")]
    private static partial void LogDiscovered(ILogger logger, Uri endpoint);
}
