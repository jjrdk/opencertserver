namespace OpenCertServer.Contrib.Intune;

using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using OpenCertServer.Scep.Server;

/// <summary>
/// Adds a webhook decision after Intune has validated the device's challenge and CSR.
/// The webhook never replaces Intune's validation.
/// </summary>
public sealed partial class DynamicChallengeValidator(
    IntuneChallengeValidator intune,
    HttpClient http,
    DynamicChallengeOptions options,
    ILogger<DynamicChallengeValidator> logger) : IScepChallengeValidator
{
    /// <inheritdoc />
    public async Task<ScepChallengeResult> Validate(ScepChallengeContext context, CancellationToken cancellationToken)
    {
        var decision = await intune.Validate(context, cancellationToken).ConfigureAwait(false);
        if (!decision.Allowed)
        {
            return decision;
        }

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, options.Webhook);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", options.Secret);
            request.Content = JsonContent.Create(
                new DynamicChallengeRequest(context.TransactionId, context.ProfileName,
                    context.MessageType.ToString(), Convert.ToBase64String(context.RequestDer)),
                IntuneJsonContext.Default.DynamicChallengeRequest);
            using var response = await http.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                LogWebhookStatus(logger, (int)response.StatusCode);
                return ScepChallengeResult.Deny("The enrollment authorization webhook failed.");
            }

            var result = await response.Content.ReadFromJsonAsync(
                IntuneJsonContext.Default.DynamicChallengeResponse, cancellationToken).ConfigureAwait(false);
            return result?.Allowed == true
                ? decision
                : ScepChallengeResult.Deny("The enrollment authorization webhook denied the request.");
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or NotSupportedException
                                   || ex is OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            LogWebhookFailed(logger);
            return ScepChallengeResult.Deny("The enrollment authorization webhook could not be contacted or returned an invalid response.");
        }
    }

    /// <inheritdoc />
    public Task NotifySuccess(ScepChallengeContext context, X509Certificate2 issued, CancellationToken cancellationToken) =>
        intune.NotifySuccess(context, issued, cancellationToken);

    /// <inheritdoc />
    public Task NotifyFailure(ScepChallengeContext context, string reason, CancellationToken cancellationToken) =>
        intune.NotifyFailure(context, reason, cancellationToken);

    [LoggerMessage(LogLevel.Warning, "The enrollment authorization webhook returned HTTP {StatusCode}.")]
    private static partial void LogWebhookStatus(ILogger logger, int statusCode);

    [LoggerMessage(LogLevel.Warning, "The enrollment authorization webhook was unavailable or returned invalid JSON.")]
    private static partial void LogWebhookFailed(ILogger logger);
}
