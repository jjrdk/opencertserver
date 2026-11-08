using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using OpenCertServer.Ca.Protocol;

namespace OpenCertServer.Ca.Server.Handlers;

using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;

using System.Diagnostics;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using OpenCertServer.Ca.Utils.Ca;
using Utils.X509Extensions;

public static class CsrHandler
{
    /// <summary>
    /// <c>POST /ca/csr</c>: signs with the default profile. The route has no profile parameter, so
    /// this overload must not ask for one - a <c>[FromRoute]</c> parameter that the route does not
    /// define makes the generated request delegate throw before the handler runs.
    /// </summary>
    public static Task<IResult> Handle(
        HttpContext context,
        ClaimsPrincipal user,
        ICertificateAuthority ca,
        [FromBody] Stream body,
        CancellationToken cancellationToken)
    {
        return HandleProfile(null, context, user, ca, body, cancellationToken);
    }

    /// <summary>
    /// <c>POST /ca/{profileName}/csr</c>: signs with the named profile.
    /// </summary>
    public static async Task<IResult> HandleProfile(
        [FromRoute] string? profileName,
        HttpContext context,
        ClaimsPrincipal user,
        ICertificateAuthority ca,
        [FromBody] Stream body,
        CancellationToken cancellationToken)
    {
        CaInstruments.CsrRequests.Add(1);
        var sw = Stopwatch.GetTimestamp();
        using var activity = CaInstruments.ActivitySource.StartActivity(ActivityNames.CsrSign);
        try
        {
            using var reader = new StreamReader(body);
            var csrPem = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
            var requestor = user.Identity as ClaimsIdentity;
            if (context.Request.Headers.TryGetValue(RaClaimTypes.DelegatedSubjectHeader, out var scopes))
            {
                if (scopes.Count != 1 || string.IsNullOrWhiteSpace(scopes[0]) ||
                    requestor?.FindFirst(RaClaimTypes.RaId) == null)
                {
                    return Results.BadRequest("A delegated-subject selector is valid only for an authenticated RA.");
                }

                var claims = requestor.Claims.ToList();
                claims.Add(new Claim(RaClaimTypes.DelegatedSubject, scopes[0]!));
                requestor = new ClaimsIdentity(
                    claims,
                    requestor.AuthenticationType,
                    requestor.NameClaimType,
                    requestor.RoleClaimType);
            }

            // A remote SCEP/EST peer that cannot host the CA core carries the certificate being
            // re-enrolled from as a PEM header so the CA supersedes (superseding-revokes) it on the
            // new certificate. Absence leaves first-enrollment behavior unchanged.
            X509Certificate2? reenrollingFrom = null;
            if (context.Request.Headers.TryGetValue(RaProtocol.ReenrollingFromHeader,
                    out var reenrollingFromHeader) &&
                !string.IsNullOrWhiteSpace(reenrollingFromHeader))
            {
                try
                {
                    reenrollingFrom = X509Certificate2.CreateFromPem(reenrollingFromHeader.ToString());
                }
                catch (Exception)
                {
                    return Results.BadRequest("Invalid reenrollingFrom header: cannot parse PEM");
                }
            }

            var certResponse = await ca.SignCertificateRequestPem(csrPem, profileName, requestor,
                reenrollingFrom, cancellationToken: cancellationToken).ConfigureAwait(false);
            if (certResponse is SignCertificateResponse.Success success)
            {
                CaInstruments.CsrSuccesses.Add(1);
                activity?.SetStatus(ActivityStatusCode.Ok);
                return Results.Text(success.Certificate.ToPemChain(success.Issuers), Constants.PemMimeType);
            }

            var error = (SignCertificateResponse.Error)certResponse;
            CaInstruments.CsrFailures.Add(1);
            activity?.SetStatus(ActivityStatusCode.Error);
            return Results.Text(
                string.Join(Environment.NewLine, error.Errors),
                Constants.TextPlainMimeType,
                Encoding.UTF8,
                (int)HttpStatusCode.BadRequest);
        }
        catch (Exception ex)
        {
            CaInstruments.CsrFailures.Add(1);
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            throw;
        }
        finally
        {
            CaInstruments.CsrDuration.Record(Stopwatch.GetElapsedTime(sw).TotalSeconds);
        }
    }
}
