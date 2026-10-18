namespace OpenCertServer.CertServer;

using System.Formats.Asn1;
using System.Security.Claims;
using OpenCertServer.Ca.Utils.X509.Templates;
using OpenCertServer.Est.Server.Handlers;
using OpenCertServer.Est.Server.Response;

/// <summary>Publishes an optional DER CsrAttrs file through the standalone host's EST endpoints.</summary>
internal sealed class ConfiguredCsrTemplateLoader(IConfiguration configuration) : ICsrTemplateLoader
{
    /// <inheritdoc />
    public async Task<CsrAttributesResponse> GetTemplate(
        string? profileName = null,
        ClaimsPrincipal? user = null,
        CancellationToken cancellationToken = default)
    {
        var path = configuration["Est:CsrAttributesFile"];
        if (string.IsNullOrWhiteSpace(path))
        {
            return CsrAttributesResponse.Unavailable();
        }

        var encoded = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        var reader = new AsnReader(encoded, AsnEncodingRules.DER);
        var attributes = new CsrAttributes(reader);
        reader.ThrowIfNotEmpty();
        if (!attributes.HasValues)
        {
            throw new InvalidOperationException("Est:CsrAttributesFile must contain nonempty DER CsrAttrs.");
        }

        return CsrAttributesResponse.Available(attributes);
    }
}
