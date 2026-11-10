namespace OpenCertServer.Contrib.Intune;

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils;

/// <summary>
/// Who a certificate was issued to, read from the names Intune puts into the request:
/// the user principal name (otherName <c>1.3.6.1.4.1.311.20.2.3</c>) for a user
/// certificate, the Intune device id (URI <c>IntuneDeviceId://…</c>) when the profile
/// carries it, and the common name - a device certificate with <c>CN={{AAD_Device_ID}}</c>
/// has a GUID there.
/// </summary>
public sealed record CertificateIdentity(string? UserPrincipalName, string? IntuneDeviceId, string? CommonName)
{
    private const string IntuneDeviceIdScheme = "intunedeviceid://";

    /// <summary>The common name, when it is a GUID - the Entra device id of a device certificate.</summary>
    public string? EntraDeviceId => CommonName is not null && Guid.TryParse(CommonName, out _) ? CommonName : null;

    /// <summary>True when there is anything a directory could be asked about.</summary>
    public bool IsCheckable => UserPrincipalName is not null || IntuneDeviceId is not null || EntraDeviceId is not null;

    public static CertificateIdentity Read(X509Certificate2 certificate)
    {
        var san = certificate.Extensions.FirstOrDefault(e => e.Oid?.Value == Oids.SubjectAltName);
        var (upn, deviceId) = san is null ? (null, null) : ReadOtherNames(san.RawData);
        return new CertificateIdentity(upn, deviceId, certificate.GetNameInfo(X509NameType.SimpleName, false) is { Length: > 0 } cn ? cn : null);
    }

    private static (string? Upn, string? IntuneDeviceId) ReadOtherNames(byte[] sanDer)
    {
        string? upn = null;
        string? deviceId = null;
        try
        {
            var reader = new AsnReader(sanDer, AsnEncodingRules.DER);
            var names = reader.ReadSequence();
            while (names.HasData)
            {
                var tag = names.PeekTag();
                if (tag.TagClass != TagClass.ContextSpecific)
                {
                    names.ReadEncodedValue();
                    continue;
                }

                switch (tag.TagValue)
                {
                    case 0: // otherName ::= SEQUENCE { type-id OID, value [0] EXPLICIT ANY }
                        var other = names.ReadSequence(tag);
                        var typeId = other.ReadObjectIdentifier();
                        var value = other.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
                        if (typeId == Oids.UserPrincipalName && upn is null)
                        {
                            upn = value.ReadCharacterString(UniversalTagNumber.UTF8String);
                        }

                        break;
                    case 6: // uniformResourceIdentifier IA5String
                        var uri = names.ReadCharacterString(UniversalTagNumber.IA5String, tag);
                        if (uri.StartsWith(IntuneDeviceIdScheme, StringComparison.OrdinalIgnoreCase))
                        {
                            deviceId = uri[IntuneDeviceIdScheme.Length..].TrimEnd('/');
                        }

                        break;
                    default:
                        names.ReadEncodedValue();
                        break;
                }
            }
        }
        catch (AsnContentException)
        {
            // A malformed SAN is not ours to repair; whatever was read before stands.
        }
        catch (CryptographicException)
        {
        }

        return (upn, deviceId);
    }
}
