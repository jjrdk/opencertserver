using OpenCertServer.Ca.Utils;

namespace OpenCertServer.Ca.Server;

using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.Ocsp;

/// <summary>
/// Validates signed OCSP requests by verifying the signature on the TBSRequest.
/// </summary>
public sealed class OcspRequestSignatureValidator : IValidateOcspRequest
{
    /// <inheritdoc />
    public Task<OcspResponseStatus?> Validate(OcspRequest request)
    {
        if (request.Signature is null)
        {
            // Unsigned requests are allowed; no error.
            return Task.FromResult<OcspResponseStatus?>(null);
        }

        // For signed requests, we need to verify the signature.
        // The signature is over the TBSRequest, and the signer certs are included in the request.
        if (request.Signature.Certs is null || request.Signature.Certs.Count == 0)
        {
            // Signed request must include signer certificate.
            return Task.FromResult<OcspResponseStatus?>(OcspResponseStatus.Unauthorized);
        }

        var signerCert = request.Signature.Certs[0]; // Use the first cert as signer.

        // Verify the signature.
        var tbsWriter = new AsnWriter(AsnEncodingRules.DER);
        request.TbsRequest.Encode(tbsWriter);
        var dataToVerify = tbsWriter.Encode();

        bool signatureValid;
        try
        {
            if (signerCert.GetRSAPublicKey() is { } rsa)
            {
                signatureValid = rsa.VerifyData(dataToVerify, request.Signature.SignatureBytes,
                    request.Signature.AlgorithmIdentifier.AlgorithmOid.Value!.GetHashAlgorithmNameFromOid(),
                    request.Signature.AlgorithmIdentifier.AlgorithmOid.Value!.GetRsaSignaturePaddingFromOid());
            }
            else if (signerCert.GetECDsaPublicKey() is { } ecdsa)
            {
                signatureValid = ecdsa.VerifyData(dataToVerify, request.Signature.SignatureBytes,
                    request.Signature.AlgorithmIdentifier.AlgorithmOid.Value!.GetHashAlgorithmNameFromOid());
            }
            else
            {
                // Unsupported key type.
                return Task.FromResult<OcspResponseStatus?>(OcspResponseStatus.Unauthorized);
            }
        }
        catch
        {
            return Task.FromResult<OcspResponseStatus?>(OcspResponseStatus.Unauthorized);
        }

        return !signatureValid
            ? Task.FromResult<OcspResponseStatus?>(OcspResponseStatus.Unauthorized)
            // Optionally, validate the signer certificate (e.g., check EKU, chain, etc.).
            // For now, just accept if signature is valid.
            : Task.FromResult<OcspResponseStatus?>(null);
    }
}
