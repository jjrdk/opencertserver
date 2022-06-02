namespace OpenCertServer.Acme.AspNetClient.Certificates;

using Certes;
using global::Certes;

/// <summary>
/// A certificate which can return an IKey
/// </summary>
public interface IKeyCertificate
{
    IKey? Key { get; }
}