namespace OpenCertServer.Acme.AspNetClient.Persistence;

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using OpenCertServer.Acme.Abstractions.Acme;

/// <summary>
/// Persists the ACME site certificate in the operating system's X.509 certificate store.
/// The certificate is stored with its private key, making it available to the server application
/// across restarts without requiring a separate key file.
/// </summary>
/// <remarks>
/// <para>
/// This strategy works across macOS, Linux, and Windows:
/// <list type="bullet">
///    <item><term>Windows</term><description>Stores in the Windows Certificate Store (CryptoAPI / CNG).</description></item>
///    <item><term>macOS</term><description>Stores in the user's Keychain.</description></item>
///    <item><term>Linux</term><description>Stores in the .NET per-user X.509 store directory
///    (<c>~/.dotnet/corefx/cryptography/x509stores/</c>).</description></item>
/// </list>
/// </para>
/// <para>
/// Account certificates (ACME private keys) are not stored in the certificate store; returning
/// <see langword="null"/> from <see cref="RetrieveAccountCertificate"/> causes the
/// <see cref="PersistenceService"/> to fall back to other registered strategies or request a new
/// account key from the ACME server.
/// </para>
/// </remarks>
public sealed class CertificateStorePersistenceStrategy : ICertificatePersistenceStrategy
{
    private readonly string _subjectName;
    private readonly StoreName _storeName;
    private readonly StoreLocation _storeLocation;

    private const char RouteSeparator = ':';
    private const string FriendlyNamePrefix = "OpenCertServer:";

     /// <summary>
     /// Initialises a new instance of <see cref="CertificateStorePersistenceStrategy"/>.
     /// </summary>
     /// <param name="subjectName">
     /// The subject (CN) or domain name used to identify the certificate inside the store.
     /// This must match (or be a substring of) the Subject of the ACME certificate, e.g.
     /// <c>"example.com"</c>.
     /// </param>
     /// <param name="storeName">
     /// The certificate store name. Defaults to <see cref="StoreName.My"/> (the personal store).
     /// </param>
     /// <param name="storeLocation">
     /// The store location. Defaults to <see cref="StoreLocation.CurrentUser"/>,
     /// which works without elevated privileges on all supported platforms.
     /// </param>
    public CertificateStorePersistenceStrategy(
        string subjectName,
        StoreName storeName = StoreName.My,
        StoreLocation storeLocation = StoreLocation.CurrentUser)
      {
        if (string.IsNullOrWhiteSpace(subjectName))
          {
            throw new ArgumentException("A non-empty subject name is required to identify the certificate in the store.", nameof(subjectName));
          }

          _subjectName = subjectName;
          _storeName = storeName;
          _storeLocation = storeLocation;
      }

     /// <inheritdoc />
    public Task Persist(CertificateType persistenceType, byte[] certificate)
      {
        if (persistenceType != CertificateType.Site)
          {
              // Account PEM keys are not stored in the OS certificate store.
            return Task.CompletedTask;
          }

        using var cert = X509CertificateLoader.LoadCertificate(certificate);
        StoreCertificate(cert, _subjectName);
        return Task.CompletedTask;
      }

     /// <inheritdoc />
    public Task PersistSiteCertificate(X509Certificate2 certificate)
      {
        StoreCertificate(certificate, RouteSubject(AcmeRouteConstants.DefaultRouteId));
        return Task.CompletedTask;
      }

     /// <summary>
     /// Stores the full certificate (including any associated private key) in the OS certificate
     /// store under a route-scoped subject name so that each YARP route keeps its own entry
     /// without colliding with other routes.
     /// </summary>
    public Task PersistSiteCertificate(X509Certificate2 certificate, string routeId)
      {
        StoreCertificate(certificate, RouteSubject(routeId));
        return Task.CompletedTask;
      }

     /// <inheritdoc />
    public Task<byte[]?> RetrieveAccountCertificate()
          => Task.FromResult<byte[]?>(null);

     /// <inheritdoc />
    public Task<X509Certificate2?> RetrieveSiteCertificate()
      {
        return RetrieveSiteCertificate(AcmeRouteConstants.DefaultRouteId);
      }

      /// <summary>
      /// Searches the OS certificate store for the certificate persisted for <paramref name="routeId"/>
      /// that has an accessible private key. On Windows the entry is disambiguated by
      /// <see cref="X509Certificate2.FriendlyName"/>; on other platforms the route-scoped subject
      /// composite (<c>{subjectName}:{routeId}</c>) is used. When multiple matches exist, the one
      /// with the latest expiry date is returned.
      /// </summary>
     public Task<X509Certificate2?> RetrieveSiteCertificate(string routeId)
        {
         var subject = RouteSubject(routeId);
         try
            {
             using var store = new X509Store(_storeName, _storeLocation);
             store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

              var match = store.Certificates
                    .Where(c => HasPrivateKey(c) && MatchesSubject(c, subject))
                    .OrderByDescending(c => c.NotAfter)
                    .FirstOrDefault();

             return Task.FromResult(match);
            }
         catch (CryptographicException)
            {
                // The store does not exist yet (can happen on first run with a custom store name).
             return Task.FromResult<X509Certificate2?>(null);
            }
        }

       /// <summary>
       /// The route-scoped store key. The default route uses the bare
       /// <see cref="_subjectName"/>; every other route is composed with a colon, which is not a
       /// valid domain character so the composite is unambiguous even when the subject or route id
       /// contains characters such as <c>@</c>.
       /// </summary>
      private string RouteSubject(string routeId)
        {
         return string.Equals(routeId, AcmeRouteConstants.DefaultRouteId, StringComparison.Ordinal)
               ? _subjectName
               : $"{_subjectName}{RouteSeparator}{routeId}";
        }

      private bool MatchesSubject(X509Certificate2 certificate, string subject)
          {
           // On Windows the entry is tagged with a FriendlyName so it is matched exactly there.
          if (OperatingSystem.IsWindows()
                   && !string.IsNullOrEmpty(certificate.FriendlyName))
                  {
                return string.Equals(certificate.FriendlyName, FriendlyNameFor(subject), StringComparison.OrdinalIgnoreCase);
                  }

                 // On non-Windows the FriendlyName is not preserved by the store, so match by subject.
               return string.Equals(certificate.GetNameInfo(X509NameType.SimpleName, false), subject, StringComparison.OrdinalIgnoreCase);
          }

      private static string FriendlyNameFor(string subject)
        {
         return OperatingSystem.IsWindows()
              ? $"{FriendlyNamePrefix}{subject}"
              : subject;
        }

      private static bool HasPrivateKey(X509Certificate2 certificate)
        {
          try
             {
              return certificate.HasPrivateKey;
             }
          catch (CryptographicException)
              {
               return false;
               }
        }

      private void StoreCertificate(X509Certificate2 certificate, string subject)
        {
         using var store = new X509Store(_storeName, _storeLocation);
        store.Open(OpenFlags.ReadWrite);

          // Remove any previously stored certificates matching this route to avoid accumulation
          // of stale entries across renewal cycles.
         var existing = store.Certificates
               .Where(c => MatchesSubject(c, subject));

         foreach (var old in existing)
            {
             store.Remove(old);
            }

          // On Windows the FriendlyName is the disambiguating key; it is not preserved by the
          // store on macOS/Linux, so the colon-separated subject composite is used there instead.
          var toAdd = certificate;
         if (OperatingSystem.IsWindows())
            {
             toAdd.FriendlyName = FriendlyNameFor(subject);
            }

        store.Add(toAdd);
        }
}
