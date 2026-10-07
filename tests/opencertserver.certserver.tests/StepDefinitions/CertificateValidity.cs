namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Security.Cryptography.X509Certificates;
using Reqnroll;
using Xunit;

public partial class CertificateServerFeatures
{
    private string? _originalTimeZone;
    private bool _timeZoneChanged;

    // The local time zone is process-wide, so the feature is tagged
    // @nonparallelizable and the zone is restored after each scenario.
    // .NET reads the TZ variable on Linux and macOS; Windows ignores it,
    // so the scenario is skipped there rather than passing vacuously.
    [Given(@"the server time zone is (.+)")]
    public void GivenTheServerTimeZoneIs(string zone)
    {
        _originalTimeZone = Environment.GetEnvironmentVariable("TZ");
        _timeZoneChanged = true;
        Environment.SetEnvironmentVariable("TZ", zone);
        TimeZoneInfo.ClearCachedData();
        if (TimeZoneInfo.Local.Id != zone)
        {
            Assert.Skip($"The local time zone cannot be set to {zone} on this platform (it is {TimeZoneInfo.Local.Id}).");
        }
    }

    [AfterScenario]
    public void RestoreTimeZone()
    {
        if (!_timeZoneChanged)
        {
            return;
        }

        Environment.SetEnvironmentVariable("TZ", _originalTimeZone);
        TimeZoneInfo.ClearCachedData();
        _timeZoneChanged = false;
    }

    [Then(@"the certificate should be valid from midnight UTC today")]
    public void ThenTheCertificateShouldBeValidFromMidnightUtcToday()
    {
        AssertValidFromMidnightUtc(_certCollection[0]);
    }

    [Then(@"the CA certificate should be valid from midnight UTC today")]
    public async Task ThenTheCaCertificateShouldBeValidFromMidnightUtcToday()
    {
        var caCertificates = await _estClient.ServerCertificates().ConfigureAwait(false);
        Assert.NotEmpty(caCertificates);
        foreach (var caCertificate in caCertificates)
        {
            AssertValidFromMidnightUtc(caCertificate);
        }
    }

    private static void AssertValidFromMidnightUtc(X509Certificate2 certificate)
    {
        // NotBefore is reported in local time; ToUniversalTime uses the zone set above.
        var notBefore = certificate.NotBefore.ToUniversalTime();
        var now = DateTime.UtcNow;
        Assert.Equal(TimeSpan.Zero, notBefore.TimeOfDay);
        Assert.True(notBefore <= now, $"Certificate is not yet valid: notBefore {notBefore:o}, now {now:o}.");
        Assert.True(now - notBefore < TimeSpan.FromDays(1), $"notBefore {notBefore:o} is not today ({now:o}).");
    }
}
