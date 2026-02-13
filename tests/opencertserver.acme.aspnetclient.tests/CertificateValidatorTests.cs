using CertesSlim.Extensions;

namespace OpenCertServer.Acme.AspNetClient.Tests;

using System;
using System.Collections.Generic;
using Certes;
using Certificates;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

public sealed class CertificateValidatorTests
{
    [Fact]
    public void IsCertificateValid_OnNullCert_ShouldReturnFalse()
    {
        var certificateValidator = new CertificateValidator(
            new LetsEncryptOptions { CertificateSigningRequest = new CsrInfo() },
            new NullLogger<CertificateValidator>());

        Assert.False(certificateValidator.IsCertificateValid(null));
    }

    [Theory]
    [MemberData(nameof(ValidateCertificateDate))]
    public void ValidateCertificateTests(CertificateDates cd, ValidatorSettings vs, bool expected)
    {
        var certificateValidator = new CertificateValidator(
            new LetsEncryptOptions
            {
                CertificateSigningRequest = new CsrInfo(),
                TimeUntilExpiryBeforeRenewal = vs.TimeUntilExpiryBeforeRenewal,
                TimeAfterIssueDateBeforeRenewal = vs.TimeAfterIssueDateBeforeRenewal
            },
            new NullLogger<CertificateValidator>());

        var cert = SelfSignedCertificate.Make(cd.From, cd.To);

        Assert.Equal(expected, certificateValidator.IsCertificateValid(cert));
    }

    public struct CertificateDates
    {
        public CertificateDates(DateTime from, DateTime to)
        {
            From = from;
            To = to;
        }

        public DateTime From;
        public DateTime To;

        public override string ToString()
        {
            return $"CertificateDates: [{From:d}-{To:d}]";
        }
    }

    public struct ValidatorSettings
    {
        public ValidatorSettings(TimeSpan? timeUntilExpiryBeforeRenewal, TimeSpan? timeAfterIssueDateBeforeRenewal)
        {
            TimeUntilExpiryBeforeRenewal = timeUntilExpiryBeforeRenewal;
            TimeAfterIssueDateBeforeRenewal = timeAfterIssueDateBeforeRenewal;
        }

        public TimeSpan? TimeUntilExpiryBeforeRenewal;
        public TimeSpan? TimeAfterIssueDateBeforeRenewal;

        public override string ToString()
        {
            static string Show(TimeSpan? ts) => ts == null ? "Never" : ts.Value.ToString("g");

            return
                $"ValidatorSettings: ({Show(TimeUntilExpiryBeforeRenewal)}, {Show(TimeAfterIssueDateBeforeRenewal)})";
        }
    }

    public static IEnumerable<object[]> ValidateCertificateDate()
    {
        // fresh certificate
        yield return Make(
            DateTime.Now.AddDays(-1).Date,
            DateTime.Now.AddDays(90).Date,
            null,
            TimeSpan.FromDays(30),
            true
        );

        // fresh certificate soon to expire
        yield return Make(
            DateTime.Now.AddDays(-10).Date,
            DateTime.Now.AddDays(10).Date,
            TimeSpan.FromDays(30),
            null,
            false
        );

        // close to expiry certificate mode 2
        yield return Make(
            DateTime.Now.AddDays(-10).Date,
            DateTime.Now.AddDays(10).Date,
            null,
            TimeSpan.FromDays(30),
            true);

        // future certificate
        yield return Make(
            DateTime.Now.AddDays(10).Date,
            DateTime.Now.AddDays(20).Date,
            null,
            TimeSpan.FromDays(30),
            false);

        // past certificate
        yield return Make(
            DateTime.Now.AddDays(-20).Date,
            DateTime.Now.AddDays(-10).Date,
            null,
            TimeSpan.FromDays(30),
            false);

        static object[] Make(
            DateTime certStart,
            DateTime certEnd,
            TimeSpan? timeUntilExpiryBeforeRenewal,
            TimeSpan? timeAfterIssueDateBeforeRenewal,
            bool isValid)
        {
            return
            [
                new CertificateDates(certStart, certEnd),
                new ValidatorSettings(timeUntilExpiryBeforeRenewal, timeAfterIssueDateBeforeRenewal),
                isValid
            ];
        }
    }
}
