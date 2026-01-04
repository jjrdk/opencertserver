using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Certes.Acme;
using Certes.Acme.Resource;
using Certes.Extensions;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Xunit;

namespace Certes;

public static class IntegrationHelper
{
    public static readonly List<byte[]> TestCertificates = [];

    public static readonly Lazy<HttpClient> Http = new(() =>
    {
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };
        return new HttpClient(handler);
    });

    private static Uri _stagingServerV2;

    public static IAcmeHttpClient GetAcmeHttpClient(Uri uri) => Helper.CreateHttp(uri, Http.Value);

    public static async Task<Uri> GetAcmeUriV2()
    {
        if (_stagingServerV2 != null)
        {
            return _stagingServerV2;
        }

        var servers = new[]
        {
            //new Uri("https://lo0.in:4431/directory"),
            //new Uri("http://localhost:8080/dir"),
            new Uri("https://pebble.azurewebsites.net/dir"),
            //WellKnownServers.LetsEncryptStagingV2,
        };

        var exceptions = new List<Exception>();
        foreach (var uri in servers)
        {
            try
            {
                await Http.Value.GetStringAsync(uri);

                foreach (var algo in new[]
                    {
                        SecurityAlgorithms.EcdsaSha256, SecurityAlgorithms.EcdsaSha384, SecurityAlgorithms.RsaSha256
                    })
                {
                    try
                    {
                        var ctx = new AcmeContext(uri, Helper.GetKeyV2(algo), GetAcmeHttpClient(uri));
                        await ctx.NewAccount(["mailto:ci@certes.app"], true);
                    }
                    catch
                    {
                    }
                }

                try
                {
                    var certUri = new Uri(uri, $"/mgnt/roots/0");
                    var certData = await Http.Value.GetByteArrayAsync(certUri);
                    TestCertificates.Add(certData);
                }
                catch
                {
                }

                return _stagingServerV2 = uri;
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        }

        throw new AggregateException("No staging server available.", exceptions);
    }

    public static async Task DeployDns01(string algo, Dictionary<string, string> tokens)
    {
        using var resp = await Http.Value.PutAsync($"http://certes-ci.dymetis.com/dns-01/{algo}",
            new StringContent(JsonConvert.SerializeObject(tokens), Encoding.UTF8, "application/json"));

        var respJson = await resp.Content.ReadAsStringAsync();
    }

    public static async Task<IOrderContext> AuthorizeHttp(AcmeContext ctx, IList<string> hosts)
    {
        for (var i = 0; i < 10; ++i)
        {
            var orderCtx = await ctx.NewOrder(hosts);
            var order = await orderCtx.Resource();
            Assert.NotNull(order);
            Assert.Equal(hosts.Count, order.Authorizations?.Count);
            Assert.True(OrderStatus.Pending == order.Status || OrderStatus.Ready == order.Status ||
                OrderStatus.Processing == order.Status);

            var authrizations = await orderCtx.Authorizations();

            foreach (var authz in authrizations)
            {
                var a = await authz.Resource();
                if (a.Status == AuthorizationStatus.Pending)
                {
                    var httpChallenge = await authz.Http();
                    await httpChallenge.Validate();
                }
            }

            while (true)
            {
                await Task.Delay(100);

                var statuses = new List<AuthorizationStatus>();
                foreach (var authz in authrizations)
                {
                    var a = await authz.Resource();
                    statuses.Add(a?.Status ?? AuthorizationStatus.Pending);
                }

                if (statuses.All(s => s == AuthorizationStatus.Valid))
                {
                    return orderCtx;
                }


                if (statuses.Any(s => s == AuthorizationStatus.Invalid))
                {
                    break;
                }
            }
        }

        Assert.Fail("Authorization failed.");
        return null;
    }
}