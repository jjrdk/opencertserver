namespace OpenCertServer.Ca.Server.Handlers;

using System.Diagnostics;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Ca.Utils.Ca;

public static class InventoryHandler
{
    public static async Task Handle(HttpContext context)
    {
        CaInstruments.InventoryRequests.Add(1);
        var sw = Stopwatch.GetTimestamp();
        using var activity = CaInstruments.ActivitySource.StartActivity(ActivityNames.Inventory);
        try
        {
            var store = context.RequestServices.GetRequiredService<IStoreCertificates>();
            var page = context.Request.Query.ContainsKey("page")
                ? int.TryParse(context.Request.Query["page"], out var p) ? p : 0
                : 0;
            var inventory = await store.GetInventory(page).ToArrayAsync().ConfigureAwait(false);
            context.Response.ContentType = "application/json";
            await JsonSerializer.SerializeAsync(context.Response.Body, inventory,
                CaServerSerializerContext.Default.CertificateItemInfoArray).ConfigureAwait(false);
            await context.Response.Body.FlushAsync().ConfigureAwait(false);
            CaInstruments.InventorySuccesses.Add(1);
            activity?.SetStatus(ActivityStatusCode.Ok);
        }
        catch (Exception ex)
        {
            CaInstruments.InventoryFailures.Add(1);
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            throw;
        }
        finally
        {
            CaInstruments.InventoryDuration.Record(Stopwatch.GetElapsedTime(sw).TotalSeconds);
        }
    }

}
