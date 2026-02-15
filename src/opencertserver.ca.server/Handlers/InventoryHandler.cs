namespace OpenCertServer.Ca.Server.Handlers;

using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Ca;

public static class InventoryHandler
{
    public static async Task Handle(HttpContext context)
    {
        var store = context.RequestServices.GetRequiredService<IStoreCertificates>();
        var page = context.Request.Query.ContainsKey("page")
            ? int.TryParse(context.Request.Query["page"], out var p) ? p : 0
            : 0;
        var inventory = await store.GetInventory(page).ToArrayAsync();
        context.Response.ContentType = "application/json";
        await JsonSerializer.SerializeAsync(context.Response.Body, inventory,
            CaServerSerializerContext.Default.CertificateItemInfoArray);
        await context.Response.Body.FlushAsync();
    }
}
