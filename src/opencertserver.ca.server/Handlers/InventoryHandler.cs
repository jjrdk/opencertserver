using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Ca;

namespace opencertserver.ca.server.Handlers;

public static class InventoryHandler
{
    public static async Task Handle(HttpContext context)
    {
        var store = context.RequestServices.GetRequiredService<IStoreCertificates>();
        var page = context.Request.Query.ContainsKey("page")
            ? int.TryParse(context.Request.Query["page"], out var p) ? p : 0
            : 0;
        var inventory = store.GetInventory(page);
        context.Response.ContentType = "application/json";
        await JsonSerializer.SerializeAsync(context.Response.Body, inventory,
            CaServerSerializerContext.Default.CertificateItemArray);
        await context.Response.Body.FlushAsync();
    }
}
