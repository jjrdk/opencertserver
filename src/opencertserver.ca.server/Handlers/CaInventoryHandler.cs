// This file is licensed under the terms in the README file of OpenCertServer.
// This file is part of OpenCertServer.
//
// CA server — inventory endpoint.
//
// Serves the certificate inventory over GET /ca/inventory — a paginated, CRL-style listing of the
// metadata for every certificate the CA has issued. This is the public "who have I issued?" view used to
// prove a certificate was (and is not) in the issued-certificate set.
namespace OpenCertServer.Ca.Server.Handlers;

using System.Diagnostics;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Ca.Utils.Ca;

/// <summary>
/// Handles the certificate inventory request.
/// </summary>
public static class CaInventoryHandler
{
    public static async Task Handle(HttpContext context)
    {
        var page = int.TryParse(context.Request.Query["page"], out var p) ? p : 0;
        var pageSize = int.TryParse(context.Request.Query["pageSize"], out var s) ? s : 100;

        CaInstruments.InventoryRequests.Add(1);
        var sw = Stopwatch.GetTimestamp();
        using var activity = CaInstruments.ActivitySource.StartActivity(ActivityNames.Inventory);
        try
        {
            var store = context.RequestServices.GetService<IStoreCertificates>()
                ?? throw new InvalidOperationException(
                    "No certificate store is registered; the inventory cannot be enumerated.");

            var items = new List<CertificateItemInfo>();
            await foreach (var item in store.GetInventory(page, pageSize, context.RequestAborted))
                items.Add(item);

            context.Response.ContentType = "application/json";
            // Write the payload directly with Utf8JsonWriter rather than reflecting over an anonymous
            // type: this keeps the handler trimming- and AOT-safe.
            using var writer = new Utf8JsonWriter(context.Response.Body);
            writer.WriteStartObject();
            writer.WriteNumber("page", page);
            writer.WriteNumber("pageSize", pageSize);
            writer.WriteNumber("count", items.Count);
            writer.WriteStartArray("items");
            foreach (var item in items)
            {
                writer.WriteStartObject();
                writer.WriteString("serialNumber", item.SerialNumber);
                writer.WriteString("distinguishedName", item.DistinguishedName);
                writer.WriteString("issuer", item.Issuer);
                writer.WriteString("notBefore", item.NotBefore);
                writer.WriteString("notAfter", item.NotAfter);
                writer.WriteBoolean("isRevoked", item.IsRevoked);
                if (item.RevocationReason is { } reason)
                    writer.WriteString("revocationReason", reason.ToString());
                if (item.RevocationDate is { } revocationDate)
                    writer.WriteString("revocationDate", revocationDate);
                writer.WriteString("thumbprint", item.Thumbprint);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
            await writer.FlushAsync(context.RequestAborted).ConfigureAwait(false);

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
            var elapsed = Stopwatch.GetElapsedTime(sw).TotalSeconds;
            CaInstruments.InventoryDuration.Record(elapsed);
        }
    }
}
