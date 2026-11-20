namespace OpenCertServer.Acme.Abstractions.HttpModel;

/// <summary>Lists the URLs of orders belonging to an ACME account.</summary>
public sealed record AccountOrders(IReadOnlyList<Uri> Orders);
