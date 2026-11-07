namespace OpenCertServer.Scep.Server;

/// <summary>Centralised activity names for SCEP request traces.</summary>
internal static class ActivityNames
{
    internal const string GetCaCaps = "opencertserver.scep.getcacaps";
    internal const string GetCaCert = "opencertserver.scep.getcacert";
    internal const string PkiOperation = "opencertserver.scep.pkioperation";
    internal const string UnsupportedOperation = "opencertserver.scep.unsupported";

    internal static string For(ScepInstruments.Operation operation) => operation switch
    {
        ScepInstruments.Operation.GetCaCaps => GetCaCaps,
        ScepInstruments.Operation.GetCaCert => GetCaCert,
        ScepInstruments.Operation.PkiOperation => PkiOperation,
        _ => UnsupportedOperation
    };
}
