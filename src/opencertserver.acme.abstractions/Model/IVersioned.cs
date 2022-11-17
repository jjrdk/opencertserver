namespace OpenCertServer.Acme.Abstractions.Model;

public interface IVersioned
{
    long Version { get; set; }
}