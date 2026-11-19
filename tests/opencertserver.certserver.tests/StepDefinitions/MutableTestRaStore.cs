namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using OpenCertServer.Ca.Protocol;

internal sealed class MutableTestRaStore(RaBinding binding) : IStoreRas
{
    private RaBinding _binding = binding;

    public void SetBinding(RaBinding binding) => _binding = binding;

    public Task<RaBinding?> Find(string raId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<RaBinding?>(
            string.Equals(_binding.RaId, raId, StringComparison.Ordinal) ? _binding : null);
    }
}
