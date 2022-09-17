namespace OpenCertServer.Acme.Abstractions.HttpModel.Requests
{
    public sealed class AcmePayload<TPayload>
    {
        public AcmePayload(TPayload value)
        {
            Value = value;
        }

        public TPayload Value { get; }
    }
}
