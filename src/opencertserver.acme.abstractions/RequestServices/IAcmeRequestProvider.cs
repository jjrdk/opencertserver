namespace OpenCertServer.Acme.Abstractions.RequestServices
{
    using HttpModel.Requests;

    public interface IAcmeRequestProvider
    {
        void Initialize(AcmeRawPostRequest rawPostRequest);

        AcmeRawPostRequest GetRequest();

        AcmeHeader GetHeader();
        
        TPayload? GetPayload<TPayload>();
    }
}
