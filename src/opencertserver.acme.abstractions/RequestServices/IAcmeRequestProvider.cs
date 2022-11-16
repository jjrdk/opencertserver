namespace OpenCertServer.Acme.Abstractions.RequestServices
{
    using System.Diagnostics.CodeAnalysis;
    using HttpModel.Requests;

    public interface IAcmeRequestProvider
    {
        [RequiresUnreferencedCode($"Uses {nameof(AcmeRawPostRequest)}")]
        void Initialize(AcmeRawPostRequest rawPostRequest);

        AcmeRawPostRequest GetRequest();

        AcmeHeader GetHeader();
        
        [RequiresUnreferencedCode("Uses unknown types")]
        TPayload? GetPayload<TPayload>();
    }
}
