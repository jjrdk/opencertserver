namespace OpenCertServer.Acme.Server.ModelBinding
{
    using Abstractions.HttpModel.Requests;
    using Abstractions.RequestServices;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc.ModelBinding;

    public sealed class AcmePayloadBinder<TPayload> : IModelBinder
    {
        private readonly IAcmeRequestProvider _requestProvider;

        public AcmePayloadBinder(IAcmeRequestProvider requestProvider)
        {
            _requestProvider = requestProvider;
        }

        public Task BindModelAsync(ModelBindingContext bindingContext)
        {
            if (bindingContext is null)
            {
                throw new ArgumentNullException(nameof(bindingContext));
            }

            var acmePayload = new AcmePayload<TPayload>(_requestProvider.GetPayload<TPayload>() ?? throw new BadHttpRequestException("Invalid content"));
            bindingContext.Result = ModelBindingResult.Success(acmePayload);

            return Task.CompletedTask;
        }
    }
}
