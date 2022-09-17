namespace OpenCertServer.Acme.Server.Controllers
{
    using Filters;
    using Microsoft.AspNetCore.Mvc;

    [ApiController]
    [AddNextNonce]
    public sealed class NonceController : ControllerBase
    {
        [Route("/new-nonce", Name = "NewNonce")]
        [HttpHead]
        public ActionResult GetNewNonceHead()
        {
            return Ok();
        }

        [Route("/new-nonce", Name = "NewNonce")]
        [HttpGet]
        public ActionResult GetNewNonce()
        {
            return NoContent();
        }
    }
}
