namespace OpenCertServer.Acme.Server.Controllers
{
    using Filters;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;

    [ApiController]
    [AddNextNonce]
    public class NonceController : ControllerBase
    {
        [Route("/new-nonce", Name = "NewNonce")]
        [HttpGet, HttpHead]
        public ActionResult GetNewNonce()
        {
            if (HttpMethods.IsGet(HttpContext.Request.Method))
            {
                return NoContent();
            }
            else
            {
                return Ok();
            }
        }
    }
}
