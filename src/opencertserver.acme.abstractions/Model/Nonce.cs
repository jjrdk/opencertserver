namespace OpenCertServer.Acme.Abstractions.Model
{
    using Exceptions;

    public class Nonce
    {
        private string? _token;

        private Nonce() { }

        public Nonce(string token)
        {
            Token = token;
        }

        public string Token
        {
            get { return _token ?? throw new NotInitializedException(); }
            private set { _token = value; }
        }
    }
}
