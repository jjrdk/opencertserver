namespace OpenCertServer.Acme.AspNetClient.Persistence
{
	public record ChallengeDto(string Token, string Response, string[] Domains);
}
