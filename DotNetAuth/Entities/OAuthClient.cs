namespace DotNetAuth.Entities;

public class OAuthClient
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string Name { get; set; }
    public string ClientId { get; set; }
    public string ClientSecret { get; set; }
    public string[] AllowedScopes { get; set; }
}