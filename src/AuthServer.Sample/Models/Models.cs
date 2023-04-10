namespace AuthServer.Sample.Models;

internal record AuthUser
{
    public string Id { get; set; }
    public string UserId { get; set; }
    public string Name { get; set; }
    public string Email { get; set; }
    public string FamilyName { get; set; }
    public string GivenName { get; set; }

    public string ClientId { get; set; }
    public string AppId { get; set; }
    public string Nonce { get; set; }
    public string[] Roles { get; set; }

}



public record class AuthRequestContext
{
    public string IPAddress { get; internal set; }
    public string Path { get; internal set; }
    public Guid TenantId { get; internal set; }
    public bool HasTenantId { get; internal set; }
    public float Version { get; internal set; }
    public bool HasVersion { get; internal set; }
    public string SiteName { get; internal set; }
    public string Issuer { get; internal set; }
    public DateTimeOffset RequestTime { get; internal set; } = DateTimeOffset.UtcNow;

}