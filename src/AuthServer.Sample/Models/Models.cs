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
