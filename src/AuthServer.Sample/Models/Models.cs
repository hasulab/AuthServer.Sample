using System.Text.Json.Serialization;

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

public class OAuthTokenRequest
{
    public string grant_type { get; set; } = GrantType.client_credentials;

    //client_id is AppId in  jwt
    public string client_id { get; set; }
    public string client_secret { get; set; }
    public string username { get; set; }
    public string password { get; set; }
    public string client_assertion { get; set; }
    public string code_verifier { get; set; }
    public string redirect_uri { get; set; }
    public string code { get; set; }
    public string scope { get; set; }
    public string tenant { get; set; }
    public string response_type { get; set; } //code id_token access_token
    public string response_mode { get; set; }//query,fragment,form_post
    public string state { get; set; }
    public string nonce { get; set; }
    public string prompt { get; set; }
    public string login_hint { get; set; }
    public string code_challenge { get; set; }
    public string code_challenge_method { get; set; }
}

public class OAuthTokenResponse
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string code { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string state { get; set; }

    public string token_type { get; set; } = TokenType.Bearer;

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string expires_in { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string ext_expires_in { get; set; }


    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string expires_on { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string not_before { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string scope { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string id_token { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string resource { get; set; } = "00000002-0000-0000-c000-000000000000";

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string access_token { get; set; }
    /*
     "token_type": "Bearer",
  "expires_in": "3599",
  "ext_expires_in": "3599",
  "expires_on": "1680540490",
  "not_before": "1680536590",
  "resource": "00000002-0000-0000-c000-000000000000",*/

}


//GET http://localhost?error=access_denied&error_description=the+user+canceled+the+authentication
public class OAuthErrorResponse
{

    public string error_description { get; set; }
    public string error { get; set; }
    public int[] error_codes { get; set; }
    public string correlation_id { get; set; }
    public string trace_id { get; set; }

    //invalid_request,unauthorized_client,access_denied
    //,unsupported_response_type,server_error
    //temporarily_unavailable,invalid_resource,
    //login_required,interaction_required
}
