using AuthServer.Sample.Extentions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using static AuthServer.Sample.Extentions.HttpContextExtensions;

namespace AuthServer.Sample.Services;

public class ResourceReader
{
    private readonly Assembly _assembly;
    public ResourceReader()
    {
        _assembly = Assembly.GetExecutingAssembly();
    }

    public string GetStringFromResource(string resourceName)
    {
        using Stream stream = _assembly.GetManifestResourceStream(resourceName);
        using StreamReader reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}

public class WellKnownOpenidConfiguration
{
    //"/.well-known/openid-configuration"
    public const string ConstV1Url = "/{tenantId}/.well-known/openid-configuration";
    public const string ConstV2Url = "/{tenantId}/v2.0/.well-known/openid-configuration";
    private const string ConstV1ConfigresourceName = "AuthServer.Sample.Resources.openid-configuration.json";
    private const string ConstV2ConfigresourceName = "AuthServer.Sample.Resources.V2.openid-configuration.json";

    private readonly ResourceReader _resourceReader;

    public WellKnownOpenidConfiguration(ResourceReader resourceReader)
    {
        _resourceReader = resourceReader;
    }

    public string GetV1(string endpoint, string tenantId)
    {
        return GetResourceText(ConstV1ConfigresourceName, endpoint, tenantId);
    }

    public string GetV2(string endpoint, string tenantId)
    {
        return GetResourceText(ConstV2ConfigresourceName, endpoint, tenantId);
    }

    private string GetResourceText(string resourceName, string endpoint, string tenantId)
    {
        if (string.IsNullOrEmpty(resourceName))
        {
            throw new ArgumentException($"'{nameof(resourceName)}' cannot be null or empty.", nameof(resourceName));
        }

        if (string.IsNullOrEmpty(endpoint))
        {
            throw new ArgumentException($"'{nameof(endpoint)}' cannot be null or empty.", nameof(endpoint));
        }

        if (string.IsNullOrEmpty(tenantId))
        {
            throw new ArgumentException($"'{nameof(tenantId)}' cannot be null or empty.", nameof(tenantId));
        }
        return _resourceReader.GetStringFromResource(resourceName)
            .Replace("__AUTH_ENDPOINT__", endpoint)
            .Replace("__AUTH_UID__", tenantId);
    }
}


public class ClientDataProvider
{
    public ClientDataProvider() 
    {
        
    }

    public virtual bool ValidateClient(string clientId)
    {
        var list = new List<string>()
        {
            "00000000-0000-0000-0000-000000000001",
            "00000001-0000-0000-a000-000000000001",
            "00000002-0000-0000-b000-000000000001"
        };
        return list.Any(x => x == clientId);
    }

    public virtual bool ValidateApp(string appId)
    {
        var list = new List<string>()
        {
            "00000000-0000-0000-0000-000000000002",
            "00000001-0000-0000-a000-000000000002",
            "00000002-0000-0000-b000-000000000002"
        };
        return list.Any(x => x == appId);
    }
    public virtual StoredUser ValidateSecret(string clientId, string clientSecret)
    {
        return new StoredUser
        {
            Id = "10000000-0000-0000-0000-000000000001"
        };
    }

    public virtual StoredUser ValidateUserPassword(string clientId, string username, string password)
    {
        return new StoredUser
        {
            Id = "10000000-0000-0000-0000-000000000002",
            Name="Test",
            Email="test@test.com",
            UserName="Test"
        };
    }
    public class StoredUser
    {
        public string Id { get; set; }
        public string UserName { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string GivenName { get; set; }
        public string SurName { get; set; }
        public string[] Roles { get; set; }
    }
}

public class OAuth2Token
{
    //"/oauth2/token"
    public const string ConstV1Url = "/{tenantId}/oauth2/token";
    public const string ConstV2Url = "/{tenantId}/oauth2/v2.0/token";

    private readonly IJwtUtils _jwtUtils;
    private readonly ClientDataProvider clientDataProvider;

    delegate Claim claimBuilder(string name, AuthRequestContext request, AuthUser user);

    private static readonly Dictionary<string, claimBuilder> _claimBuilders = new()
    {
        {"sub", (name, req, user)=> { return new Claim(name, user.UserId??user.Id); } },
        {"oid", (name, req, user)=> { return new Claim(name, user.Id); } },
        {"name", (name, req, user)=> { return new Claim(name, user.Name); } },
        {"family_name", (name, req, user)=> { return new Claim(name, user.FamilyName); } },
        {"given_name", (name, req, user)=> { return new Claim(name, user.GivenName); } },
        {"email", (name, req, user)=> { return new Claim(name, user.Email); } },
        {"unique_name", (name, req, user)=> { return new Claim(name, user.Email); } },
        {"preferred_username", (name, req, user)=> { return new Claim(name, user.Email); } },
        {"nonce", (name, req, user)=> { return new Claim(name, user.Nonce); } },
        //{"roles", (name, req, user)=> { return new Claim(name, user.Roles); } },
        {"appid", (name, req, user)=> { return new Claim(name, user.AppId ?? user.ClientId); } },
        {"aud", (name, req, user)=> { return new Claim(name, user.AppId ?? user.ClientId); } },

        {"tid", (name, req, user)=> { return new Claim(name, req.TenantId.ToString()); } },
        {"ver", (name, req, user)=> { return new Claim(name, req.Version.ToString("F1")); } },
        //{"iss", (name, req, user)=> { return new Claim(name, req.Issuer); } },
        {"idp", (name, req, user)=> { return new Claim(name, req.Issuer); } },
    };

    internal IEnumerable<Claim> BuildClaims(string[] includeClaims, AuthRequestContext request, AuthUser user)
    {
        if (includeClaims?.Length > 0)
        {
            var claims = includeClaims
                .Where(x => _claimBuilders.ContainsKey(x))
                .Select(x => _claimBuilders[x](x, request, user))
                .Where(x => !string.IsNullOrEmpty(x.Value))
                .ToList();

            if (includeClaims.Contains("roles") && user.Roles?.Length > 0)
            {
                claims.AddRange(user.Roles.Select(x => new Claim("roles", x))); 
            }

            return claims;
        }

        return new List<Claim>();
    }

    public OAuth2Token(IJwtUtils jwtUtils, ClientDataProvider clientDataProvider)
    {
        _jwtUtils = jwtUtils;
        this.clientDataProvider = clientDataProvider;
    }

    public string GetResponse(OAuthTokenRequest tokenRequest, AuthRequestContext requestCtx)
    {
        var claimsToInclude= new string[]{ "aud", "iss", "idp", "oid", "sub", "tid", "ver" };
        var user = clientDataProvider.ValidateSecret(tokenRequest.client_id, tokenRequest.client_secret);
        var authUser = new AuthUser
        {
            AppId= tokenRequest.client_id,
            Id = user.Id,
            UserId = user.Id,
            Email = user.Email,
            Name = user.Name,
            ClientId = tokenRequest.client_id,
        };
        var claims = BuildClaims(claimsToInclude, requestCtx, authUser);
        ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims);
        return _jwtUtils.GenerateToken(claimsIdentity, requestCtx);
    }

}
public class OAuthTokenRequest
{
    public static class GrantType
    {
        public const string password = "password";
        public const string client_credentials = "client_credentials";
    }
    public static class ResponseType
    {
        public const string id_token = "id_token";
        public const string code = "code";
        public const string token = "token";
        public const string access_token = "access_token";
    }
    public static class ResponseMode
    {
        public const string query = "query";
        public const string fragment = "fragment";
        public const string form_post = "form_post";
    }
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
    public string response_type { get; set; } //code id_token
    public string response_mode { get; set; }//query,fragment,form_post
    public string state { get; set; }
    public string nonce { get; set; }
    public string prompt { get; set; }
    public string login_hint { get; set; }
    public string code_challenge { get; set; }
    public string code_challenge_method { get; set; }
}

public abstract class OAuthTokenResponse
{
    public string code { get; set; }
    public string state { get; set; }
    public string token_type { get; set; } = "Bearer";
    public string expires_in { get; set; }
    public string ext_expires_in { get; set; }
    public string expires_on { get; set; }
    public string not_before { get; set; }

    public string scope { get; set; }
    public string id_token { get; set; }
    public string resource { get; set; } = "00000002-0000-0000-c000-000000000000";
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
    public static class Errors
    {
        public const string invalid_request = "invalid_request";
        public const string unauthorized_client = "unauthorized_client";
        public const string access_denied = "access_denied";
        public const string unsupported_response_type = "unsupported_response_type";
        public const string server_error = "server_error";
        public const string temporarily_unavailable = "temporarily_unavailable";
        public const string invalid_resource = "invalid_resource";
        public const string invalid_grant = "invalid_grant";
        public const string invalid_scope = "invalid_scope";
        public const string invalid_token = "invalid_token";
        public const string invalid_client = "invalid_client";
        public const string user_authentication_required = "user_authentication_required";
    }
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

public class OAuth2Authorize
{
    //"/oauth2/authorize"
    public const string ConstV1Url = "/{tenantId}/oauth2/authorize";
    public const string ConstV2Url = "/{tenantId}/oauth2/v2.0/authorize";
}


///https://jasonwatmore.com/post/2021/06/02/net-5-create-and-validate-jwt-tokens-use-custom-jwt-middleware

public class AppSettings
{
    public string SecretKey { get; set; }
}

public interface IJwtUtils
{
    public string GenerateToken(ClaimsIdentity claimsIdentity, AuthRequestContext requestContext,
        DateTime? issuedAt = null, DateTime? notBefore = null, DateTime? expires = null);
    public bool ValidateToken(string token, AuthRequestContext requestContext);
}

public class JwtUtils : IJwtUtils
{
    private readonly AppSettings _appSettings;

    public JwtUtils(IOptions<AppSettings> appSettings)
    {
        _appSettings = appSettings.Value;
    }

    public string GenerateToken(ClaimsIdentity claimsIdentity, AuthRequestContext requestContext,
        DateTime? issuedAt = null, DateTime? notBefore = null , DateTime? expires = null)
    {
        // generate token that is valid for 30 minutes
        var tokenHandler = new JwtSecurityTokenHandler();
        var secret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_appSettings.SecretKey));
        var signingCredentials = new SigningCredentials(secret, SecurityAlgorithms.HmacSha256);
        var encryptionCredentials = new EncryptingCredentials(secret, JwtConstants.DirectKeyUseAlg, SecurityAlgorithms.Aes256CbcHmacSha512);

        //using a certificate file
        //X509Certificate2 cert = new X509Certificate2("MySelfSignedCertificate.pfx", "password");
        //X509SecurityKey key = new X509SecurityKey(cert);
        //signingCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);

        var requestTime = requestContext.RequestTime;// DateTimeOffset.UtcNow;
        var nowUnix = requestTime.ToUnixTimeSeconds;
        var nowUtc = requestTime.UtcDateTime;

        var tokenDescriptor = new SecurityTokenDescriptor()
        {
            Issuer = requestContext.Issuer,
            //Audience = requestContext.Issuer,
            Subject = claimsIdentity,
            NotBefore = notBefore ?? requestTime.UtcDateTime,
            IssuedAt = issuedAt ?? requestTime.UtcDateTime,
            Expires = expires ?? requestTime.UtcDateTime.AddMinutes(30),
            //EncryptingCredentials = encryptionCredentials,
            SigningCredentials = signingCredentials
        };
        var tokenOptions = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);
        return tokenHandler.WriteToken(tokenOptions);
    }

    public bool ValidateToken(string token, AuthRequestContext requestContext)
    {
        if (token == null)
            return false;

        var tokenHandler = new JwtSecurityTokenHandler();
        var secret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_appSettings.SecretKey));
        try
        {
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidIssuer = requestContext.Issuer,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,
                RequireExpirationTime = true,
                ValidateIssuer = true,
                //ValidAudience = requestContext.Issuer,
                //ValidateAudience = true,
                IssuerSigningKey = secret,
                TokenDecryptionKey = secret,
                // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

            var jwtToken = (JwtSecurityToken)validatedToken;
            //var userId = int.Parse(jwtToken.Claims.First(x => x.Type == "id").Value);

            // return user id from JWT token if validation successful
            return true;
        }
        catch
        {
            // return null if validation fails
            return false;
        }
    }
}

public static class StreamExtentions
{
    public static Stream GenerateStreamFromString(string s)
    {
        var stream = new MemoryStream();
        var writer = new StreamWriter(stream);
        writer.Write(s);
        writer.Flush();
        stream.Position = 0;
        return stream;
    }

    public static Stream GenerateStreamFromStringBuilder(StringBuilder s)
    {
        var stream = new MemoryStream();
        var writer = new StreamWriter(stream);
        writer.Write(s);
        writer.Flush();
        stream.Position = 0;
        return stream;
    }
}


internal class AuthUser
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