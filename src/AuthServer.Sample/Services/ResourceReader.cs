using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;

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

public class OAuth2Token
{
    //"/oauth2/token"
    public const string ConstV1Url = "/{tenantId}/oauth2/token";
    public const string ConstV2Url = "/{tenantId}/oauth2/v2.0/token";
    //oauth-token-access_token-response
    private const string ConstV1ConfigresourceName = "AuthServer.Sample.Resources.oauth-token-access_token-response.json";
    private const string ConstV2ConfigresourceName = "AuthServer.Sample.Resources.V2.openid-configuration.json";

    private readonly ResourceReader _resourceReader;
    private readonly IJwtUtils _jwtUtils;

    public OAuth2Token(ResourceReader resourceReader, IJwtUtils jwtUtils)
    {
        _resourceReader = resourceReader;
        _jwtUtils = jwtUtils;
    }

    public string GetResponse(OAuthTokenRequest tokenRequest)
    {
        ClaimsIdentity claimsIdentity = new ClaimsIdentity(new[] { new Claim("subject", "test" ) });
        return _jwtUtils.GenerateToken(claimsIdentity);
        //return GetResourceText(ConstV1ConfigresourceName, "", "");
    }

    private string GetResourceText(string resourceName, string endpoint, string tenantId)
    {
        return _resourceReader.GetStringFromResource(resourceName);
    }
}
public class OAuthTokenRequest
{
    public string grant_type { get; set; } = "client_credentials";
     public string client_id { get; set; }
    public string client_secret { get; set; }
    public string code_verifier { get; set; }
    public string redirect_uri { get; set; }
    public string code { get; set; }
    public string scope { get; set; }
    public string tenant { get; set; }
    public string response_type { get; set; } //code id_token
    public string response_mode { get; set; }//query,fragment,form_post
    public string nonce { get; set; }
    public string code_challenge { get; set; }
    public string code_challenge_method { get; set; }
}

public class OAuthTokenResponse
{
    public string code { get; set; }
    public string id_token { get; set; }
    public string state { get; set; }
}

//GET http://localhost?error=access_denied&error_description=the+user+canceled+the+authentication
public class OAuthErrorResponse
{
    public string error_description { get; set; }
    public string error { get; set; }
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
    public string GenerateToken(ClaimsIdentity claimsIdentity);
    public bool ValidateToken(string token);
}

public class JwtUtils : IJwtUtils
{
    private readonly AppSettings _appSettings;

    public JwtUtils(IOptions<AppSettings> appSettings)
    {
        _appSettings = appSettings.Value;
    }

    public string GenerateToken(ClaimsIdentity claimsIdentity)
    {
        // generate token that is valid for 7 days
        var tokenHandler = new JwtSecurityTokenHandler();
        var secret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_appSettings.SecretKey));
        var signingCredentials = new SigningCredentials(secret, SecurityAlgorithms.HmacSha256);
        var encryptionCredentials = new EncryptingCredentials(secret, JwtConstants.DirectKeyUseAlg, SecurityAlgorithms.Aes256CbcHmacSha512);

        //using a certificate file
        //X509Certificate2 cert = new X509Certificate2("MySelfSignedCertificate.pfx", "password");
        //X509SecurityKey key = new X509SecurityKey(cert);
        //signingCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);

        var nowDateTimeoffset = DateTimeOffset.UtcNow;
        var nowUnix = nowDateTimeoffset.ToUnixTimeSeconds;
        var nowUtc = nowDateTimeoffset.UtcDateTime;

        var tokenDescriptor = new SecurityTokenDescriptor()
        {
            Audience = "https://TestValidAudience",
            Issuer = "http://TestValidIssuer",
            Subject = claimsIdentity,
            NotBefore = nowUtc,
            IssuedAt = nowUtc,
            Expires = nowUtc.AddMinutes(10),
            //EncryptingCredentials = encryptionCredentials,
            SigningCredentials = signingCredentials
        };
        var tokenOptions = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);
        return tokenHandler.WriteToken(tokenOptions);
    }

    public bool ValidateToken(string token)
    {
        if (token == null)
            return false;

        var tokenHandler = new JwtSecurityTokenHandler();
        var secret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_appSettings.SecretKey));
        try
        {
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidIssuer = "TestValidIssuer",
                ValidAudience = "TestValidAudience",
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,
                RequireExpirationTime = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                IssuerSigningKey = secret,
                TokenDecryptionKey= secret,
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
public static class RequestExtentions
{
    public static async Task FormContentToJson(this HttpRequest request)
    {
        if (!request.HasFormContentType)
        {
            throw new Exception("Invalid ContentType");
        }
        StringBuilder stringBuilder = new("{");
        var formFields = await request.ReadFormAsync();
        var enumerator = formFields.GetEnumerator();
        var hasMore = enumerator.MoveNext();
        while (hasMore)
        {
            var field = enumerator.Current;
            stringBuilder.Append($"\"{field.Key}\":\"{field.Value}\"");
            hasMore = enumerator.MoveNext();
            if (hasMore)
            {
                stringBuilder.Append(',');
            }
        }
        stringBuilder.Append("}");
        request.ContentType = "application/json";
        request.Body = StreamExtentions.GenerateStreamFromStringBuilder(stringBuilder);
    }
}

