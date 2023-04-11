using AuthServer.Sample.Exceptions;
using AuthServer.Sample.Extentions;
using AuthServer.Sample.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using static AuthServer.Sample.Constants.Auth;

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
    private readonly ResourceReader _resourceReader;

    public WellKnownOpenidConfiguration(ResourceReader resourceReader)
    {
        _resourceReader = resourceReader;
    }

    public string GetV1(string endpoint, string tenantId)
    {
        return GetResourceText(WellKnownConfig.V1ConfigresourceName, endpoint, tenantId);
    }

    public string GetV2(string endpoint, string tenantId)
    {
        return GetResourceText(WellKnownConfig.V2ConfigresourceName, endpoint, tenantId);
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
    
    public virtual string[] GetResponseTypes(Guid tenantId, OAuthTokenRequest tokenRequest)
    {
        var response_type = string.Empty;
        switch (tokenRequest.grant_type)
        {
            case GrantType.client_credentials:
                response_type = tokenRequest.response_type ?? ResponseType.access_token;
                break;
            case GrantType.password:
                response_type = tokenRequest.response_type ?? ResponseType.id_token;
                break;
        }

        return response_type.Split('+',' ');
    }

    public virtual StoredUser ValidateSecret(Guid tenantId, OAuthTokenRequest tokenRequest)
    {
        return new StoredUser
        {
            Id = "10000000-0000-0000-0000-000000000001"
        };
    }

    public virtual StoredUser ValidateUserPassword(Guid tenantId, OAuthTokenRequest tokenRequest)
    {
        return new StoredUser
        {
            Id = "10000000-0000-0000-0000-000000000002",
            Name="Test",
            Email="test@test.com",
            UserName="Test",
            Roles= new string[] { "Admin", "Dev", "QA" }
        };
    }

    public class StoredUser
    {
        public string Id { get; set; }
        public string UserName { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string FirstName { get; set; }
        public string SurName { get; set; }
        public string[] Roles { get; set; }
    }
}

public class OAuth2Token
{
    private readonly IJwtUtils _jwtUtils;
    private readonly ClientDataProvider clientDataProvider;

    delegate ClaimRecord claimBuilder(string name, AuthRequestContext request, AuthUser user);

    private static readonly Dictionary<string, claimBuilder> _claimBuilders = new()
    {
        {Claims.sub, (name, req, user)=> { return new ClaimRecord(name, user.UserId??user.Id); } },
        {Claims.oid, (name, req, user)=> { return new ClaimRecord(name, user.Id); } },
        {Claims.name, (name, req, user)=> { return new ClaimRecord(name, user.Name); } },
        {Claims.family_name, (name, req, user)=> { return new ClaimRecord(name, user.FamilyName); } },
        {Claims.given_name, (name, req, user)=> { return new ClaimRecord(name, user.GivenName); } },
        {Claims.email, (name, req, user)=> { return new ClaimRecord(name, user.Email); } },
        {Claims.unique_name, (name, req, user)=> { return new ClaimRecord(name, user.Email); } },
        {Claims.preferred_username, (name, req, user)=> { return new ClaimRecord(name, user.Email); } },
        {Claims.nonce, (name, req, user)=> { return new ClaimRecord(name, user.Nonce); } },
        //{Claims.roles, (name, req, user)=> { return new ClaimRecord(name, user.Roles); } },
        {Claims.appid, (name, req, user)=> { return new ClaimRecord(name, user.AppId ?? user.ClientId); } },
        {Claims.aud, (name, req, user)=> { return new ClaimRecord(name, user.AppId ?? user.ClientId); } },

        {Claims.tid, (name, req, user)=> { return new ClaimRecord(name, req.TenantId.ToString()); } },
        {Claims.ver, (name, req, user)=> { return new ClaimRecord(name, req.Version.ToString("F1")); } },
        //{Claims.iss, (name, req, user)=> { return new ClaimRecord(name, req.Issuer); } },
        {Claims.idp, (name, req, user)=> { return new ClaimRecord(name, req.Issuer); } },
    };

    record ClaimRecord
    {
        public ClaimRecord(string key, string value)
        {
            Key = key;
            Value = value;
        }
        public string Key { get;  }
        public string Value { get;}
    }

    internal static IEnumerable<Claim> BuildClaims(string[] includeClaims, AuthRequestContext request, AuthUser user)
    {
        if (includeClaims?.Length > 0)
        {
            var claims = includeClaims
                .Where(x => _claimBuilders.ContainsKey(x))
                .Select(x => _claimBuilders[x](x, request, user))
                .Where(x => !string.IsNullOrEmpty(x.Value))
            .ToList();

            if (includeClaims.Contains(Claims.roles) && user.Roles?.Length > 0)
            {
                claims.AddRange(user.Roles.Select(x => new ClaimRecord(Claims.roles, x))); 
            }

            return claims.Select(x => new Claim(x.Key, x.Value)).ToList();
        }

        return new List<Claim>();
    }

    public OAuth2Token(IJwtUtils jwtUtils, ClientDataProvider clientDataProvider)
    {
        _jwtUtils = jwtUtils;
        this.clientDataProvider = clientDataProvider;
    }

    delegate void UpdateToken(IJwtUtils jwtUtils, OAuthTokenResponse response, AuthUser authUser, AuthRequestContext requestCtx);

    private readonly Dictionary<string, UpdateToken> _tokenUpdaters = new()
    {
        { ResponseType.token,(jwtUtils, res,user, ctx)=> { UpdateAccessToken(jwtUtils, res,user,ctx); } },
        { ResponseType.access_token,(jwtUtils, res,user, ctx)=> { UpdateAccessToken(jwtUtils, res,user,ctx); } },
        { ResponseType.id_token,(jwtUtils, res,user, ctx)=> { UpdateIdToken(jwtUtils, res,user,ctx); } }
    };

    public OAuthTokenResponse GenerateResponse(OAuthTokenRequest tokenRequest, AuthRequestContext requestCtx)
    {
        AuthUser authUser;
        if (tokenRequest.grant_type == GrantType.client_credentials)
        {
            authUser = BuildAccessToken(tokenRequest, requestCtx);
        }
        else if (tokenRequest.grant_type == GrantType.password)
        {
            authUser = BuildIdToken(tokenRequest, requestCtx);
        }
        else
        {
            throw new AuthException
            {
                OAuthError = new OAuthErrorResponse
                {
                    error= Errors.invalid_grant,
                    error_description= $"Invalid {tokenRequest.grant_type} grant_type"
                }
            };
        }

        var responseTypes = clientDataProvider.GetResponseTypes(requestCtx.TenantId ,tokenRequest);
        var tokenResponse = new OAuthTokenResponse();
        responseTypes
            .Where(x => _tokenUpdaters.ContainsKey(x))
            .ToList()
            .ForEach(x => _tokenUpdaters[x](_jwtUtils, tokenResponse, authUser, requestCtx));

        return tokenResponse;
    }

    private AuthUser BuildIdToken(OAuthTokenRequest tokenRequest, AuthRequestContext requestCtx)
    {
        var user = clientDataProvider.ValidateUserPassword(requestCtx.TenantId, tokenRequest);

        user.ThrowAuthExceptionIfNull(Errors.invalid_request, "Invalid username or password");

        return new AuthUser
        {
            AppId = tokenRequest.client_id,
            Id = user.Id,
            UserId = user.Id,
            Email = user.Email,
            Name = user.Name,
            FamilyName = user.SurName,
            GivenName = user.FirstName,
            Roles = user.Roles,
            ClientId = tokenRequest.client_id,
        };
    }

    private AuthUser BuildAccessToken(OAuthTokenRequest tokenRequest, AuthRequestContext requestCtx)
    {
        var user = clientDataProvider.ValidateSecret(requestCtx.TenantId, tokenRequest);

        user.ThrowAuthExceptionIfNull(Errors.invalid_request, "Invalid token or client id");

        return new AuthUser
        {
            AppId = tokenRequest.client_id,
            Id = user.Id,
            UserId = user.Id,
            ClientId = tokenRequest.client_id,
        };
    }

    static readonly string[] AccesskenClaims = new string[] {
        Claims.aud, Claims.iss, Claims.idp, Claims.oid, Claims.sub, Claims.tid, Claims.ver
    };

    private static void UpdateAccessToken(IJwtUtils jwtUtils, OAuthTokenResponse response, AuthUser authUser, AuthRequestContext requestCtx)
    {
        var claims = BuildClaims(AccesskenClaims, requestCtx, authUser);
        var claimsIdentity= new ClaimsIdentity(claims);
        response.access_token = jwtUtils.GenerateToken(claimsIdentity, requestCtx, out long expiresIn);
        if (response.expires_in == null)
        {
            response.expires_in = expiresIn.ToString();
            response.ext_expires_in = expiresIn.ToString();
        }
    }

    static readonly string[] IdTokenClaims = new string[]
    {
        Claims.aud, Claims.iss, Claims.iat, Claims.nbf, Claims.exp, Claims.aio, Claims.amr, Claims.rsa,
        Claims.name, Claims.email, Claims.family_name, Claims.given_name, Claims.idp, Claims.roles,
        Claims.ipaddr,Claims.nonce, Claims.oid, Claims.rh, Claims.sub, Claims.tid, Claims.unique_name, Claims.uti, Claims.ver
    };

    private static void UpdateIdToken(IJwtUtils jwtUtils, OAuthTokenResponse response, AuthUser authUser, AuthRequestContext requestCtx)
    {
        var claims = BuildClaims(IdTokenClaims, requestCtx, authUser);
        var claimsIdentity = new ClaimsIdentity(claims);
        response.id_token = jwtUtils.GenerateToken(claimsIdentity, requestCtx, out long expiresIn);
        if (response.expires_in != null)
        {
            response.expires_in = expiresIn.ToString();
            response.ext_expires_in = expiresIn.ToString();
        }
    }
}

public class OAuth2Authorize
{
}


///https://jasonwatmore.com/post/2021/06/02/net-5-create-and-validate-jwt-tokens-use-custom-jwt-middleware

public class AppSettings
{
    public string SecretKey { get; set; }
    public string CertificateFile { get; set; }
    public string CertificatePassword { get; set; }
}

public interface IJwtSigningService
{
    SecurityKey GetSecurityKey(Guid tenantId);
    SigningCredentials GetSigningCredentials(Guid tenantId);
    EncryptingCredentials GetEncryptingCredentials(Guid tenantId);
}

internal class JwtSigningService : IJwtSigningService
{
    private readonly AppSettings _appSettings;

    public JwtSigningService(IOptions<AppSettings> appSettings)
    {
        _appSettings = appSettings.Value;
    }

    public SecurityKey GetSecurityKey(Guid tenantId)
    {
        SecurityKey secret = null;
        if (_appSettings.CertificateFile != null && _appSettings.CertificatePassword != null )
        {
            var cert = new X509Certificate2(_appSettings.CertificateFile, _appSettings.CertificatePassword);
            secret = new X509SecurityKey(cert);
        }
        else if (_appSettings.SecretKey != null)
        {
            secret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_appSettings.SecretKey));
        }
        else
        {
            _appSettings.SecretKey.ThrowAuthExceptionIfNull(Errors.invalid_resource, "SecretKey or CertificateFile not configured");
        }
        return secret;
    }

    public EncryptingCredentials GetEncryptingCredentials(Guid tenantId)
    {
        var secret = GetSecurityKey(tenantId);
        var encryptionCredentials = new EncryptingCredentials(secret, JwtConstants.DirectKeyUseAlg, SecurityAlgorithms.Aes256CbcHmacSha512);
        return encryptionCredentials;
    }

    public SigningCredentials GetSigningCredentials(Guid tenantId)
    {
        var secret = GetSecurityKey(tenantId);
        var signingCredentials = new SigningCredentials(secret, SecurityAlgorithms.HmacSha256);

        //using a certificate file
        //X509Certificate2 cert = new X509Certificate2("MySelfSignedCertificate.pfx", "password");
        //X509SecurityKey key = new X509SecurityKey(cert);
        //signingCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);

        return signingCredentials;
    }

}

public interface IJwtUtils
{
    public string GenerateToken(ClaimsIdentity claimsIdentity, AuthRequestContext requestContext,
        out long expiresIn,
        DateTime? issuedAt = null, DateTime? notBefore = null, DateTime? expires = null, double defaultExpiryMinutes = 30);
    public bool ValidateToken(string token, AuthRequestContext requestContext);
}

public class JwtUtils : IJwtUtils
{
    private readonly IJwtSigningService _signingService;

    public JwtUtils(IJwtSigningService signingService)
    {
        _signingService = signingService;
    }

    public string GenerateToken(ClaimsIdentity claimsIdentity, AuthRequestContext requestContext,
        out long expiresIn, DateTime? issuedAt = null, DateTime? notBefore = null, DateTime? expires = null,
        double defaultExpiryMinutes = 30)
    {
        // generate token that is valid for 30 minutes
        var tokenHandler = new JwtSecurityTokenHandler();
        var signingCredentials = _signingService.GetSigningCredentials(requestContext.TenantId);

        var requestTime = requestContext.RequestTime;// DateTimeOffset.UtcNow;

        notBefore ??= requestTime.UtcDateTime;
        issuedAt ??= requestTime.UtcDateTime;
        expires ??= requestTime.UtcDateTime.AddMinutes(defaultExpiryMinutes);

        expiresIn = (long)(expires.Value - DateTime.UtcNow).TotalSeconds;

        var tokenDescriptor = new SecurityTokenDescriptor()
        {
            Issuer = requestContext.Issuer,
            //Audience = requestContext.Issuer,
            Subject = claimsIdentity,
            NotBefore = notBefore,
            IssuedAt = issuedAt,
            Expires = expires,
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

        var secret = _signingService.GetSecurityKey(requestContext.TenantId);
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
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




