using System.Reflection;

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

    public OAuth2Token(ResourceReader resourceReader)
    {
        _resourceReader = resourceReader;
    }

    public string GetResponse(OAuthTokenRequest tokenRequest)
    {
        return GetResourceText(ConstV1ConfigresourceName, "", "");
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
}

public class OAuth2Authorize
{
    //"/oauth2/authorize"
    public const string ConstV1Url = "/{tenantId}/oauth2/authorize";
    public const string ConstV2Url = "/{tenantId}/oauth2/v2.0/authorize";
}
