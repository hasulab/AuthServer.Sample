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
    public const string ConstV1Url = "/.well-known/openid-configuration";
    public const string ConstV2Url = "/v2.0/.well-known/openid-configuration";
    private const string ConstV1ConfigresourceName = "AuthServer.Sample.Resources.openid-configuration.json";
    private const string ConstV2ConfigresourceName = "AuthServer.Sample.Resources.V2.openid-configuration.json";

    private readonly ResourceReader _resourceReader;

    public WellKnownOpenidConfiguration(ResourceReader resourceReader)
    {
        _resourceReader = resourceReader;
    }

    public string GetV1(string siteName, string appId)
    {
        return _resourceReader.GetStringFromResource(ConstV1ConfigresourceName)
            .Replace("__AUTH_ENDPOINT__", siteName)
            .Replace("__AUTH_UID__", appId);
    }

    public string GetV2(string siteName, string appId)
    {
        return _resourceReader.GetStringFromResource(ConstV2ConfigresourceName)
            .Replace("__AUTH_ENDPOINT__", siteName)
            .Replace("__AUTH_UID__", appId);
    }

}
