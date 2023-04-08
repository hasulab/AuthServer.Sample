using AuthServer.Sample.Services;
using System.Text.RegularExpressions;
using System.Text;

namespace AuthServer.Sample.Extentions;

public static class RequestExtentions
{
    public static async Task FormContentToJson(this HttpRequest request)
    {
        if (!request.HasFormContentType)
        {
            throw new Exception("Invalid ContentType");
        }
        var formFields = await request.ReadFormAsync();
        var enumerator = formFields.GetEnumerator();
        var hasMore = enumerator.MoveNext();

        StringBuilder stringBuilder = new("{");
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

public static class HttpContextExtensions
{
    const string versionRegEx = @"^v\d.\d$";
    public static void SetRequestContext(this HttpContext context)
    {
        var requestContext = context.Features.Get<AuthRequestContext>();
        if (requestContext == null)
        {
            var request = context.Request;
            var path = request.Path.Value ?? string.Empty;
            var pathSegments = path.Split('/');
            var hasTenantId = TryTenantId(pathSegments, out Guid tenantId);
            var hasVersion = TryVersion(pathSegments, out float version);

            var siteName = $"{request.Scheme}//{request.Host.ToUriComponent()}";
            var issuer = hasTenantId ? $"{siteName}/tenantId" : siteName;
            requestContext = new AuthRequestContext
            {
                IPAddress = context.Connection.RemoteIpAddress != null
                ? context.Connection.RemoteIpAddress.ToString()
                : string.Empty,
                Path = path,
                TenantId = tenantId,
                HasTenantId = hasTenantId,
                Version = version,
                HasVersion = hasVersion,
                SiteName = siteName,
                Issuer = issuer
            };
            context.Features.Set(requestContext);
        }

        static bool TryTenantId(string[] pathSegments, out Guid tenantId)
        {
            tenantId = Guid.Empty;
            return pathSegments.Length > 0
                ? Guid.TryParse(pathSegments[1], out tenantId)
                : false;
        }

        static bool TryVersion(string[] pathSegments, out float version)
        {
            var versionString = pathSegments.FirstOrDefault(x => Regex.IsMatch(x, versionRegEx)) ?? "v1.0";
            return float.TryParse(versionString.Replace("v", string.Empty), out version);
        }
    }

    public static AuthRequestContext? GetRequestContext(this HttpContext context)
    {
        return context.Features.Get<AuthRequestContext>();
    }
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