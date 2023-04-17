using AuthServer.Sample.Services;
using System.Text.RegularExpressions;
using System.Text;
using AuthServer.Sample.Models;
using AuthServer.Sample.Exceptions;
using Microsoft.AspNetCore.Http;
using System.Text.Json;
using static AuthServer.Sample.Constants.Auth;

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

    public static T QueryStringTo<T>(this HttpRequest request)
        where T:class, new()
    {
        if (!request.QueryString.HasValue)
        {
            return new T();
        }

        var queryString = request.QueryString.Value ?? string.Empty;

        var enumerator = queryString.ToDictionary().GetEnumerator();
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

        stringBuilder.Append('}');
        return JsonSerializer.Deserialize<T>(stringBuilder.ToString());        
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

            var siteName = $"{request.Scheme}://{request.Host.ToUriComponent()}";
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

    public static void SetTenantsContext(this HttpContext context)
    {
        if (context.GetTenantsContext() != null)
        {
            return;
        }

        var requestContext = context.Features.Get<AuthRequestContext>();
        if (requestContext != null && requestContext.HasTenantId)
        {
            var tenantSettings = GetTenantSettings(context, requestContext.TenantId);
            context.Features.Set(tenantSettings);
        }
    }

    private static TenantSettings GetTenantSettings(HttpContext context, Guid tenantId)
    {
        return context.RequestServices.GetService<ITenantsDataProvider>().GetTenantSettings(tenantId);
    }

    public static TenantSettings? GetTenantsContext(this HttpContext context)
    {
        return context.Features.Get<TenantSettings>();
    }

    static readonly List<string> ValidAuthPaths = new()
    {
        WellKnownConfig.V1Url,
        WellKnownConfig.V2Url,
        Token.V1Url,
        Token.V2Url,
        Authorize.V1Url,
        Authorize.V2Url,
        Login.V1Url,
        Login.V2Url,
        Logout.V1Url,
        Logout.V2Url
    };

    public static bool HasValidAuthPath(this HttpContext context)
    {
        var requestContext = context.Features.Get<AuthRequestContext>();
        if (requestContext != null && requestContext.HasTenantId)
        {
            var validAuthPath = requestContext.Path?.Replace(requestContext.TenantId.ToString(), UrlParams.tenantId) ?? string.Empty;
            return ValidAuthPaths.Contains(validAuthPath); 
        }
        return false;
    }

}

public static class NullObjectCheck
{
    public static void ThrowAuthExceptionIfNull(this object obj, string errorCode, string errorDescription)
    {
        if (obj == null)
        {
            throw new AuthException
            {
                OAuthError = new OAuthErrorResponse
                {
                    error = errorCode,
                    error_description = errorDescription
                }
            };
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


public static class AuthResults
{
    public static IResult HandleAuhResponse(Func<OAuthAuthorizeResponse> func)
    {
        try
        {
            var authorizeResponse = func();
            return BuildAuthResponse(ResponseMode.fragment, new { authorizeResponse.RequestToken }, authorizeResponse.LoginUrl);
        }
        catch (AuthException ex)
        {
            return Results.BadRequest(ex?.OAuthError);
        }
        catch (Exception ex)
        {
            return Results.BadRequest(ex);
        }
    }

    public static IResult HandleAuhResponse(string response_mode, Func<OAuthTokenResponse> func,
        string? redirect_uri = null)
    {
        try
        {
            var tokenResponse = func();
            return BuildAuthResponse(response_mode, tokenResponse, redirect_uri);
        }
        catch (AuthException ex)
        {
            return Results.BadRequest(ex?.OAuthError);
        }
        catch (Exception ex)
        {
            return Results.BadRequest(ex);
        }
    }

    private static IResult BuildAuthResponse<T>(string response_mode, T response, string? redirect_uri = null)
        where T : class
    {
        if (string.IsNullOrEmpty(response_mode))
        {
            return Results.Ok(response);
        }
        else if (response_mode == ResponseMode.fragment)
        {
            var queryString = response.ToDictionary().ToQueryString();

            return Results.Redirect($"{redirect_uri}?{queryString}");
        }
        else if (response_mode == ResponseMode.form_post)
        {
            return Results.Ok(response);
        }
        else
        {
            throw new AuthException(Errors.invalid_resource, $"invalid {nameof(response_mode)} : {response_mode}");
        }
    }
}

public static class ObjectExtentions
{
    public static Dictionary<string,string> ToDictionary<T>(this T t)
        where T: class
    {
        if (t == null)
        {
            throw new ArgumentNullException(nameof(t));
        }
        var type = typeof(T);
        var properties = type.GetProperties(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public);

#pragma warning disable CS8619 // Nullability of reference types in value doesn't match target type.
        return properties
            .Select(p => new { p, v = p.GetValue(t, null) })
            .Where(x => x.v != null)
            .ToDictionary(k => k.p.Name, v => v?.v?.ToString());
#pragma warning restore CS8619 // Nullability of reference types in value doesn't match target type.

    }

    public static string ToQueryString(this Dictionary<string, string> queryDictionary)
    {
        var queryString = string.Join('&', queryDictionary.Select(x => $"{x.Key}={x.Value}"));
        return queryString; 

    }
}

public static class StringExtentions
{ 
    public static string ToBase64String(this string plainText)
    {
        var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
        var base64EncodedText = Convert.ToBase64String(plainTextBytes);
        return base64EncodedText;
    }

    public static Dictionary<string, string> ToDictionary(this string queryString)
    {
        var queryDictionary = queryString.Split('&')
            .Select(x =>
            {
                var kv = x.Split('=');
                return new { k = kv.First(), v = kv.Last() };
            }).
            ToDictionary(x => x.k, x => x.v);

        return queryDictionary;
    }
}

public static class ServiceProviderExtentions
{
    public static T? GetHttpContextFeature<T>(this IServiceProvider serviceProvider)
        where T: class, new()
    {
        var HttpContextAccessor = serviceProvider.GetService<IHttpContextAccessor>();
        if (HttpContextAccessor?.HttpContext?.Features != null)
        {
            return HttpContextAccessor?.HttpContext.Features.Get<T>();
        }
        else
            return null;
    }
}