using AuthServer.Sample.Extentions;
using AuthServer.Sample.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.Extensions.Configuration;
using System.Reflection;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
builder.Services
    .AddSingleton<AppSettings>()
    .AddSingleton<ResourceReader>()
    .AddTransient<WellKnownOpenidConfiguration>()
    .AddTransient<OAuth2Token>()
    .AddTransient<IJwtUtils, JwtUtils>();
var app = builder.Build();

var tmp = RoutePatternFactory.Parse("/{guid}/test/1");

app.Use(async (context, next) =>
{

    if (context.Request.HasFormContentType)
    {
        await context.Request.FormContentToJson();
    }
    await next(context);

    static async Task AwaitRequestTask()
    {
        await Task.CompletedTask;
    }
});
//app.UseEndpoints();
app.UseRouting();

app.MapGet("/", (LinkGenerator linker) =>
       {
           var urls = new Dictionary<string, string?>()
           {
               { "V1 /.well-known/openid-configuration",linker.GetPathByName(WellKnownConfig.V1EPName, values: new { tenantId = Guid.Empty }) },
               { "V2 /.well-known/openid-configuration",linker.GetPathByName(WellKnownConfig.V2EPName, values: new { tenantId = Guid.Empty }) },
               { "V1 /oauth2/token",linker.GetPathByName("v1-oauth2-token", values: new { tenantId = Guid.Empty }) },
           }
           .Select(x => $"<a href='{x.Value}'>{x.Key}</a>").ToArray();

           var htmlBody = $"<div><span>The link to the</span> { string.Join(",", urls) } </dv>";
           return Results.Content($"<html><body></body>{htmlBody}</html>", "text/html; charset=utf-8");
       });

app.MapGet(WellKnownConfig.V1Url, (WellKnownOpenidConfiguration configuration, HttpRequest request, string tenantId) =>
{
    var siteName = $"{request.Scheme}//{request.Host.ToUriComponent()}";
    return Results.Text(configuration.GetV1(siteName, tenantId), "application/json"); 
})
    .WithName(WellKnownConfig.V1EPName);

app.MapGet(WellKnownConfig.V2Url, (WellKnownOpenidConfiguration configuration, HttpRequest request, string tenantId) =>
{
    var siteName = $"{request.Scheme}//{request.Host.ToUriComponent()}";
    return Results.Text(configuration.GetV2(siteName, tenantId), "application/json");
})
    .WithName(WellKnownConfig.V2EPName);

app.MapPost(Token.V1Url, (HttpContext context, OAuth2Token tokenService, OAuthTokenRequest tokenRequest) =>
{
    var requestConext = context.GetRequestContext();
    return Results.Text(tokenService.GenerateResponse(tokenRequest, requestConext), "application/json");
})
    .WithName(Token.V1EPName);

app.Use(async (context, next) =>
{
    //context.Request.HasFormContentType
    Console.WriteLine(context.Request.ContentType);
    Console.WriteLine($"2. Endpoint: {context.GetEndpoint()?.DisplayName ?? "(null)"}");
    await next(context);
});

app.Run();
