using AuthServer.Sample.Services;
using Microsoft.Extensions.Configuration;
using System.Reflection;

var builder = WebApplication.CreateBuilder(args);
builder.Services
    .AddSingleton<ResourceReader>()
    .AddTransient<WellKnownOpenidConfiguration>()
    .AddTransient<OAuth2Token>();
var app = builder.Build();

app.Use(async (context, next) =>
{
    Console.WriteLine($"1. Endpoint: {context.GetEndpoint()?.DisplayName ?? "(null)"}");
    Console.WriteLine(context.Request.ContentType);
    await next(context);
});


app.MapGet("/", (LinkGenerator linker) =>
       {
           var v1Url = linker.GetPathByName("v1-well-known-config", values: new { tenantId = Guid.Empty });
           var v2Url = linker.GetPathByName("v2-well-known-config", values: new { tenantId = Guid.Empty });
           var htmlBody = $"The link to the /.well-known/openid-configuration route of <a href='{v1Url}'>v1</a>  <a href='{v2Url}'>v2</a> ";
           return Results.Content($"<html><body></body>{htmlBody}</html>", "text/html; charset=utf-8");
       });

app.MapGet(WellKnownOpenidConfiguration.ConstV1Url, (WellKnownOpenidConfiguration configuration, HttpRequest request, string tenantId) =>
{
    var siteName = $"{request.Scheme}//{request.Host.ToUriComponent()}";
    return Results.Text(configuration.GetV1(siteName, tenantId), "application/json"); 
})
    .WithName("v1-well-known-config");

app.MapGet(WellKnownOpenidConfiguration.ConstV2Url, (WellKnownOpenidConfiguration configuration, HttpRequest request, string tenantId) =>
{
    var siteName = $"{request.Scheme}//{request.Host.ToUriComponent()}";
    return Results.Text(configuration.GetV2(siteName, tenantId), "application/json");
})
    .WithName("v2-well-known-config");

app.MapPost(OAuth2Token.ConstV1Url, (OAuth2Token tokenService, OAuthTokenRequest tokenRequest) =>
{
    return Results.Text(tokenService.GetResponse(tokenRequest), "application/json");
});

app.Use(async (context, next) =>
{
    Console.WriteLine($"1. Endpoint: {context.GetEndpoint()?.DisplayName ?? "(null)"}");
    Console.WriteLine(context.Request.ContentType);
    await next(context);
});

app.Run();
