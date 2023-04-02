using AuthServer.Sample.Services;
using System.Reflection;

var builder = WebApplication.CreateBuilder(args);
builder.Services
    .AddSingleton<ResourceReader>()
    .AddTransient<WellKnownOpenidConfiguration>();
var app = builder.Build();

app.MapGet("/", () => "Hello World!");

app.MapGet(WellKnownOpenidConfiguration.ConstV1Url, (WellKnownOpenidConfiguration configuration, HttpRequest request) =>
{
    var siteName = $"{request.Scheme}//{request.Host.ToUriComponent()}";
    var appId = string.Empty;
    return Results.Text(configuration.GetV1(siteName, appId), "application/json"); 
});

app.MapGet(WellKnownOpenidConfiguration.ConstV2Url, (WellKnownOpenidConfiguration configuration, HttpRequest request) =>
{
    var siteName = $"{request.Scheme}//{request.Host.ToUriComponent()}";
    var appId = string.Empty;
    return Results.Text(configuration.GetV2(siteName, appId), "application/json");
});

app.Run();
