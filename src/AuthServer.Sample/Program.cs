using AuthServer.Sample.Extentions;
using AuthServer.Sample.Models;
using AuthServer.Sample.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using static AuthServer.Sample.Constants.Auth;

var builder = WebApplication.CreateBuilder(args);
builder.Services
    .AddHttpContextAccessor()
    .AddSingleton<ResourceReader>()
    .AddScoped<WellKnownConfiguration>()
    .AddScoped<OAuth2Token>()
    .AddScoped<IJwtSigningService, JwtSigningService>()
    .AddScoped<IJwtUtils, JwtUtils>()
    .AddScoped<ClientDataProvider>()
    .AddScoped<ITenantsDataProvider, TenantsDataProvider>()
    .AddScoped<AuthRequestContext>((sp) =>
    {
        return sp.GetHttpContextFeature<AuthRequestContext>() ?? new AuthRequestContext();
    })
    .AddScoped<TenantSettings>((sp) =>
    {
        return sp.GetHttpContextFeature<TenantSettings>() ?? new TenantSettings();
    })
    ;
builder.Services.AddOptions<AuthSettings>().BindConfiguration("AuthSettings");

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new()
    {
        Title = builder.Environment.ApplicationName,
        Version = "v1"
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json",
                                    $"{builder.Environment.ApplicationName} v1"));
}

var authSettings = app.Services.GetService<IOptions<AuthSettings>>();

var tmp = RoutePatternFactory.Parse("/{guid}/test/1");
//Microsoft.AspNetCore.Http.DefaultHttpContext

app.Use(async (context, next) =>
{
    context.SetRequestContext();
    if (context.Request.HasFormContentType)
    {
        await context.Request.FormContentToJson();
    }
    context.SetTenantsContext();

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
               { "V1 /oauth2/token",linker.GetPathByName(Token.V1EPName, values: new { tenantId = Guid.Empty }) },
               { "V2 /oauth2/token",linker.GetPathByName(Token.V2EPName, values: new { tenantId = Guid.Empty }) },
               { "V1 /oauth2/authorize",linker.GetPathByName(Authorize.V1GetEPName, values: new { tenantId = Guid.Empty }) },
               { "V2 /oauth2/authorize",linker.GetPathByName(Authorize.V2GetEPName, values: new { tenantId = Guid.Empty }) },
           }
           .Select(x => $"<tr><td><a href='{x.Value}'>{x.Key}</a></td></tr>").ToArray();

           var htmlBody = $"<div><span>The link to the</span> <table>{ string.Join(",", urls) }</table></dv>";
           return Results.Content($"<html><body></body>{htmlBody}</html>", "text/html; charset=utf-8");
       });

app.MapGet(WellKnownConfig.V1Url, (WellKnownConfiguration configuration, HttpRequest request, string tenantId) =>
{
    var siteName = $"{request.Scheme}://{request.Host.ToUriComponent()}";
    return Results.Text(configuration.GetV1(siteName, tenantId), "application/json"); 
})
    .WithName(WellKnownConfig.V1EPName);

app.MapGet(WellKnownConfig.V2Url, (WellKnownConfiguration configuration, HttpRequest request, string tenantId) =>
{
    var siteName = $"{request.Scheme}://{request.Host.ToUriComponent()}";
    return Results.Text(configuration.GetV2(siteName, tenantId), "application/json");
})
    .WithName(WellKnownConfig.V2EPName);

app.MapPost(Token.V1Url, (OAuth2Token tokenService,[FromBody] OAuthTokenRequest tokenRequest, [FromServices] AuthRequestContext requestConext) =>
{
    return AuthResults.HandleAuhResponse(tokenRequest.response_mode,
            ()=> tokenService.GenerateResponse(tokenRequest, requestConext));
})
    .WithName(Token.V1EPName);

app.MapPost(Token.V2Url, (OAuth2Token tokenService, [FromBody] OAuthTokenRequest tokenRequest, [FromServices] AuthRequestContext requestConext) =>
{
    return AuthResults.HandleAuhResponse(tokenRequest.response_mode,
            () => tokenService.GenerateResponse(tokenRequest, requestConext));
})
    .WithName(Token.V2EPName);


app.MapGet(Authorize.V1Url, (OAuth2Token tokenService, HttpRequest request, [FromServices] AuthRequestContext requestConext) =>
{
    var tokenRequest = request.QueryStringTo<OAuthTokenRequest>();
    return AuthResults.HandleAuhResponse(()=> tokenService.BuildAuthorizeResponse(tokenRequest, requestConext));
})
    .WithName(Authorize.V1GetEPName);

app.MapPost(Authorize.V1Url, (OAuth2Token tokenService, [FromBody] OAuthTokenRequest tokenRequest, [FromServices] AuthRequestContext requestConext) =>
{
    return AuthResults.HandleAuhResponse(tokenRequest.response_mode ?? ResponseMode.fragment,
            () => tokenService.GenerateResponse(tokenRequest, requestConext), tokenRequest.redirect_uri);

})
    .WithName(Authorize.V1PostEPName);

app.MapGet(Authorize.V2Url, (OAuth2Token tokenService, HttpRequest request, [FromServices] AuthRequestContext requestConext) =>
{
    var tokenRequest = request.QueryStringTo<OAuthTokenRequest>();
    return AuthResults.HandleAuhResponse(() => tokenService.BuildAuthorizeResponse(tokenRequest, requestConext));
})
    .WithName(Authorize.V2GetEPName);

app.MapPost(Authorize.V2Url, (OAuth2Token tokenService, [FromBody] OAuthTokenRequest tokenRequest, [FromServices] AuthRequestContext requestConext) =>
{
    return AuthResults.HandleAuhResponse(tokenRequest.response_mode ?? ResponseMode.fragment,
            () => tokenService.GenerateResponse(tokenRequest, requestConext));

})
    .WithName(Authorize.V2PostEPName);

app.Use(async (context, next) =>
{
    //context.Request.HasFormContentType
    Console.WriteLine(context.Request.ContentType);
    Console.WriteLine($"2. Endpoint: {context.GetEndpoint()?.DisplayName ?? "(null)"}");
    await next(context);
});

app.Run();


public partial class Program { }