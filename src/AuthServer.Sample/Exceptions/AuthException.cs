using AuthServer.Sample.Models;
using AuthServer.Sample.Services;

namespace AuthServer.Sample.Exceptions;

public class AuthException : Exception
{
    public AuthException() : base("Auth error")
    {
        OAuthError = new()
        {
            error = "None",
            error_description = "Unknown"
        };
    }
    public AuthException(string message) : base(message)
    {
        OAuthError = new()
        {
            error = "None",
            error_description = message
        };
    }

    public AuthException(string errorCode, string message)
        : base($"{errorCode}-{message}")
    {
        OAuthError = new()
        {
            error = errorCode,
            error_description = message
        };
    }
    public OAuthErrorResponse OAuthError { get; set; }

}
