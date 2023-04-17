namespace AuthServer.Sample;

public class Constants
{
    public static class Auth
    {
        public static class Errors
        {
            public const string invalid_request = "invalid_request";
            public const string unauthorized_client = "unauthorized_client";
            public const string access_denied = "access_denied";
            public const string unsupported_response_type = "unsupported_response_type";
            public const string server_error = "server_error";
            public const string temporarily_unavailable = "temporarily_unavailable";
            public const string invalid_resource = "invalid_resource";
            public const string invalid_grant = "invalid_grant";
            public const string invalid_scope = "invalid_scope";
            public const string invalid_token = "invalid_token";
            public const string invalid_client = "invalid_client";
            public const string user_authentication_required = "user_authentication_required";
        }

        public static class WellKnownConfig
        {
            //"/.well-known/openid-configuration"
            public const string V1Url = "/{tenantId}/.well-known/openid-configuration";
            public const string V2Url = "/{tenantId}/v2.0/.well-known/openid-configuration";
            public const string V1ConfigresourceName = "AuthServer.Sample.Resources.openid-configuration.json";
            public const string V2ConfigresourceName = "AuthServer.Sample.Resources.V2.openid-configuration.json";

            public const string V1EPName = "v1-well-known-config";
            public const string V2EPName = "v2-well-known-config";
        }

        public static class Token
        {
            //"/oauth2/token"
            public const string V1Url = "/{tenantId}/oauth2/token";
            public const string V2Url = "/{tenantId}/oauth2/v2.0/token";

            public const string V1EPName = "v1-oauth2-token";
            public const string V2EPName = "v2-oauth2-token";
        }

        public static class Authorize
        {
            //"/oauth2/authorize"
            public const string V1Url = "/{tenantId}/oauth2/authorize";
            public const string V2Url = "/{tenantId}/oauth2/v2.0/authorize";

            public const string V1PostEPName = "v1-oauth2-authorize";
            public const string V2PostEPName = "v2-oauth2-authorize";

            public const string V1GetEPName = "Get-v1-oauth2-authorize";
            public const string V2GetEPName = "Get-v2-oauth2-authorize";

        }

        public static class GrantType
        {
            public const string password = "password";
            public const string client_credentials = "client_credentials";
        }

        public static class ResponseType
        {
            public const string id_token = "id_token";
            public const string code = "code";
            public const string token = "token";
            public const string access_token = "access_token";
        }

        public static class ResponseMode
        {
            public const string query = "query";
            public const string fragment = "fragment";
            public const string form_post = "form_post";
        }

        public static class TokenType { 
            public const string Bearer = "Bearer";
        }

        public static class Claims
        {
            public const string aud = "aud";
            public const string iss = "iss";
            public const string iat = "iat";
            public const string nbf = "nbf";
            public const string exp = "exp";
            public const string aio = "aio";
            public const string amr = "amr";
            public const string rsa = "rsa";
            public const string email = "email";
            public const string family_name = "family_name";
            public const string given_name = "given_name";
            public const string roles = "roles";
            public const string idp = "idp";
            public const string ipaddr = "ipaddr";
            public const string name = "name";
            public const string nonce = "nonce";
            public const string oid = "oid";
            public const string rh = "rh";
            public const string sub = "sub";
            public const string tid = "tid";
            public const string unique_name = "unique_name";
            public const string preferred_username = "preferred_username";
            public const string appid = "appid";
            public const string uti = "uti";
            public const string ver = "ver";
        }

        public static class UrlParams
        {
             public const string tenantId = "{tenantId}"; 
        }
    }
}
