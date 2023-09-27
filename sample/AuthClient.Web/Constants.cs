namespace AuthClient.Web
{
    public static class Constants
    {
        public static class Authorize
        {
            //"/oauth2/authorize"
            public const string TenantId = "{tenantId}";
            public const string V1Url = "/{tenantId}/oauth2/authorize";
            public const string V2Url = "/{tenantId}/oauth2/v2.0/authorize";

        }
        public static class Token
        {
            //"/oauth2/token"
            public const string V1Url = "/{tenantId}/oauth2/token";
            public const string V2Url = "/{tenantId}/oauth2/v2.0/token";

        }

    }
}
