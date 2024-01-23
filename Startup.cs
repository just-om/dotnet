using Microsoft.Owin;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;

[assembly: OwinStartup(typeof(LoginwDb.Startup))]

namespace LoginwDb
{
    public class Startup
    {
        public static OAuthAuthorizationServerOptions OAuthOptions { get; private set; }

        public void Configuration(IAppBuilder app)
        {
            ConfigureOAuth(app);
        }

        public void ConfigureOAuth(IAppBuilder app)
        {
            OAuthOptions = new OAuthAuthorizationServerOptions
            {
                AllowInsecureHttp = true, // Remove this line if using HTTPS in production
                TokenEndpointPath = new PathString("/token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(30), // Set the desired token expiration time
               
            };

            app.UseOAuthAuthorizationServer(OAuthOptions);
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());
        }

    }
}
