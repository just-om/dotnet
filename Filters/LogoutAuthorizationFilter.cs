using LoginwDb.Models;
using System;
using System.Configuration;
using System.Data.SqlClient;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;

namespace LoginwDb.Filters
{
    public class TokenValidationFilter : AuthorizationFilterAttribute
    {
        private readonly string ConnectionString = ConfigurationManager.ConnectionStrings["YourDatabaseConnection"].ConnectionString;

        public override void OnAuthorization(HttpActionContext actionContext)
        {
            var token = actionContext.Request.Headers.Authorization?.Parameter;
            var identity = actionContext.RequestContext.Principal?.Identity as ClaimsIdentity;
            var userId = identity.FindFirst(ClaimTypes.Name)?.Value;

            if (token == null || string.IsNullOrEmpty(token))
            {
                actionContext.Response = new HttpResponseMessage(HttpStatusCode.Unauthorized)
                {
                    Content = new StringContent("UnAuthorised")
                };
                return;
            }

            if (!IsTokenValid(token))
            {
                actionContext.Response = new HttpResponseMessage(HttpStatusCode.Unauthorized)
                {
                    Content = new StringContent("Invalid or expired token")
                };
                return;
            }

            base.OnAuthorization(actionContext);
        }

        private bool IsTokenValid(string token)
        {
            using (var connection = new SqlConnection(ConnectionString))
            {
                connection.Open();

                using (var command = new SqlCommand("SELECT Top 1 ExpirationTime FROM TokenHistory WHERE Token = @Token", connection))
                {
                    command.Parameters.AddWithValue("@Token", token);


                    using (var reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            var expirationTime = (DateTime)reader["ExpirationTime"];
                            var remainingValidity = expirationTime - DateTime.UtcNow;

                            // If remaining validity is less than 30 seconds, refresh the token
                            if (remainingValidity.TotalSeconds < 300)
                            {
                                TryRefreshToken(token);
                            }

                            // Token is still valid
                            return true;
                        }
                        else
                        {
                            // No record found, token is not valid
                            return false;
                        }
                        
                    }

                }

            }
        }

        private bool TryRefreshToken(string token)
        {
            using (var connection = new SqlConnection(ConnectionString))
            {
                connection.Open();

                // Retrieve the current expiration time
                DateTime currentExpirationTime;
                using (var getCurrentExpirationCommand = new SqlCommand("SELECT TOP 1 ExpirationTime FROM TokenHistory WHERE Token = @Token", connection))
                {
                    getCurrentExpirationCommand.Parameters.AddWithValue("@Token", token);
                    currentExpirationTime = (DateTime)getCurrentExpirationCommand.ExecuteScalar();
                }

                // Calculate the new expiration time (refresh)
                var newExpirationTime = currentExpirationTime.AddMinutes(3); // Update with your desired expiration time

                // Attempt to refresh the token
                using (var command = new SqlCommand("UPDATE TokenHistory SET ExpirationTime = @ExpirationTime WHERE Token = @Token AND ExpirationTime = @CurrentExpirationTime", connection))
                {
                    command.Parameters.AddWithValue("@Token", token);
                    command.Parameters.AddWithValue("@ExpirationTime", newExpirationTime);
                    command.Parameters.AddWithValue("@CurrentExpirationTime", currentExpirationTime);

                    int rowsAffected = command.ExecuteNonQuery();

                    return rowsAffected > 0;
                }
            }
        }
    }
}
