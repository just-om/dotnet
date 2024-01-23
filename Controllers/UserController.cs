using System;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;
using System.Web.Http.Description;
using LoginwDb.Filters;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;

namespace LoginwDb.Controllers
{
    public class UserController : ApiController
    {
        private readonly string ConnectionString = ConfigurationManager.ConnectionStrings["YourDatabaseConnection"].ConnectionString;

        [HttpPost]
        [Route("api/authenticate")]
        [ResponseType(typeof(AuthenticationResponse))]
        public IHttpActionResult Authenticate([FromBody] UserCredentials credentials)
        {
            using (var connection = new SqlConnection(ConnectionString))
            {
                connection.Open();
                using (var command = new SqlCommand("AuthenticateUser", connection))
                {
                    command.CommandType = CommandType.StoredProcedure;
                    command.Parameters.AddWithValue("@Username", credentials.Username);
                    command.Parameters.AddWithValue("@Password", credentials.Password);

                    using (var reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            var userId = reader["UserId"].ToString();
                            var firstName = reader["FirstName"].ToString();
                            var lastName = reader["LastName"].ToString();

                            var oAuthIdentity = new ClaimsIdentity(Startup.OAuthOptions.AuthenticationType);
                            oAuthIdentity.AddClaim(new Claim(ClaimTypes.Name, userId));
                            oAuthIdentity.AddClaim(new Claim(ClaimTypes.GivenName, firstName));
                            oAuthIdentity.AddClaim(new Claim(ClaimTypes.Surname, lastName));

                            var ticket = new AuthenticationTicket(oAuthIdentity, new AuthenticationProperties
                            {
                                IssuedUtc = DateTime.UtcNow,
                            });

                            var accessToken = Startup.OAuthOptions.AccessTokenFormat.Protect(ticket);

                            UpdateTokenDetails(userId, accessToken, DateTime.UtcNow, DateTime.UtcNow.AddMinutes(3));

                            var authenticationResponse = new AuthenticationResponse
                            {
                                Access_token = accessToken
                            };

                            return Ok(authenticationResponse);
                        }
                        else
                        {
                            return Unauthorized();
                        }
                    }
                }
            }
        }

        [HttpGet]
        [Route("api/user/details")]
        [TokenValidationFilter] // Apply the TokenValidationFilter here
        public IHttpActionResult GetUserDetails()
        {
            var identity = User.Identity as ClaimsIdentity;
            var userId = identity.FindFirst(ClaimTypes.Name)?.Value;


            // Retrieve user details from the database based on userId
            var userDetails = GetUserDetailsFromDatabase(userId);

            if (userDetails != null)
            {
                return Ok(userDetails);
            }
            else
            {
                return NotFound();
            }
        }

        [HttpPost]
        [Route("api/logout")]
        [Authorize]
        [TokenValidationFilter]
        public IHttpActionResult Logout()
        {
            var token = ExtractTokenFromHeader(Request);

            if (!string.IsNullOrEmpty(token))
            {
                // Remove the token details from the database (optional)
                RemoveTokenDetails(token);

                return Ok("Logout successful");
            }
            else
            {
                return Unauthorized();
            }
        }

        private UserDetails GetUserDetailsFromDatabase(string userId)
        {
            // Implement logic to retrieve user details from the database based on userId
            // This could include querying the user table or any other relevant storage

            using (var connection = new SqlConnection(ConnectionString))
            using (var command = new SqlCommand("SELECT UserId, FirstName, LastName FROM Users WHERE UserId = @UserId", connection))
            {

                connection.Open();
                command.Parameters.AddWithValue("@UserId", userId);

                using (var reader = command.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        return new UserDetails
                        {
                            UserId = reader["UserId"].ToString(),
                            FirstName = reader["FirstName"].ToString(),
                            LastName = reader["LastName"].ToString()
                        };
                    }
                    else
                    {
                        return null; // User not found
                    }
                }
            }
        }

        private void RemoveTokenDetails(string token)
        {
            using (var connection = new SqlConnection(ConnectionString))
            {
                connection.Open();

                using (var command = new SqlCommand("DELETE FROM TokenHistory WHERE Token = @Token", connection))
                {
                    command.Parameters.AddWithValue("@Token", token);

                    command.ExecuteNonQuery();
                }
            }
        }

        private void UpdateTokenDetails(string userId, string accessToken, DateTime generatedTime, DateTime expirationTime)
        {
            using (var connection = new SqlConnection(ConnectionString))
            {
                connection.Open();

                using (var command = new SqlCommand("INSERT INTO TokenHistory (UserId, Token, GeneratedTime, ExpirationTime) VALUES (@UserId, @Token, @GeneratedTime, @ExpirationTime)", connection))
                {
                    command.Parameters.AddWithValue("@UserId", userId);
                    command.Parameters.AddWithValue("@Token", accessToken);
                    command.Parameters.AddWithValue("@GeneratedTime", generatedTime);
                    command.Parameters.AddWithValue("@ExpirationTime", expirationTime);

                    command.ExecuteNonQuery();
                }
            }
        }

        private string ExtractTokenFromHeader(HttpRequestMessage request)
        {
            var authHeader = request.Headers.Authorization;

            if (authHeader != null && authHeader.Scheme.Equals("Bearer", StringComparison.OrdinalIgnoreCase))
            {
                return authHeader.Parameter;
            }

            return null;
        }

        public class AuthenticationResponse
        {
            public string Access_token { get; set; }
        }

        public class UserDetails
        {
            public string UserId { get; set; }
            public string FirstName { get; set; }
            public string LastName { get; set; }
        }

        public class UserCredentials
        {
            public string Username { get; set; }
            public string Password { get; set; }
        }
    }
}
