using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Data.Entity;

namespace LoginwDb.Models
{
    public class YourDbContextName : DbContext
    {
        public YourDbContextName() : base("name=YourDbContextName")
        {
        }

        public DbSet<User> Users { get; set; }
        public DbSet<Token> Tokens { get; set; }
    }
}