namespace LoginwDb.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class Initial : DbMigration
    {
        public override void Up()
        {
            CreateTable(
                "dbo.Tokens",
                c => new
                    {
                        TokenId = c.Int(nullable: false, identity: true),
                        UserId = c.Int(nullable: false),
                        TokenValue = c.String(),
                        GeneratedTime = c.DateTime(nullable: false),
                        ExpireTime = c.DateTime(nullable: false),
                    })
                .PrimaryKey(t => t.TokenId);
            
            CreateTable(
                "dbo.Users",
                c => new
                    {
                        UserId = c.Int(nullable: false, identity: true),
                        Username = c.String(),
                        Password = c.String(),
                        FirstName = c.String(),
                        LastName = c.String(),
                    })
                .PrimaryKey(t => t.UserId);
            
        }
        
        public override void Down()
        {
            DropTable("dbo.Users");
            DropTable("dbo.Tokens");
        }
    }
}
