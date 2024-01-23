using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace LoginwDb.Models
{
    public class Token
    {
        public int TokenId { get; set; }
        public int UserId { get; set; }
        public string TokenValue { get; set; }
        public DateTime GeneratedTime { get; set; }
        public DateTime ExpireTime { get; set; }
    }


}