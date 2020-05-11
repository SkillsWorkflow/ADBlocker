using System;

namespace SkillsWorkflow.Services.ADBlocker.Models
{
    public class User
    {
        public Guid Oid { get; set; }
        public string UserName { get; set; }
        public string AdUserName { get; set; }
    }

    public class UserToBlock
    {
        public Guid Oid { get; set; }
        public DateTime? AccountExpirationDate { get; set; }
        public bool Success { get; set; }
        public string Message { get; set; }
    }
}
