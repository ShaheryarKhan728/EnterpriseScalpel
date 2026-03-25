namespace Scalpel.Enterprise
{
    public class MethodInfo
    {
        public string FilePath { get; set; }
        public string MethodName { get; set; }
        public HashSet<string> Requirements { get; set; }
        public int ChangeCount { get; set; }
        public int LineStart { get; set; }
        public int LineEnd { get; set; }
        
        // Per-requirement tracking: Requirement ID -> (LineStart, LineEnd, ChangeCount)
        public Dictionary<string, (int start, int end, int changes)> RequirementDetails { get; set; } 
            = new Dictionary<string, (int, int, int)>();

        public object Clone()
        {
            return new MethodInfo
            {
                FilePath = this.FilePath,
                MethodName = this.MethodName,
                Requirements = new HashSet<string>(this.Requirements ?? new HashSet<string>()),
                ChangeCount = this.ChangeCount,
                LineStart = this.LineStart,
                LineEnd = this.LineEnd,
                RequirementDetails = this.RequirementDetails != null 
                    ? new Dictionary<string, (int, int, int)>(this.RequirementDetails)
                    : new Dictionary<string, (int, int, int)>()
            };
        }
    }
}