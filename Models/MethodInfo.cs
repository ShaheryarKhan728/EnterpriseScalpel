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

        public object Clone()
        {
            return new MethodInfo
            {
                FilePath = this.FilePath,
                MethodName = this.MethodName,
                Requirements = new HashSet<string>(this.Requirements ?? new HashSet<string>()),
                ChangeCount = this.ChangeCount,
                LineStart = this.LineStart,
                LineEnd = this.LineEnd
            };
        }
    }
}