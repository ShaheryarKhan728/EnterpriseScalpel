namespace Scalpel.Enterprise
{
    public class RequirementImpact
    {
        public string RequirementId { get; set; }
        public int CommitCount { get; set; }
        public HashSet<string> AffectedFiles { get; set; }
        public HashSet<string> AffectedMethods { get; set; }
        public List<string> Dependencies { get; set; }
        public double RiskScore { get; set; }
    }
}