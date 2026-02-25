namespace Scalpel.Enterprise
{
    public class AnalysisResult
    {
        public Dictionary<string, List<string>> CommitToRequirements { get; set; }
        public Dictionary<string, HashSet<string>> FileToRequirements { get; set; }
        public Dictionary<string, MethodInfo> MethodToRequirements { get; set; }
        public DateTime AnalysisDate { get; set; }
        public string RepositoryPath { get; set; }
        public List<string> RepositoryPaths { get; set; } // For multiple repositories
        public string FilteredByRequirementId { get; set; } // If analysis is filtered by a specific requirement
    }
}