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

        /// <summary>
        /// Repository (service) names used as path prefixes in merged results, in analysis order.
        /// File keys and method file paths look like "{name}/{path}". Empty for unmerged results.
        /// </summary>
        public List<string> RepositoryNames { get; set; } = new();
    }
}
