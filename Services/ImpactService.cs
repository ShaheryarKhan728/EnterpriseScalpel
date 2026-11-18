namespace Scalpel.Enterprise
{
    /// <summary>
    /// Answers "I'm changing these files/methods, which requirements should I retest?" from a
    /// completed analysis: every requirement whose commits touched the file (or method) is listed.
    /// </summary>
    public static class ImpactService
    {
        public const int MaxTargets = 20;
        public const int MaxTargetLength = 300;

        public static string? ValidateTargets(List<string>? targets)
        {
            var cleaned = targets?.Where(t => !string.IsNullOrWhiteSpace(t)).Select(t => t.Trim()).ToList() ?? new List<string>();
            if (cleaned.Count == 0)
                return "Enter at least one file or method you are changing.";
            if (cleaned.Count > MaxTargets)
                return $"At most {MaxTargets} files or methods can be checked at once.";
            if (cleaned.Any(t => t.Length > MaxTargetLength || t.Any(char.IsControl)))
                return "A file or method name is too long or contains invalid characters.";
            return null;
        }

        public static ImpactResponse FindImpact(
            AnalysisResult analysis,
            IEnumerable<string> targets,
            IReadOnlyDictionary<string, PMTicket>? tickets = null)
        {
            var targetResults = new List<ImpactTargetResult>();
            var unmatched = new List<string>();
            var allRequirements = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var rawTarget in targets.Where(t => !string.IsNullOrWhiteSpace(t)).Select(t => t.Trim()).Distinct())
            {
                var matches = new List<ImpactMatch>();
                var separator = rawTarget.IndexOf("::", StringComparison.Ordinal);

                if (separator >= 0)
                {
                    var filePart = NormalizePath(rawTarget.Substring(0, separator));
                    var methodPart = rawTarget.Substring(separator + 2).Trim();
                    foreach (var method in (analysis.MethodToRequirements ?? new Dictionary<string, MethodInfo>()).Values)
                    {
                        if (method.Requirements == null || method.Requirements.Count == 0) continue;
                        if (!string.Equals(method.MethodName, methodPart, StringComparison.OrdinalIgnoreCase)) continue;
                        if (filePart.Length > 0 && !PathMatches(method.FilePath, filePart)) continue;
                        matches.Add(new ImpactMatch(method.FilePath, method.MethodName, Sorted(method.Requirements)));
                    }
                }
                else
                {
                    var filePart = NormalizePath(rawTarget);
                    foreach (var (file, reqs) in analysis.FileToRequirements ?? new Dictionary<string, HashSet<string>>())
                    {
                        if (reqs.Count > 0 && PathMatches(file, filePart))
                        {
                            matches.Add(new ImpactMatch(file, null, Sorted(reqs)));
                        }
                    }
                }

                if (matches.Count == 0)
                {
                    unmatched.Add(rawTarget);
                    continue;
                }

                foreach (var match in matches)
                {
                    allRequirements.UnionWith(match.Requirements);
                }
                targetResults.Add(new ImpactTargetResult(rawTarget, matches.OrderBy(m => m.File, StringComparer.OrdinalIgnoreCase).ToList()));
            }

            var requirements = allRequirements
                .Select(id => new ImpactRequirement(id, tickets != null && tickets.TryGetValue(id, out var t) ? t.Url : null))
                .ToList();

            return new ImpactResponse(requirements, targetResults, unmatched);
        }

        private static IReadOnlyList<string> Sorted(IEnumerable<string> reqs) =>
            reqs.OrderBy(r => r, StringComparer.OrdinalIgnoreCase).ToList();

        private static string NormalizePath(string path) =>
            path.Trim().Replace('\\', '/').TrimStart('.', '/').TrimEnd('/');

        /// <summary>
        /// Matches a full path, or a trailing part of it on a folder boundary:
        /// "PaymentService.cs" and "Services/PaymentService.cs" both match "repo/src/Services/PaymentService.cs".
        /// </summary>
        private static bool PathMatches(string candidate, string query)
        {
            if (query.Length == 0) return false;
            var normalized = candidate.Replace('\\', '/');
            return normalized.Equals(query, StringComparison.OrdinalIgnoreCase)
                   || normalized.EndsWith("/" + query, StringComparison.OrdinalIgnoreCase);
        }
    }
}
