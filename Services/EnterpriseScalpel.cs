using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Scalpel.Enterprise
{
    /// <summary>
    /// Enterprise-grade requirement traceability and impact analysis tool
    /// </summary>
    public class EnterpriseScalpel
    {
        private readonly Configuration _config;
        private readonly ILogger _logger;
        private readonly ReportService _reportService;

        public EnterpriseScalpel(Configuration config, ILogger logger)
        {
            _config = config;
            _logger = logger;
            _reportService = new ReportService();
        }

        public void ExecuteCommand(string[] args)
        {
            var command = args[0].ToLower();
            switch (command)
            {
                case "analyze":
                    var repositories = new List<string>();
                    string requirementId = null;
                    bool usePM = false;

                    for (int i = 1; i < args.Length; i++)
                    {
                        if (args[i] == "--repos" && i + 1 < args.Length)
                        {
                            repositories.AddRange(args[i + 1].Split(',').Select(r => r.Trim()));
                            i++;
                        }
                        else if (args[i] == "--pm")
                        {
                            usePM = true;
                        }
                        else if (!args[i].StartsWith("--"))
                        {
                            requirementId = args[i];
                        }
                    }
                    _logger.Info($"Use PM integration: {usePM}");

                    if (usePM)
                    {
                        AnalyzeWithRepositoriesAndPM(repositories, requirementId);
                    }
                    else
                    {
                        AnalyzeWithRepositories(repositories, requirementId);
                    }
                    break;
                case "impact":
                    if (args.Length < 2)
                    {
                        _logger.Error("Usage: scalpel impact <filepath>");
                        return;
                    }
                    AnalyzeFileImpact(args[1]);
                    break;
                case "report":
                    var format = args.Length > 1 ? args[1] : "html";
                    GenerateReport(format);
                    break;
                case "hotspots":
                    FindHotspots();
                    break;
                default:
                    ShowHelp();
                    break;
            }
        }

        public void RunFullAnalysis()
        {
            _logger.Info("Starting comprehensive analysis...");

            var commitToReqs = BuildCommitToRequirementsMap();
            var allCommitFiles = GetAllCommitFiles(commitToReqs.Keys);
            var fileToReqs = BuildFileToRequirementsMap(commitToReqs, allCommitFiles);
            var methodToReqs = BuildMethodToRequirementsMap(commitToReqs, allCommitFiles);

            var analysis = new AnalysisResult
            {
                CommitToRequirements = commitToReqs,
                FileToRequirements = fileToReqs,
                MethodToRequirements = methodToReqs,
                AnalysisDate = DateTime.Now,
                RepositoryPath = Directory.GetCurrentDirectory()
            };

            DisplayAnalysis(analysis);
            ExportResults(analysis);
        }

        private void AnalyzeRequirement(string requirementId)
        {
            requirementId ??= _config.DefaultRequirementId;

            _logger.Info($"Analyzing requirement: {requirementId}");

            var commits = GetCommitsForRequirement(requirementId);
            if (commits.Count == 0)
            {
                _logger.Warning($"No commits found for {requirementId}");
                return;
            }

            var files = GetAffectedFiles(commits);
            var methods = GetAffectedMethods(commits);
            var dependencies = AnalyzeDependencies(files);

            var impact = new RequirementImpact
            {
                RequirementId = requirementId,
                CommitCount = commits.Count,
                AffectedFiles = files,
                AffectedMethods = methods,
                Dependencies = dependencies,
                RiskScore = CalculateRiskScore(files, methods, dependencies)
            };

            DisplayRequirementImpact(impact);
        }

        private void AnalyzeWithRepositories(List<string> repositories, string requirementId)
        {
            _logger.Info($"Analyzing {(repositories.Count > 0 ? repositories.Count + " repositories" : "current repository")}...");

            if (repositories.Count == 0)
            {
                repositories.Add(Directory.GetCurrentDirectory());
            }

            var allAnalysisResults = new List<AnalysisResult>();
            var originalDirectory = Directory.GetCurrentDirectory();


            try
            {
                foreach (var repo in repositories)
                {
                    _logger.Info($"Processing repository: {repo}");

                    if (IsRepositoryUrl(repo))
                    {
                        var (repoUrl, branchName) = ParseRepositoryUrl(repo);
                        var tempDir = CloneRepository(repoUrl, branchName);

                        if (string.IsNullOrEmpty(tempDir))
                        {
                            _logger.Warning($"Failed to clone repository: {repo}");
                            continue;
                        }
                        Directory.SetCurrentDirectory(tempDir);
                    }
                    else if (Directory.Exists(repo))
                    {
                        Directory.SetCurrentDirectory(repo);
                    }
                    else
                    {
                        _logger.Warning($"Repository not found: {repo}");
                        continue;
                    }

                    if (string.IsNullOrEmpty(requirementId))
                    {
                        _logger.Info("Performing complete analysis (no requirement ID specified)...");
                        var analysis = PerformCompleteAnalysis();
                        allAnalysisResults.Add(analysis);
                    }
                    else
                    {
                        var _currentDirectory = Directory.GetCurrentDirectory();
                        var analysis = AnalyzeRequirementInRepository(requirementId, _currentDirectory);
                        if (analysis != null)
                        {
                            allAnalysisResults.Add(analysis);
                        }
                    }
                }

                if (allAnalysisResults.Count > 0)
                {
                    var mergedAnalysis = MergeAnalysisResults(allAnalysisResults);
                    DisplayAnalysis(mergedAnalysis);
                    ExportResults(mergedAnalysis);
                }
                else
                {
                    _logger.Warning("No analysis results to display");
                }
            }
            finally
            {
                Directory.SetCurrentDirectory(originalDirectory);
            }
        }

        private bool IsRepositoryUrl(string repository)
        {
            return repository.StartsWith("http://") ||
                   repository.StartsWith("https://") ||
                   repository.StartsWith("git@") ||
                   repository.EndsWith(".git");
        }

        /// <summary>
        /// Extracts repository URL and branch name from repository input.
        /// Supports formats like:
        /// - https://github.com/user/repo/tree/develop
        /// - https://gitlab.com/group/project/-/tree/develop
        /// - https://gitlab.com/group/project/-/tree/develop?ref_type=heads
        /// - https://github.com/user/repo.git
        /// - git@github.com:user/repo.git
        /// </summary>
        private (string repositoryUrl, string branchName) ParseRepositoryUrl(string repositoryInput)
        {
            string repositoryUrl = repositoryInput;
            string branchName = null;

            // Handle GitHub tree URLs: https://github.com/user/repo/tree/branch-name
            var githubTreeMatch = Regex.Match(repositoryInput, @"(https?://github\.com/[^/]+/[^/]+)/tree/(.+?)(?:\?|$)");
            if (githubTreeMatch.Success)
            {
                repositoryUrl = githubTreeMatch.Groups[1].Value + ".git";
                branchName = githubTreeMatch.Groups[2].Value;
                return (repositoryUrl, branchName);
            }

            // Handle GitLab tree URLs: https://gitlab.com/group/project/-/tree/branch-name
            var gitlabTreeMatch = Regex.Match(repositoryInput, @"(https?://[^/]+/[^/]+/[^/]+)/-/tree/(.+?)(?:\?|$)");
            if (gitlabTreeMatch.Success)
            {
                repositoryUrl = gitlabTreeMatch.Groups[1].Value + ".git";
                branchName = gitlabTreeMatch.Groups[2].Value;
                return (repositoryUrl, branchName);
            }

            // Handle git SSH URLs with branch (if specified with #): git@github.com:user/repo.git#branch-name
            var sshBranchMatch = Regex.Match(repositoryInput, @"(git@.+\.git)#(.+)");
            if (sshBranchMatch.Success)
            {
                repositoryUrl = sshBranchMatch.Groups[1].Value;
                branchName = sshBranchMatch.Groups[2].Value;
                return (repositoryUrl, branchName);
            }

            // Handle https URLs with branch (if specified with #): https://github.com/user/repo.git#branch-name
            var httpsBranchMatch = Regex.Match(repositoryInput, @"(https?://.+\.git)#(.+)");
            if (httpsBranchMatch.Success)
            {
                repositoryUrl = httpsBranchMatch.Groups[1].Value;
                branchName = httpsBranchMatch.Groups[2].Value;
                return (repositoryUrl, branchName);
            }

            // Handle Bitbucket URLs: https://bitbucket.org/owner/repo/src/branch
            var bitbucketMatch = Regex.Match(repositoryInput, @"(https?://bitbucket\.org/[^/]+/[^/]+)/src/(.+?)(?:\?|$)");
            if (bitbucketMatch.Success)
            {
                repositoryUrl = bitbucketMatch.Groups[1].Value + ".git";
                branchName = bitbucketMatch.Groups[2].Value;
                return (repositoryUrl, branchName);
            }

            // Handle Azure DevOps URLs: https://dev.azure.com/org/project/_git/repo?version=GBbranch
            var azureMatch = Regex.Match(repositoryInput, @"(https?://dev\.azure\.com/[^/]+/[^/]+/_git/[^?]+)(?:\?version=GB(.+))?");
            if (azureMatch.Success)
            {
                repositoryUrl = azureMatch.Groups[1].Value; // Azure clone URL needs no .git suffix
                branchName = azureMatch.Groups[2].Success ? azureMatch.Groups[2].Value : null;
                return (repositoryUrl, branchName);
            }

            return (repositoryUrl, branchName);
        }

        private string CloneRepository(string repositoryUrl, string branchName = null)
        {
            try
            {
                var tempDir = Path.Combine(Path.GetTempPath(), "scalpel-" + Guid.NewGuid().ToString().Substring(0, 8));
                Directory.CreateDirectory(tempDir);

                _logger.Info($"Cloning repository to: {tempDir}");
                if (!string.IsNullOrEmpty(branchName))
                {
                    _logger.Info($"Checking out branch: {branchName}");
                }

                // Build clone command with optional branch
                var cloneArgs = branchName != null 
                    ? $"clone --branch {branchName} {repositoryUrl} {tempDir}"
                    : $"clone {repositoryUrl} {tempDir}";

                using var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "git",
                        Arguments = cloneArgs,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                process.WaitForExit();

                if (process.ExitCode == 0)
                {
                    _logger.Success($"Repository cloned successfully");
                    return tempDir;
                }
                else
                {
                    var error = process.StandardError.ReadToEnd();
                    _logger.Error($"Failed to clone repository: {error}");
                    return null;
                }
            }
            catch (Exception ex)
            {
                _logger.Error($"Exception while cloning repository: {ex.Message}");
                return null;
            }
        }

        private (string cloneUrl, string branchName) ParseGitUrl(string webUrl)
        {
            var uri = new Uri(webUrl);
            var path = uri.AbsolutePath;

            string branchName = null;
            string repoPath = path;

            // Azure DevOps: https://dev.azure.com/org/project/_git/repo?version=GBbranch
            if (uri.Host.Equals("dev.azure.com", StringComparison.OrdinalIgnoreCase) ||
                uri.Host.EndsWith(".visualstudio.com", StringComparison.OrdinalIgnoreCase))
            {
                var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
                var version = query["version"]; // e.g. "GBdevelop"
                if (!string.IsNullOrEmpty(version) && version.StartsWith("GB"))
                    branchName = version.Substring(2); // strip "GB" prefix

                // repoPath is already correct — Azure clone URL == web URL (without query)
                var cloneUrl = $"{uri.Scheme}://{uri.Host}{path}";
                return (cloneUrl, branchName);
            }

            // GitLab: /owner/repo/-/tree/branch
            var gitlabTree = path.IndexOf("/-/tree/");
            if (gitlabTree >= 0)
            {
                repoPath   = path.Substring(0, gitlabTree);
                branchName = path.Substring(gitlabTree + 8).Split('?')[0].Trim('/');
                return ($"{uri.Scheme}://{uri.Host}{repoPath}.git", branchName);
            }

            // GitHub: /owner/repo/tree/branch
            var githubTree = path.IndexOf("/tree/");
            if (githubTree >= 0)
            {
                repoPath   = path.Substring(0, githubTree);
                branchName = path.Substring(githubTree + 6).Split('?')[0].Trim('/');
                return ($"{uri.Scheme}://{uri.Host}{repoPath}.git", branchName);
            }

            // Bitbucket: /owner/repo/src/branch
            var bitbucketSrc = path.IndexOf("/src/");
            if (bitbucketSrc >= 0)
            {
                repoPath   = path.Substring(0, bitbucketSrc);
                branchName = path.Substring(bitbucketSrc + 5).Split('?')[0].Trim('/');
                return ($"{uri.Scheme}://{uri.Host}{repoPath}.git", branchName);
            }

            // No branch segment found — clone default branch
            return ($"{uri.Scheme}://{uri.Host}{repoPath}.git", null);
        }

        private AnalysisResult PerformCompleteAnalysis()
        {
            _logger.Info("Starting comprehensive repository analysis...");

            var commitToReqs = BuildCommitToRequirementsMap();
            var allCommitFiles = GetAllCommitFiles(commitToReqs.Keys);
            var fileToReqs = BuildFileToRequirementsMap(commitToReqs, allCommitFiles);
            var methodToReqs = BuildMethodToRequirementsMap(commitToReqs, allCommitFiles);

            var analysis = new AnalysisResult
            {
                CommitToRequirements = commitToReqs,
                FileToRequirements = fileToReqs,
                MethodToRequirements = methodToReqs,
                AnalysisDate = DateTime.Now,
                RepositoryPath = Directory.GetCurrentDirectory()
            };

            return analysis;
        }

        private AnalysisResult AnalyzeRequirementInRepository(string requirementId, string repositoryPath = null)
        {
            _logger.Info($"Analyzing requirement: {requirementId}");

            var commits = GetCommitsForRequirement(requirementId, repositoryPath);
            if (commits.Count == 0)
            {
                _logger.Warning($"No commits found for {requirementId}");
                return null;
            }

            var commitToReqs = BuildCommitToRequirementsMap();
            _logger.Info($"[MERGE] Full commitToReqs: {commitToReqs.Count} commits");
            foreach (var kvp in commitToReqs.Take(5))
            {
                _logger.Debug($"[MERGE]   Commit: {kvp.Key} => {string.Join(", ", kvp.Value)}");
            }
            
            // Build COMPLETE mappings with ALL commits (to show all requirements per file/method)
            var allCommitFiles = GetAllCommitFiles(commitToReqs.Keys);
            _logger.Info($"[MERGE] All commit files: {allCommitFiles.Count} commits with files");
            var completeFileToReqs = BuildFileToRequirementsMap(commitToReqs, allCommitFiles);
            _logger.Info($"[MERGE] Complete files: {completeFileToReqs.Count} files");
            var completeMethodToReqs = BuildMethodToRequirementsMap(commitToReqs, allCommitFiles);
            _logger.Info($"[MERGE] Complete methods: {completeMethodToReqs.Count} methods");
            
            // Filter commits to only those containing the specific requirement ID (for tracking changes)
            var filteredCommitToReqs = commitToReqs.Where(c => c.Value.Contains(requirementId))
                .ToDictionary(x => x.Key, x => x.Value);
            _logger.Info($"[MERGE] Filtering for '{requirementId}'...");
            _logger.Debug($"[MERGE]   Checking {commitToReqs.Count} commits for requirement '{requirementId}'");
            foreach (var kvp in commitToReqs)
            {
                bool hasReq = kvp.Value.Contains(requirementId);
                _logger.Debug($"[MERGE]   Commit {kvp.Key.Substring(0, 8)}: {string.Join(", ", kvp.Value)} - Match: {hasReq}");
            }
            _logger.Info($"[MERGE] Filtered commitToReqs: {filteredCommitToReqs.Count} commits");
            
            var filteredCommitFiles = GetAllCommitFiles(filteredCommitToReqs.Keys);
            _logger.Info($"[MERGE] Filtered commit files: {filteredCommitFiles.Count} commits with files");
            var filteredFileToReqs = BuildFileToRequirementsMap(filteredCommitToReqs, filteredCommitFiles);
            _logger.Info($"[MERGE] Filtered files: {filteredFileToReqs.Count} files");
            var filteredMethodToReqs = BuildMethodToRequirementsMap(filteredCommitToReqs, filteredCommitFiles);
            _logger.Info($"[MERGE] Filtered methods: {filteredMethodToReqs.Count} methods");
            
            // Merge: Use files/methods from filteredMapping, but Requirements from completeMapping
            var mergedFileToReqs = new Dictionary<string, HashSet<string>>();
            foreach (var file in filteredFileToReqs)
            {
                // Include file if it was affected by the specific requirement
                if (completeFileToReqs.ContainsKey(file.Key))
                {
                    mergedFileToReqs[file.Key] = new HashSet<string>(completeFileToReqs[file.Key]);
                    _logger.Debug($"[MERGE] File {file.Key}: merged requirements {string.Join(", ", completeFileToReqs[file.Key])}");
                }
            }
            
            var mergedMethodToReqs = new Dictionary<string, MethodInfo>();
            foreach (var method in filteredMethodToReqs)
            {
                // Include method if it was affected by the specific requirement
                if (completeMethodToReqs.ContainsKey(method.Key))
                {
                    var completeMethod = completeMethodToReqs[method.Key];
                    var methodInfo = new MethodInfo
                    {
                        FilePath = method.Value.FilePath,
                        MethodName = method.Value.MethodName,
                        Requirements = new HashSet<string>(completeMethod.Requirements),  // All requirements from complete mapping
                        ChangeCount = method.Value.ChangeCount,  // Change count for specific requirement
                        LineStart = method.Value.LineStart,  // Line ranges for specific requirement
                        LineEnd = method.Value.LineEnd
                    };
                    mergedMethodToReqs[method.Key] = methodInfo;
                    _logger.Debug($"[MERGE] Method {method.Key}: merged requirements {string.Join(", ", completeMethod.Requirements)}");
                }
            }

            _logger.Info($"[MERGE] Final merged result: {mergedFileToReqs.Count} files, {mergedMethodToReqs.Count} methods");

            var analysis = new AnalysisResult
            {
                CommitToRequirements = filteredCommitToReqs,  // Keep filtered for scoped view in reports
                FileToRequirements = mergedFileToReqs,
                MethodToRequirements = mergedMethodToReqs,
                AnalysisDate = DateTime.Now,
                RepositoryPath = Directory.GetCurrentDirectory(),
                FilteredByRequirementId = requirementId
            };

            return analysis;
        }

        private void AnalyzeWithRepositoriesAndPM(List<string> repositories, string requirementId)
        {
            try
            {
                Task.Run(async () => await AnalyzeWithRepositoriesAndPMAsync(repositories, requirementId)).Wait();
            }
            catch (Exception ex)
            {
                _logger.Error($"Error during PM-enriched analysis: {ex.Message}");
            }
        }

        private async Task AnalyzeWithRepositoriesAndPMAsync(List<string> repositories, string requirementId)
        {
            _logger.Info($"Analyzing {(repositories.Count > 0 ? repositories.Count + " repositories" : "current repository")} with PM integration...");

            if (repositories.Count == 0)
            {
                repositories.Add(Directory.GetCurrentDirectory());
            }

            var allAnalysisResults = new List<AnalysisResult>();
            var originalDirectory = Directory.GetCurrentDirectory();

            try
            {
                foreach (var repo in repositories)
                {
                    _logger.Info($"Processing repository: {repo}");

                    if (IsRepositoryUrl(repo))
                    {
                        var (repoUrl, branchName) = ParseRepositoryUrl(repo);
                        var tempDir = CloneRepository(repoUrl, branchName);
                        if (string.IsNullOrEmpty(tempDir))
                        {
                            _logger.Warning($"Failed to clone repository: {repo}");
                            continue;
                        }
                        Directory.SetCurrentDirectory(tempDir);
                    }
                    else if (Directory.Exists(repo))
                    {
                        Directory.SetCurrentDirectory(repo);
                    }
                    else
                    {
                        _logger.Warning($"Repository not found: {repo}");
                        continue;
                    }

                    if (string.IsNullOrEmpty(requirementId))
                    {
                        _logger.Info("Performing complete analysis with PM enrichment...");
                        var analysis = PerformCompleteAnalysis();
                        allAnalysisResults.Add(analysis);
                    }
                    else
                    {
                        var analysis = AnalyzeRequirementInRepository(requirementId);
                        if (analysis != null)
                        {
                            allAnalysisResults.Add(analysis);
                        }
                    }
                }

                if (allAnalysisResults.Count > 0)
                {
                    var mergedAnalysis = MergeAnalysisResults(allAnalysisResults);
                    DisplayAnalysis(mergedAnalysis);
                    await ExportResultsWithPMAsync(mergedAnalysis);
                }
                else
                {
                    _logger.Warning("No analysis results to display");
                }
            }
            finally
            {
                Directory.SetCurrentDirectory(originalDirectory);
            }
        }

        private async Task ExportResultsWithPMAsync(AnalysisResult analysis)
        {
            var outputDir = Path.GetFullPath(_config.OutputDirectory);
            Directory.CreateDirectory(outputDir);

            // Load PM configuration
            PMPlatformManager pmManager = null;
            Dictionary<string, PMTicket> ticketData = new Dictionary<string, PMTicket>();

            try
            {
                var pmConfigPath = "pm-integration.config.json";
                if (File.Exists(pmConfigPath))
                {
                    _logger.Info("Loading PM configuration...");
                    var pmConfigJson = File.ReadAllText(pmConfigPath);
                    var pmConfig = JsonSerializer.Deserialize<PMConfig>(pmConfigJson);

                    if (pmConfig?.Enabled == true)
                    {
                        // Load API tokens from environment variables if not in config
                        if (string.IsNullOrWhiteSpace(pmConfig.ApiToken))
                        {
                            pmConfig.ApiToken = pmConfig.Platform?.ToLower() switch
                            {
                                "jira" => Environment.GetEnvironmentVariable("JIRA_API_TOKEN"),
                                "clickup" => Environment.GetEnvironmentVariable("CLICKUP_API_TOKEN"),
                                "azuredevops" or "ado" => Environment.GetEnvironmentVariable("ADO_PAT"),
                                _ => null
                            };
                        }

                        if (!string.IsNullOrWhiteSpace(pmConfig.ApiToken))
                        {
                            pmManager = new PMPlatformManager(pmConfig, _logger, _config.OutputDirectory);

                            // Extract all unique requirements from analysis (CommitToRequirements, FileToRequirements, MethodToRequirements)
                            var requirements = new HashSet<string>();
                            
                            // From commit to requirements mapping
                            foreach (var reqs in analysis.CommitToRequirements.Values)
                            {
                                foreach (var req in reqs)
                                {
                                    requirements.Add(req);
                                }
                            }
                            
                            // From file to requirements mapping
                            foreach (var reqs in analysis.FileToRequirements.Values)
                            {
                                foreach (var req in reqs)
                                {
                                    requirements.Add(req);
                                }
                            }
                            
                            // From method to requirements mapping
                            if (analysis.MethodToRequirements != null)
                            {
                                foreach (var methodInfo in analysis.MethodToRequirements.Values)
                                {
                                    if (methodInfo?.Requirements != null)
                                    {
                                        foreach (var req in methodInfo.Requirements)
                                        {
                                            requirements.Add(req);
                                        }
                                    }
                                }
                            }

                            if (requirements.Count > 0)
                            {
                                _logger.Info($"Fetching PM data for {requirements.Count} requirement(s)...");
                                ticketData = await pmManager.GetTicketsForRequirementsAsync(requirements);
                                _logger.Success($"Retrieved PM data for {ticketData.Count} ticket(s)");
                            }
                        }
                        else
                        {
                            _logger.Warning("PM integration enabled but no API token found");
                        }
                    }
                    else
                    {
                        _logger.Info("PM integration is disabled in configuration");
                    }
                }
                else
                {
                    _logger.Info("No PM configuration file found (pm-integration.config.json)");
                }
            }
            catch (Exception ex)
            {
                _logger.Warning($"Failed to initialize PM integration: {ex.Message}");
            }

            // Export reports with PM data
            ExportToJson(analysis, outputDir);
            ExportToHtmlWithPM(analysis, outputDir, ticketData);
            ExportToMarkdown(analysis, outputDir);

            _logger.Success($"Reports exported to: {outputDir}");
        }

        private async Task<Dictionary<string, PMTicket>> FetchPMDataForPlatformAsync(AnalysisResult analysis, string pmPlatform)
        {
            var ticketData = new Dictionary<string, PMTicket>();

            try
            {
                var pmConfigPath = "pm-integration.config.json";
                if (!File.Exists(pmConfigPath))
                {
                    _logger.Warning($"PM configuration file not found: {pmConfigPath}");
                    return ticketData;
                }

                var pmConfigJson = File.ReadAllText(pmConfigPath);
                // Parse JSON to access _platforms object
                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                using var document = JsonDocument.Parse(pmConfigJson);
                var root = document.RootElement;

                // Extract _platforms object from JSON
                if (!root.TryGetProperty("_platforms", out var platformsElement))
                {
                    _logger.Warning("No _platforms configuration found in pm-integration.config.json");
                    return ticketData;
                }

                // Normalize the requested platform name for lookup (handles aliases like "ado" -> "azuredevops")
                var requestedPlatformNormalized = NormalizePlatformName(pmPlatform);

                // Search through _platforms to find matching platform configuration
                PMConfig pmConfig = null;
                foreach (var platformProperty in platformsElement.EnumerateObject())
                {
                    var platformJson = platformProperty.Value.GetRawText();
                    var tempConfig = JsonSerializer.Deserialize<PMConfig>(platformJson, options);
                    
                    // Match platform using normalized name (e.g., "ado" matches "azuredevops")
                    if (tempConfig != null && NormalizePlatformName(tempConfig.Platform) == requestedPlatformNormalized)
                    {
                        pmConfig = tempConfig;
                        break;
                    }
                }
                
                // Platform configuration not found in _platforms
                if (pmConfig == null)
                {
                    _logger.Warning($"PM platform '{pmPlatform}' not found in _platforms configuration");
                    return ticketData;
                }

                // var pmConfig = JsonSerializer.Deserialize<PMConfig>(pmConfigJson);

                if (pmConfig == null)
                {
                    _logger.Warning("Failed to deserialize PM configuration");
                    return ticketData;
                }

                // Only use config if platform matches
                if (pmConfig.Platform?.ToLower() != pmPlatform?.ToLower())
                {
                    _logger.Warning($"PM platform mismatch. Config has '{pmConfig.Platform}' but requested '{pmPlatform}'");
                    return ticketData;
                }

                // Load API token from environment variable if not in config
                if (string.IsNullOrWhiteSpace(pmConfig.ApiToken))
                {
                    pmConfig.ApiToken = pmPlatform?.ToLower() switch
                    {
                        "jira" => Environment.GetEnvironmentVariable("JIRA_API_TOKEN"),
                        "clickup" => Environment.GetEnvironmentVariable("CLICKUP_API_TOKEN"),
                        "azuredevops" or "ado" => Environment.GetEnvironmentVariable("ADO_PAT"),
                        _ => null
                    };
                }

                if (string.IsNullOrWhiteSpace(pmConfig.ApiToken))
                {
                    _logger.Warning($"No API token found for platform: {pmPlatform}");
                    return ticketData;
                }

                var outputDir = Path.GetFullPath(_config.OutputDirectory);
                var pmManager = new PMPlatformManager(pmConfig, _logger, outputDir);

                // Extract all unique requirements from analysis (CommitToRequirements, FileToRequirements, MethodToRequirements)
                var requirements = new HashSet<string>();
                
                // From commit to requirements mapping
                foreach (var reqs in analysis.CommitToRequirements.Values)
                {
                    foreach (var req in reqs)
                    {
                        requirements.Add(req);
                    }
                }
                
                // From file to requirements mapping
                foreach (var reqs in analysis.FileToRequirements.Values)
                {
                    foreach (var req in reqs)
                    {
                        requirements.Add(req);
                    }
                }
                
                // From method to requirements mapping
                if (analysis.MethodToRequirements != null)
                {
                    foreach (var methodInfo in analysis.MethodToRequirements.Values)
                    {
                        if (methodInfo?.Requirements != null)
                        {
                            foreach (var req in methodInfo.Requirements)
                            {
                                requirements.Add(req);
                            }
                        }
                    }
                }

                if (requirements.Count > 0)
                {
                    _logger.Info($"Fetching PM data from {pmPlatform} for {requirements.Count} requirement(s)...");
                    ticketData = await pmManager.GetTicketsForRequirementsAsync(requirements);
                    _logger.Success($"Retrieved PM data for {ticketData.Count} ticket(s) from {pmPlatform}");
                }
            }
            catch (Exception ex)
            {
                _logger.Warning($"Failed to fetch PM data for platform {pmPlatform}: {ex.Message}");
            }

            return ticketData;
        }

        
        // Helper method to normalize platform names
        // Handles aliases: "ado" -> "azuredevops"
        private string NormalizePlatformName(string? platform)
        {
            return platform?.ToLower() switch
            {
                "ado" => "azuredevops",
                "jira" => "jira",
                "clickup" => "clickup",
                "azuredevops" => "azuredevops",
                _ => platform?.ToLower() ?? ""
            };
        }

        private void ExportToHtmlWithPM(AnalysisResult analysis, string outputDir, Dictionary<string, PMTicket> ticketData)
        {
            var html = _reportService.GenerateHtmlReport(analysis, ticketData);
            var path = Path.Combine(outputDir, "traceability-report.html");
            File.WriteAllText(path, html);
            _logger.Success($"HTML report: {path}");
        }

        public AnalysisResult AnalyzeRepositoriesForApi(List<string> repositories, string requirementId, string requirementPattern = null)
        {
            _logger.Info($"API: Analyzing {(repositories?.Count > 0 ? repositories.Count + " repositories" : "current repository")}...");

            if (repositories == null || repositories.Count == 0)
            {
                repositories = new List<string> { Directory.GetCurrentDirectory() };
            }

            var allAnalysisResults = new List<AnalysisResult>();
            var originalDirectory = Directory.GetCurrentDirectory();
            var originalPattern = _config.RequirementPattern;

            if (!string.IsNullOrWhiteSpace(requirementPattern))
            {
                _logger.Info($"Using override requirement pattern: {requirementPattern}");
                Console.WriteLine($"⚙️  Using override requirement pattern: {requirementPattern}");
                _config.RequirementPattern = requirementPattern;
            }
            Console.WriteLine($"🔍 Analyzing repositories: {string.Join(", ", repositories)} for requirement ID: {requirementId ?? "N/A"} with pattern: {_config.RequirementPattern}");
            _logger.Info($"Request requirement pattern: {requirementPattern}");

            try
            {
                foreach (var repo in repositories)
                {
                    _logger.Info($"Processing repository: {repo}");
                    if (IsRepositoryUrl(repo))
                    {
                        var (repoUrl, branchName) = ParseRepositoryUrl(repo);
                        var tempDir = CloneRepository(repoUrl, branchName);
                        if (string.IsNullOrEmpty(tempDir))
                        {
                            _logger.Warning($"Failed to clone repository: {repo}");
                            continue;
                        }
                        Directory.SetCurrentDirectory(tempDir);
                    }
                    else if (Directory.Exists(repo))
                    {
                        Directory.SetCurrentDirectory(repo);
                    }
                    else
                    {
                        _logger.Warning($"Repository not found: {repo}");
                        continue;
                    }

                    if (string.IsNullOrEmpty(requirementId))
                    {
                        var analysis = PerformCompleteAnalysis();
                        allAnalysisResults.Add(analysis);
                    }
                    else
                    {
                        var analysis = AnalyzeRequirementInRepository(requirementId);
                        if (analysis != null) allAnalysisResults.Add(analysis);
                    }
                }

                if (allAnalysisResults.Count > 0)
                {
                    return MergeAnalysisResults(allAnalysisResults);
                }

                return new AnalysisResult
                {
                    CommitToRequirements = new Dictionary<string, List<string>>(),
                    FileToRequirements = new Dictionary<string, HashSet<string>>(),
                    MethodToRequirements = new Dictionary<string, MethodInfo>(),
                    AnalysisDate = DateTime.Now,
                    RepositoryPath = Directory.GetCurrentDirectory(),
                    RepositoryPaths = repositories
                };
            }
            finally
            {
                // restore working directory and pattern
                Directory.SetCurrentDirectory(originalDirectory);
                if (!string.IsNullOrWhiteSpace(requirementPattern))
                {
                    _config.RequirementPattern = originalPattern;
                }
            }
        }

        public void StartWebHost()
        {
            // Intelligently find wwwroot directory to work both with `dotnet run` and compiled exe
            string contentRoot;
            string webRoot;
            
            // First, try current working directory (when running with dotnet run from project root)
            var cwd = Directory.GetCurrentDirectory();
            var wwwrootInCwd = Path.Combine(cwd, "wwwroot");
            
            if (Directory.Exists(wwwrootInCwd))
            {
                contentRoot = cwd;
                webRoot = wwwrootInCwd;
            }
            else
            {
                // Fallback: navigate from assembly location (when running as exe from bin directory)
                var exePath = AppContext.BaseDirectory;
                // Navigate up from bin/Debug/net8/ (or bin/Release/net8/) to project root
                var projectRoot = Path.GetFullPath(Path.Combine(exePath, "..", "..", ".."));
                contentRoot = projectRoot;
                webRoot = Path.Combine(projectRoot, "wwwroot");
            }
            
            // Create builder with web root specified at initialization time (required in .NET 8)
            var options = new WebApplicationOptions
            {
                ApplicationName = "EnterpriseScalpel",
                ContentRootPath = contentRoot,
                WebRootPath = webRoot
            };
            
            var builder = WebApplication.CreateBuilder(options);
            var app = builder.Build();

            app.UseDefaultFiles();
            app.UseStaticFiles();

            app.MapPost("/api/generate-report", async (HttpContext ctx) =>
            {
                try
                {
                    var request = await JsonSerializer.DeserializeAsync<GenerateRequest>(ctx.Request.Body);
                    request ??= new GenerateRequest();

                    var repos = request.Repositories ?? new List<string>();
                    var reqId = request.RequirementIds?.FirstOrDefault();

                    var analysis = AnalyzeRepositoriesForApi(repos, reqId, request.RequirementPattern);
                    var format = (request.Format ?? "json").ToLower();

                    // Fetch PM data if platform specified
                    Dictionary<string, PMTicket> ticketData = new Dictionary<string, PMTicket>();
                    if (!string.IsNullOrWhiteSpace(request.PmPlatform))
                    {
                        ticketData = await FetchPMDataForPlatformAsync(analysis, request.PmPlatform);
                    }

                    if (format == "json")
                    {
                        var json = SerializeAnalysisToJsonString(analysis);
                        ctx.Response.ContentType = "application/json";
                        await ctx.Response.WriteAsync(json);
                        return;
                    }
                    else if (format == "html")
                    {
                        var html = _reportService.GenerateHtmlReport(analysis, ticketData.Count > 0 ? ticketData : null);
                        ctx.Response.ContentType = "text/html";
                        ctx.Response.Headers["Content-Disposition"] = "attachment; filename=traceability-report.html";
                        await ctx.Response.WriteAsync(html);
                        return;
                    }
                    else if (format == "csv")
                    {
                        var csv = GenerateCsvFromAnalysis(analysis);
                        ctx.Response.ContentType = "text/csv";
                        ctx.Response.Headers["Content-Disposition"] = "attachment; filename=traceability-report.csv";
                        await ctx.Response.WriteAsync(csv);
                        return;
                    }

                    ctx.Response.StatusCode = 400;
                    await ctx.Response.WriteAsync("Unknown format");
                }
                catch (Exception ex)
                {
                    _logger.Error($"API error: {ex.Message}");
                    ctx.Response.StatusCode = 500;
                    await ctx.Response.WriteAsync("Server error");
                }
            });

            app.MapGet("/api/health", () => Results.Json(new { status = "ok" }));

            var port = 5001;
            _logger.Info($"Starting web server on http://localhost:{port}");
            _logger.Info($"Content root: {contentRoot}");
            _logger.Info($"Static files from: {Path.Combine(contentRoot, "wwwroot")}");
            
            try
            {
                app.Run($"http://0.0.0.0:{port}");
            }
            catch (Exception ex)
            {
                _logger.Error($"Failed to start web server: {ex.Message}");
                if (ex.Message.Contains("Address already in use"))
                {
                    _logger.Info("Port 5001 is already in use. Make sure you killed the previous instance.");
                }
                throw;
            }
        }

        private string SerializeAnalysisToJsonString(AnalysisResult analysis)
        {
            return JsonSerializer.Serialize(analysis, new JsonSerializerOptions { WriteIndented = true });
        }

        private string GenerateCsvFromAnalysis(AnalysisResult analysis)
        {
            var csv = new System.Text.StringBuilder();
            csv.AppendLine("File,Requirements,Risk Level,Change Count");

            foreach (var entry in analysis.FileToRequirements.OrderByDescending(f => f.Value.Count))
            {
                var reqs = string.Join(";", entry.Value);
                var riskLevel = GetRiskLevel(entry.Value.Count);
                csv.AppendLine($"\"{entry.Key}\",\"{reqs}\",\"{riskLevel}\",{entry.Value.Count}");
            }

            return csv.ToString();
        }

        private AnalysisResult MergeAnalysisResults(List<AnalysisResult> results)
        {
            var mergedAnalysis = new AnalysisResult
            {
                CommitToRequirements = new Dictionary<string, List<string>>(),
                FileToRequirements = new Dictionary<string, HashSet<string>>(),
                MethodToRequirements = new Dictionary<string, MethodInfo>(),
                AnalysisDate = DateTime.Now,
                RepositoryPaths = results.Select(r => r.RepositoryPath).ToList()
            };

            foreach (var result in results)
            {
                var repoPrefix = Path.GetFileName(result.RepositoryPath) ?? "repo";
                foreach (var (commit, reqs) in result.CommitToRequirements)
                {
                    var key = $"{repoPrefix}:{commit}";
                    mergedAnalysis.CommitToRequirements[key] = reqs;
                }

                foreach (var (file, reqs) in result.FileToRequirements)
                {
                    var key = $"{repoPrefix}/{file}";
                    if (!mergedAnalysis.FileToRequirements.ContainsKey(key))
                    {
                        mergedAnalysis.FileToRequirements[key] = new HashSet<string>();
                    }
                    foreach (var req in reqs)
                    {
                        mergedAnalysis.FileToRequirements[key].Add(req);
                    }
                }

                foreach (var (method, info) in (result.MethodToRequirements ?? new Dictionary<string, MethodInfo>()))
                {
                    var key = $"{repoPrefix}/{info.FilePath}::{info.MethodName}";
                    if (!mergedAnalysis.MethodToRequirements.ContainsKey(key))
                    {
                        var newInfo = (MethodInfo)info.Clone();
                        newInfo.FilePath = $"{repoPrefix}/{info.FilePath}";
                        mergedAnalysis.MethodToRequirements[key] = newInfo;
                    }
                }
            }

            return mergedAnalysis;
        }

        private void AnalyzeFileImpact(string filePath)
        {
            _logger.Info($"Analyzing impact of: {filePath}");

            var requirements = GetRequirementsForFile(filePath);
            var dependentFiles = GetDependentFiles(filePath);
            var consumers = GetFileConsumers(filePath);

            Console.WriteLine($"\n📄 File: {filePath}");
            Console.WriteLine($"   Requirements: {string.Join(", ", requirements)}");
            Console.WriteLine($"   Risk Level: {GetRiskLevel(requirements.Count)}");
            Console.WriteLine($"\n   Dependent Files ({dependentFiles.Count}):");
            foreach (var dep in dependentFiles.Take(10))
            {
                Console.WriteLine($"   - {dep}");
            }

            if (dependentFiles.Count > 10)
            {
                Console.WriteLine($"   ... and {dependentFiles.Count - 10} more");
            }
        }

        private void FindHotspots()
        {
            _logger.Info("Finding code hotspots...");

            var fileChangeFrequency = GetFileChangeFrequency();
            var complexity = AnalyzeComplexity();

            var hotspots = fileChangeFrequency
                .Join(complexity,
                    f => f.Key,
                    c => c.Key,
                    (f, c) => new Hotspot
                    {
                        FilePath = f.Key,
                        ChangeFrequency = f.Value,
                        Complexity = c.Value,
                        HotspotScore = f.Value * c.Value
                    })
                .OrderByDescending(h => h.HotspotScore)
                .Take(20)
                .ToList();

            Console.WriteLine("\n🔥 Code Hotspots (High Change + High Complexity):");
            Console.WriteLine("─────────────────────────────────────────────────");
            foreach (var hotspot in hotspots)
            {
                Console.WriteLine($"{hotspot.FilePath}");
                Console.WriteLine($"  Changes: {hotspot.ChangeFrequency} | Complexity: {hotspot.Complexity} | Score: {hotspot.HotspotScore:F2}");
            }
        }

        private void GenerateReport(string format)
        {
            _logger.Info($"Generating {format} report...");

            var analysis = new AnalysisResult
            {
                CommitToRequirements = BuildCommitToRequirementsMap(),
                FileToRequirements = BuildFileToRequirementsMap(null),
                AnalysisDate = DateTime.Now,
                RepositoryPath = Directory.GetCurrentDirectory()
            };

            switch (format.ToLower())
            {
                case "html":
                    ExportToHtml(analysis);
                    break;
                case "json":
                    ExportToJson(analysis);
                    break;
                case "csv":
                    ExportToCsv(analysis);
                    break;
                case "markdown":
                    ExportToMarkdown(analysis);
                    break;
                default:
                    _logger.Error($"Unknown format: {format}");
                    break;
            }
        }

        private Dictionary<string, List<string>> BuildCommitToRequirementsMap()
        {
            _logger.Info("🔍 [C2R] Starting BuildCommitToRequirementsMap...");
            var logLines = RunGitCommand("log --pretty=format:\"%H %s\" --all --no-merges");
            if (string.IsNullOrWhiteSpace(logLines))
            {
                _logger.Warning("⚠️ [C2R] No commits found in repository");
                return new Dictionary<string, List<string>>();
            }

            var lines = logLines.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
            _logger.Info($"📊 [C2R] Found {lines.Length} commit log lines to process");
            var commitToRequirements = new Dictionary<string, List<string>>();

            foreach (var line in lines)
            {
                var matches = _config.RequirementRegex.Matches(line);
                if (matches.Count == 0)
                {
                    _logger.Debug($"[C2R] No requirements found in: {line.Substring(0, Math.Min(60, line.Length))}");
                    continue;
                }
                if (line.Length < 40)
                {
                    _logger.Warning($"⚠️ [C2R] Line too short (<40 chars), skipping: {line}");
                    continue;
                }

                var commitHash = line.Substring(0, 40);
                var requirements = matches.Select(m => m.Value).Distinct().ToList();
                commitToRequirements[commitHash] = requirements;
                _logger.Debug($"✓ [C2R] Commit {commitHash.Substring(0, 8)}... -> {string.Join(", ", requirements)}");
            }

            _logger.Info($"✅ [C2R] Complete: {commitToRequirements.Count} commits with requirements");
            return commitToRequirements;
        }

        private List<string> GetCommitsForRequirement(string requirementId, string repositoryPath = null)
        {
            var output = RunGitCommand($"log --grep={requirementId} --oneline --no-merges", repositoryPath);
            return string.IsNullOrWhiteSpace(output)
                ? new List<string>()
                : output.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries).ToList();
        }

        private HashSet<string> GetAffectedFiles(List<string> commits)
        {
            var files = new HashSet<string>();
            foreach (var commit in commits)
            {
                var hash = commit.Split(' ')[0];
                var changedFiles = GetFilesChangedInCommit(hash);
                foreach (var file in changedFiles)
                {
                    files.Add(file);
                }
            }
            return files;
        }

        private HashSet<string> GetAffectedMethods(List<string> commits)
        {
            var methods = new HashSet<string>();
            return methods;
        }

        private List<string> AnalyzeDependencies(HashSet<string> files)
        {
            var dependencies = new List<string>();
            return dependencies;
        }

        private double CalculateRiskScore(HashSet<string> files, HashSet<string> methods, List<string> dependencies)
        {
            double fileScore = files.Count * 0.3;
            double methodScore = methods.Count * 0.2;
            double dependencyScore = dependencies.Count * 0.5;

            return Math.Min(fileScore + methodScore + dependencyScore, 100);
        }

        private HashSet<string> GetRequirementsForFile(string filePath)
        {
            var fileToReqs = BuildFileToRequirementsMap(null);
            return fileToReqs.ContainsKey(filePath) ? fileToReqs[filePath] : new HashSet<string>();
        }

        private List<string> GetDependentFiles(string filePath)
        {
            return new List<string>();
        }

        private List<string> GetFileConsumers(string filePath)
        {
            return new List<string>();
        }

        private Dictionary<string, int> GetFileChangeFrequency()
        {
            var output = RunGitCommand("log --name-only --pretty=format:");
            var files = output.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);

            return files
                .GroupBy(f => f.Trim())
                .Where(g => !string.IsNullOrWhiteSpace(g.Key))
                .ToDictionary(g => g.Key, g => g.Count());
        }

        private Dictionary<string, int> AnalyzeComplexity()
        {
            var complexity = new Dictionary<string, int>();

            var csFiles = Directory.GetFiles(Directory.GetCurrentDirectory(), "*.cs", SearchOption.AllDirectories);

            foreach (var file in csFiles)
            {
                try
                {
                    var code = File.ReadAllText(file);
                    var tree = CSharpSyntaxTree.ParseText(code);
                    var root = tree.GetRoot();

                    var methodCount = root.DescendantNodes().OfType<MethodDeclarationSyntax>().Count();
                    var classCount = root.DescendantNodes().OfType<ClassDeclarationSyntax>().Count();
                    var ifCount = root.DescendantNodes().OfType<IfStatementSyntax>().Count();
                    var loopCount = root.DescendantNodes().OfType<ForStatementSyntax>().Count() +
                                   root.DescendantNodes().OfType<WhileStatementSyntax>().Count();

                    var relativePath = Path.GetRelativePath(Directory.GetCurrentDirectory(), file);
                    complexity[relativePath] = methodCount + classCount + ifCount + loopCount;
                }
                catch
                {
                }
            }

            return complexity;
        }

        private string GetRiskLevel(int requirementCount)
        {
            return requirementCount switch
            {
                0 => "⚪ None",
                1 => "🟢 Low",
                2 or 3 => "🟡 Medium",
                4 or 5 => "🟠 High",
                _ => "🔴 Critical"
            };
        }

        private void DisplayAnalysis(AnalysisResult analysis)
        {
            Console.WriteLine("\n╔═══════════════════════════════════════════════╗");
            Console.WriteLine("║     REQUIREMENT TRACEABILITY ANALYSIS         ║");
            Console.WriteLine("╚═══════════════════════════════════════════════╝");

            Console.WriteLine($"\n📊 Summary:");
            Console.WriteLine($"   Total Commits with Requirements: {analysis.CommitToRequirements.Count}");
            Console.WriteLine($"   Total Files Affected: {analysis.FileToRequirements.Count}");
            Console.WriteLine($"   Total Methods Tracked: {analysis.MethodToRequirements?.Count ?? 0}");

            var entangled = analysis.FileToRequirements.Where(f => f.Value.Count > 1).ToList();
            Console.WriteLine($"   High-Risk Files (multiple requirements): {entangled.Count}");

            if (entangled.Any())
            {
                Console.WriteLine("\n⚠️  Top 10 Entangled Files:");
                foreach (var file in entangled.OrderByDescending(f => f.Value.Count).Take(10))
                {
                    Console.WriteLine($"   {file.Key}");
                    Console.WriteLine($"      Requirements: {string.Join(", ", file.Value)} ({file.Value.Count} reqs)");
                }
            }
        }

        private void DisplayRequirementImpact(RequirementImpact impact)
        {
            Console.WriteLine($"\n📋 Requirement: {impact.RequirementId}");
            Console.WriteLine($"   Commits: {impact.CommitCount}");
            Console.WriteLine($"   Files: {impact.AffectedFiles.Count}");
            Console.WriteLine($"   Methods: {impact.AffectedMethods.Count}");
            Console.WriteLine($"   Risk Score: {impact.RiskScore:F2}/100");
        }

        private void ExportResults(AnalysisResult analysis)
        {
            var outputDir = Path.GetFullPath(_config.OutputDirectory);
            Directory.CreateDirectory(outputDir);

            ExportToJson(analysis, outputDir);
            ExportToHtml(analysis, outputDir);
            ExportToMarkdown(analysis, outputDir);

            _logger.Success($"Reports exported to: {outputDir}");
        }

        private void ExportToJson(AnalysisResult analysis, string outputDir = "")
        {
            var json = JsonSerializer.Serialize(analysis, new JsonSerializerOptions { WriteIndented = true });
            var path = Path.Combine(outputDir, "traceability-report.json");
            File.WriteAllText(path, json);
            _logger.Success($"JSON report: {path}");
        }

        private void ExportToHtml(AnalysisResult analysis, string outputDir = "")
        {
            var html = _reportService.GenerateHtmlReport(analysis);
            var path = Path.Combine(outputDir, "traceability-report.html");
            File.WriteAllText(path, html);
            _logger.Success($"HTML report: {path}");
        }

        private void ExportToCsv(AnalysisResult analysis, string outputDir = "")
        {
            var csv = new System.Text.StringBuilder();
            csv.AppendLine("File,Requirements,Risk Level,Change Count");

            foreach (var entry in analysis.FileToRequirements.OrderByDescending(f => f.Value.Count))
            {
                var reqs = string.Join(";", entry.Value);
                var riskLevel = GetRiskLevel(entry.Value.Count);
                csv.AppendLine($"\"{entry.Key}\",\"{reqs}\",\"{riskLevel}\",{entry.Value.Count}");
            }

            var path = Path.Combine(outputDir, "traceability-report.csv");
            File.WriteAllText(path, csv.ToString());
            _logger.Success($"CSV report: {path}");
        }

        private void ExportToMarkdown(AnalysisResult analysis, string outputDir = "")
        {
            var md = new System.Text.StringBuilder();
            md.AppendLine("# Requirement Traceability Report");
            md.AppendLine($"\n**Generated:** {analysis.AnalysisDate}");
            md.AppendLine($"**Repository:** {analysis.RepositoryPath}");
            md.AppendLine("\n## Summary");
            md.AppendLine($"- Total Commits: {analysis.CommitToRequirements.Count}");
            md.AppendLine($"- Total Files: {analysis.FileToRequirements.Count}");

            md.AppendLine("\n## High-Risk Files");
            md.AppendLine("| File | Requirements | Count |");
            md.AppendLine("|------|--------------|-------|");

            foreach (var file in analysis.FileToRequirements.Where(f => f.Value.Count > 1).OrderByDescending(f => f.Value.Count))
            {
                md.AppendLine($"| {file.Key} | {string.Join(", ", file.Value)} | {file.Value.Count} |");
            }

            var path = Path.Combine(outputDir, "traceability-report.md");
            File.WriteAllText(path, md.ToString());
            _logger.Success($"Markdown report: {path}");
        }

        private string GenerateHtmlReport(AnalysisResult analysis)
        {
            return _reportService.GenerateHtmlReport(analysis);
        }

        private string GenerateBadgeHtml(List<string> reqs)
        {
            if (reqs.Count <= 3)
            {
                return string.Join("", reqs.Select(r => $"<span class='badge'>{r}</span>"));
            }

            var badgesHtml = $"<span class='badge'>{reqs[0]}</span>" +
                           $"<button class='expand-btn' onclick='expandBadges(this)'>+{reqs.Count - 1}</button>" +
                           $"<div class='expanded-badges' style='display:none'>" +
                           string.Join("", reqs.Skip(1).Select(r => $"<span class='badge'>{r}</span>")) +
                           $"</div>";
            return badgesHtml;
        }

        private int GetRiskNumericValue(int requirementCount)
        {
            return requirementCount switch
            {
                0 => 0,
                1 => 1,
                2 or 3 => 3,
                4 or 5 => 4,
                _ => 6
            };
        }

        private string[] GetFilesChangedInCommit(string commitHash)
        {
            var filesOutput = RunGitCommand($"diff-tree --no-commit-id --name-only --root -r {commitHash}");
            return filesOutput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                              .Select(f => f.Trim())
                              .Where(f => !string.IsNullOrWhiteSpace(f))
                              .ToArray();
        }

        private Dictionary<string, List<(int start, int end)>> GetChangedLineRangesByFile(string commitHash)
        {
            _logger.Debug($"[LR] Parsing line ranges for commit {commitHash.Substring(0, 8)}...");
            var diffOutput = RunGitCommand($"show {commitHash}");
            var changedLineRangesByFile = new Dictionary<string, List<(int start, int end)>>();
            string currentFile = null;
            int lineRangesFound = 0;
            var actualChangedLines = new Dictionary<string, HashSet<int>>();  // Track which lines actually have +/- in diff

            var lines = diffOutput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            _logger.Debug($"[LR] Git show output: {lines.Length} lines, {diffOutput.Length} bytes");
            
            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i];
                
                // Reset on new file section
                if (line.StartsWith("diff --git"))
                {
                    currentFile = null;
                    // Extract file path from "diff --git a/path b/path"
                    var parts = line.Split(' ');
                    if (parts.Length >= 4)
                    {
                        var aPath = parts[2].Substring(2);  // Remove 'a/' prefix
                        _logger.Debug($"[LR] New diff section for file: {aPath}");
                    }
                }
                
                // Look for +++ line which shows the file path (more reliable than diff --git line)
                // Only process changed files (with +++ line), skip deleted files (only have ---)
                if (line.StartsWith("+++ b/"))
                {
                    // Format: "+++ b/path/to/file.cs"
                    currentFile = line.Substring(6);  // Remove "+++ b/" prefix
                    // Normalize path separators to forward slashes
                    currentFile = currentFile.Replace("\\", "/");
                    if (!changedLineRangesByFile.ContainsKey(currentFile))
                    {
                        changedLineRangesByFile[currentFile] = new List<(int start, int end)>();
                        actualChangedLines[currentFile] = new HashSet<int>();
                    }
                    _logger.Debug($"[LR]   Processing file: {currentFile}");
                }
                else if (line.StartsWith("@@") && currentFile != null)
                {
                    // Format: "@@ -10,5 +15,8 @@"
                    // We want the +15,8 part (new file line numbers)
                    var match = Regex.Match(line, @"\+(\d+)(?:,(\d+))?");
                    if (match.Success)
                    {
                        int start = int.Parse(match.Groups[1].Value);
                        int length = match.Groups[2].Success ? int.Parse(match.Groups[2].Value) : 1;
                        var range = (start, start + length - 1);  // -1 because end should be inclusive
                        changedLineRangesByFile[currentFile].Add(range);
                        lineRangesFound++;
                        _logger.Debug($"[LR]     Hunk: lines {start}-{start + length - 1} (length: {length})");
                    }
                    else
                    {
                        _logger.Debug($"[LR]     WARNING: Could not parse @@ line: {line}");
                    }
                }
            }

            _logger.Debug($"[LR] Found {lineRangesFound} hunk(s) in {changedLineRangesByFile.Count} file(s)");
            foreach (var kvp in changedLineRangesByFile)
            {
                _logger.Debug($"[LR] File {kvp.Key}: {kvp.Value.Count} hunk(s) - Ranges: {string.Join(", ", kvp.Value.Select(r => $"{r.start}-{r.end}"))}");
            }
            return changedLineRangesByFile;
        }

        private List<(int start, int end)> GetChangedLineRanges(string commitHash)
        {
            var rangesByFile = GetChangedLineRangesByFile(commitHash);
            var allRanges = new List<(int start, int end)>();
            foreach (var ranges in rangesByFile.Values)
            {
                allRanges.AddRange(ranges);
            }
            return allRanges;
        }

        private IEnumerable<MethodDeclarationSyntax> GetMethodsFromFile(string filePath)
        {
            try
            {
                var code = File.ReadAllText(filePath);
                var tree = CSharpSyntaxTree.ParseText(code);
                var root = tree.GetRoot();
                return root.DescendantNodes().OfType<MethodDeclarationSyntax>();
            }
            catch
            {
                return Enumerable.Empty<MethodDeclarationSyntax>();
            }
        }

        private (int start, int end) GetMethodLineRange(MethodDeclarationSyntax method)
        {
            var span = method.SyntaxTree.GetLineSpan(method.Span);
            return (span.StartLinePosition.Line + 1, span.EndLinePosition.Line + 1);
        }

        private bool Overlaps((int start, int end) a, (int start, int end) b)
        {
            return a.start <= b.end && b.start <= a.end;
        }

        private string RunGitCommand(string arguments, string repositoryPath = null)
        {
            try
            {
                _logger.Debug($"[GIT] Running: git {arguments.Substring(0, Math.Min(80, arguments.Length))}");
                
                using var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "git",
                        Arguments = arguments,
                        WorkingDirectory = repositoryPath ?? string.Empty,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                var error = process.StandardError.ReadToEnd();
                process.WaitForExit();

                if (!string.IsNullOrWhiteSpace(error) && process.ExitCode != 0)
                {
                    _logger.Error($"[GIT] Error: {error}");
                    return output; // Return whatever output we got even if there's an error
                }

                _logger.Debug($"[GIT] Output: {output.Length} bytes, exit code: {process.ExitCode}");
                return output;
            }
            catch (Exception ex)
            {
                _logger.Error($"[GIT] Failed to run command: {ex.Message}");
                return string.Empty;
            }
        }

        private Dictionary<string, HashSet<string>> BuildFileToRequirementsMap(
            Dictionary<string, List<string>> commitToRequirements,
            Dictionary<string, string[]> allCommitFiles = null)
        {
            _logger.Info("🔍 [F2R] Starting BuildFileToRequirementsMap...");
            commitToRequirements ??= BuildCommitToRequirementsMap();
            _logger.Info($"[F2R] commitToRequirements: {commitToRequirements.Count} entries");
            
            allCommitFiles ??= GetAllCommitFiles(commitToRequirements.Keys);
            _logger.Info($"[F2R] allCommitFiles: {allCommitFiles.Count} entries");

            var fileToRequirements = new Dictionary<string, HashSet<string>>();
            int skippedCommits = 0;

            foreach (var (commitHash, requirements) in commitToRequirements)
            {
                if (!allCommitFiles.ContainsKey(commitHash))
                {
                    _logger.Warning($"⚠️ [F2R] Missing file mapping for commit {commitHash.Substring(0, 8)}...");
                    skippedCommits++;
                    continue;
                }

                var filesChanged = allCommitFiles[commitHash];
                _logger.Debug($"[F2R] Commit {commitHash.Substring(0, 8)}... + {filesChanged.Length} file(s) + {requirements.Count} req(s)");

                foreach (var file in filesChanged)
                {
                    if (!fileToRequirements.ContainsKey(file))
                    {
                        fileToRequirements[file] = new HashSet<string>();
                    }

                    foreach (var req in requirements)
                    {
                        fileToRequirements[file].Add(req);
                    }
                }
            }

            _logger.Info($"✅ [F2R] Complete: {fileToRequirements.Count} files, {skippedCommits} commits skipped (missing mapping)");
            return fileToRequirements;
        }

        private Dictionary<string, MethodInfo> BuildMethodToRequirementsMap(
            Dictionary<string, List<string>> commitToRequirements,
            Dictionary<string, string[]> allCommitFiles = null)
        {
            _logger.Info("🔍 [M2R] Starting BuildMethodToRequirementsMap...");
            allCommitFiles ??= GetAllCommitFiles(commitToRequirements.Keys);
            _logger.Info($"[M2R] Processing {commitToRequirements.Count} commits, {allCommitFiles.Count} have files");
            
            var methodToReqs = new Dictionary<string, MethodInfo>();
            int processingErrors = 0;
            int skippedCommits = 0;
            int processedFiles = 0;

            foreach (var (commitHash, requirements) in commitToRequirements)
            {
                if (!allCommitFiles.ContainsKey(commitHash))
                {
                    _logger.Warning($"⚠️ [M2R] Missing file mapping for commit {commitHash.Substring(0, 8)}...");
                    skippedCommits++;
                    continue;
                }

                var filesChanged = allCommitFiles[commitHash];
                _logger.Debug($"[M2R] Commit {commitHash.Substring(0, 8)}... has {filesChanged.Length} file(s)");
                
                var changedLineRangesByFile = GetChangedLineRangesByFile(commitHash);
                _logger.Debug($"[M2R] Got line ranges for {changedLineRangesByFile.Count} file(s)");

                foreach (var file in filesChanged.Where(f => f.EndsWith(".cs")))
                {
                    var normalizedFile = file.Replace("\\", "/");
                    var absolutePath = Path.Combine(Directory.GetCurrentDirectory(), file);
                    
                    if (!File.Exists(absolutePath))
                    {
                        _logger.Debug($"[M2R] File not found: {absolutePath}");
                        continue;
                    }

                    // Get line ranges for THIS specific file
                    var fileLineRanges = new List<(int start, int end)>();
                    
                    if (changedLineRangesByFile.ContainsKey(normalizedFile))
                    {
                        fileLineRanges = changedLineRangesByFile[normalizedFile];
                    }
                    else if (changedLineRangesByFile.ContainsKey(file))
                    {
                        fileLineRanges = changedLineRangesByFile[file];
                    }

                    if (fileLineRanges.Count == 0)
                    {
                        _logger.Debug($"[M2R] No line ranges for {file}");
                        continue;
                    }

                    processedFiles++;
                    var rangeStr = string.Join(", ", fileLineRanges.Select(r => $"{r.start}-{r.end}"));
                    _logger.Debug($"[M2R] Processing {file} with {fileLineRanges.Count} changed range(s): [{rangeStr}]");

                    try
                    {
                        var methods = GetMethodsFromFile(absolutePath);
                        _logger.Debug($"[M2R]   Found {methods.Count()} method(s)");
                        int matchCount = 0;

                        foreach (var method in methods)
                        {
                            var (methodStart, methodEnd) = GetMethodLineRange(method);

                            foreach (var change in fileLineRanges)
                            {
                                if (Overlaps((methodStart, methodEnd), change))
                                {
                                    var key = $"{file}::{method.Identifier.Text}";
                                    matchCount++;
                                    _logger.Debug($"[M2R]   ✓ Match {matchCount}: {method.Identifier.Text} (lines {methodStart}-{methodEnd}) overlaps with {change.start}-{change.end}");

                                    if (!methodToReqs.ContainsKey(key))
                                    {
                                        methodToReqs[key] = new MethodInfo
                                        {
                                            FilePath = file,
                                            MethodName = method.Identifier.Text,
                                            Requirements = new HashSet<string>(),
                                            ChangeCount = 0,
                                            LineStart = methodStart,
                                            LineEnd = methodEnd,
                                            RequirementDetails = new Dictionary<string, (int, int, int)>()
                                        };
                                    }

                                    foreach (var req in requirements)
                                    {
                                        methodToReqs[key].Requirements.Add(req);
                                        
                                        // Track per-requirement line ranges and changes
                                        if (!methodToReqs[key].RequirementDetails.ContainsKey(req))
                                        {
                                            methodToReqs[key].RequirementDetails[req] = (change.start, change.end, 1);
                                        }
                                        else
                                        {
                                            // Increment change count for this requirement
                                            var (start, end, count) = methodToReqs[key].RequirementDetails[req];
                                            methodToReqs[key].RequirementDetails[req] = (Math.Min(start, change.start), Math.Max(end, change.end), count + 1);
                                        }
                                    }
                                    methodToReqs[key].ChangeCount++;
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.Warning($"⚠️ [M2R] Error processing {file}: {ex.Message}");
                        processingErrors++;
                    }
                }
            }

            _logger.Info($"✅ [M2R] Complete: {methodToReqs.Count} methods mapped, {processedFiles} files processed, {skippedCommits} commits skipped, {processingErrors} error(s)");
            return methodToReqs;
        }

        private Dictionary<string, string[]> GetAllCommitFiles(IEnumerable<string> commitHashes)
        {
            _logger.Info("🔍 [C2F] Starting GetAllCommitFiles...");
            var result = new Dictionary<string, string[]>();
            var commitList = commitHashes.ToList();
            _logger.Info($"📊 [C2F] Processing {commitList.Count} commits");

            if (commitList.Count == 0)
            {
                _logger.Warning("⚠️ [C2F] No commits provided");
                return result;
            }

            // Process each commit individually for reliable parsing
            foreach (var commitHash in commitList)
            {
                _logger.Debug($"[C2F] Getting files for commit {commitHash.Substring(0, 8)}...");
                var output = RunGitCommand($"show --pretty=format:%H --name-only {commitHash}");

                if (string.IsNullOrWhiteSpace(output))
                {
                    _logger.Warning($"⚠️ [C2F] No output for commit {commitHash.Substring(0, 8)}...");
                    continue;
                }

                var lines = output.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                _logger.Debug($"[C2F] Got {lines.Length} lines for commit {commitHash.Substring(0, 8)}...");
                
                var files = new List<string>();

                // First line should be the commit hash from --pretty=format:%H
                // Skip it and process remaining lines as file paths
                for (int i = 1; i < lines.Length; i++)
                {
                    var trimmed = lines[i].Trim();
                    if (!string.IsNullOrWhiteSpace(trimmed))
                    {
                        files.Add(trimmed);
                        _logger.Debug($"[C2F]   File: {trimmed}");
                    }
                }

                if (files.Any())
                {
                    result[commitHash] = files.ToArray();
                    // _logger.Info($"✓ [C2F] Commit {commitHash.Substring(0, 8)}... -> {files.Count} file(s)");
                }
                else
                {
                    _logger.Warning($"⚠️ [C2F] No files found for commit {commitHash.Substring(0, 8)}...");
                }
            }

            _logger.Info($"✅ [C2F] Complete: {result.Count} commit(s) mapped to files");
            return result;
        }

        private void ShowHelp()
        {
            Console.WriteLine(@"
╔═══════════════════════════════════════════════════════════════╗
║                    ENTERPRISE SCALPEL                         ║
║            Requirement Traceability & Impact Analysis         ║
╚═══════════════════════════════════════════════════════════════╝

USAGE:
  scalpel [command] [options]

COMMANDS:
  analyze [options] [reqId]  Analyze requirement(s) in repository/-ies
  impact <filepath>          Show impact analysis for a specific file
  report <format>            Generate report (html|json|csv|markdown)
  hotspots                  Find code hotspots (high change + complexity)

ANALYSIS OPTIONS:
  --repos <repo1,repo2,...>  Specify multiple repository URLs or paths
                             (comma-separated, no spaces after commas)
                             If omitted, uses current directory
  
  --pm                       Enrich HTML report with PM platform data
                             (JIRA, ClickUp, or Azure DevOps)
                             Requires pm-integration.config.json configuration
  
  reqId (optional)           Analyze specific requirement across repositories
                             If omitted, performs complete analysis

EXAMPLES:
  scalpel                                       (Full analysis of current repo)
  scalpel analyze --repos /path/to/repo1,/path/to/repo2
                                               (Full analysis of multiple repos)
  scalpel analyze Req123                        (Requirement in current repo)
  scalpel analyze --repos /path/to/repo1,/path/to/repo2 Req123
                                               (Requirement across multiple repos)
  scalpel analyze --pm Req123                   (Requirement with PM enrichment)
  scalpel analyze --repos /path/to/repo1 --pm  (Full analysis with PM data)

PM INTEGRATION:
  The --pm flag enriches HTML reports with ticket data from your PM platform:
  - JIRA Cloud (Atlassian Cloud API v3)
  - ClickUp (API v2)
  - Azure DevOps (REST API 7.0)
  
  Setup:
  1. Create pm-integration.config.json in current directory
  2. Configure with platform, credentials, and project details
  3. Support for environment variables: JIRA_API_TOKEN, CLICKUP_API_TOKEN, ADO_PAT
  4. Run analysis with --pm flag
  
  Output: enriched-report.html with clickable ticket links and metadata

REPOSITORY FORMATS:
  Local paths:              /absolute/path  or  C:\\Windows\\path
  
  Git URLs:                 https://github.com/org/repo.git
                           git@github.com:org/repo.git
  
  GitHub with branch:       https://github.com/org/repo/tree/branch-name
  GitLab with branch:       https://gitlab.com/group/project/-/tree/branch-name
                           https://gitlab.com/group/project/-/tree/branch-name?ref_type=heads
  
  Git URLs with branch:     https://github.com/org/repo.git#branch-name
                           git@github.com:org/repo.git#branch-name

BRANCH SPECIFICATION:
  When you specify a repository URL with branch information, the analysis
  will be performed only on that specific branch. Supported formats:
  
  - GitHub tree URLs:       https://github.com/org/repo/tree/develop
  - GitLab tree URLs:       https://gitlab.com/group/project/-/tree/develop
  - Hash-based notation:    https://url/repo.git#branch-name
  
  Examples:
  scalpel analyze --repos 'https://github.com/org/repo/tree/develop' PSW-123
  scalpel analyze --repos 'https://gitlab.com/group/proj/-/tree/staging' 
  scalpel analyze --repos 'https://github.com/org/repo.git#feature-branch' Req456

CONFIG:
  Edit scalpel.config.json to customize:
  - Requirement ID patterns
  - Output directory
  - File filters
  - Risk thresholds
  
  PM Integration configurations:
  - Create pm-integration.config.json for PM platform setup
  - See examples in documentation for each platform
");
        }
    }
}
