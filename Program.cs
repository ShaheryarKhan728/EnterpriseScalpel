using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Scalpel.Enterprise
{
    /// <summary>
    /// Enterprise-grade requirement traceability and impact analysis tool
    /// </summary>
    class EnterpriseScalpel
    {
        private readonly Configuration _config;
        private readonly ILogger _logger;

        public EnterpriseScalpel(Configuration config, ILogger logger)
        {
            _config = config;
            _logger = logger;
        }

        static void Main(string[] args)
        {
            var config = Configuration.LoadFromFile("scalpel.config.json");
            var logger = new ConsoleLogger();
            var scalpel = new EnterpriseScalpel(config, logger);

            // If invoked with `serve` or `web`, start minimal web server with UI + API
            if (args.Length > 0)
            {
                var first = args[0].ToLower();
                if (first == "serve" || first == "web")
                {
                    scalpel.StartWebHost();
                    return;
                }

                scalpel.ExecuteCommand(args);
            }
            else
            {
                scalpel.RunFullAnalysis();
            }
        }

        private void ExecuteCommand(string[] args)
        {
            var command = args[0].ToLower();
            switch (command)
            {
                case "analyze":
                    // Parse: analyze [--repos <repo1,repo2,...>] [reqId]
                    var repositories = new List<string>();
                    string requirementId = null;
                    
                    for (int i = 1; i < args.Length; i++)
                    {
                        if (args[i] == "--repos" && i + 1 < args.Length)
                        {
                            repositories.AddRange(args[i + 1].Split(',').Select(r => r.Trim()));
                            i++;
                        }
                        else if (!args[i].StartsWith("--"))
                        {
                            requirementId = args[i];
                        }
                    }
                    
                    AnalyzeWithRepositories(repositories, requirementId);
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

        private void RunFullAnalysis()
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
            
            // If no repositories specified, use current directory
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
                    
                    // Check if repo is a URL or local path
                    if (IsRepositoryUrl(repo))
                    {
                        // Clone the repository to a temporary location
                        var tempDir = CloneRepository(repo);
                        if (string.IsNullOrEmpty(tempDir))
                        {
                            _logger.Warning($"Failed to clone repository: {repo}");
                            continue;
                        }
                        Directory.SetCurrentDirectory(tempDir);
                    }
                    else if (Directory.Exists(repo))
                    {
                        // Use local repository
                        Directory.SetCurrentDirectory(repo);
                    }
                    else
                    {
                        _logger.Warning($"Repository not found: {repo}");
                        continue;
                    }

                    // Perform analysis
                    if (string.IsNullOrEmpty(requirementId))
                    {
                        // Complete analysis if no requirement ID specified
                        _logger.Info("Performing complete analysis (no requirement ID specified)...");
                        var analysis = PerformCompleteAnalysis();
                        allAnalysisResults.Add(analysis);
                    }
                    else
                    {
                        // Analyze specific requirement
                        var analysis = AnalyzeRequirementInRepository(requirementId);
                        if (analysis != null)
                        {
                            allAnalysisResults.Add(analysis);
                        }
                    }
                }

                // Merge and display results from all repositories
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

        private string CloneRepository(string repositoryUrl)
        {
            try
            {
                var tempDir = Path.Combine(Path.GetTempPath(), "scalpel-" + Guid.NewGuid().ToString().Substring(0, 8));
                Directory.CreateDirectory(tempDir);
                
                _logger.Info($"Cloning repository to: {tempDir}");
                
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "git",
                        Arguments = $"clone {repositoryUrl} {tempDir}",
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

        private AnalysisResult AnalyzeRequirementInRepository(string requirementId)
        {
            _logger.Info($"Analyzing requirement: {requirementId}");
            
            var commits = GetCommitsForRequirement(requirementId);
            if (commits.Count == 0)
            {
                _logger.Warning($"No commits found for {requirementId}");
                return null;
            }

            var commitToReqs = BuildCommitToRequirementsMap();
            var allCommitFiles = GetAllCommitFiles(commitToReqs.Keys);
            var fileToReqs = BuildFileToRequirementsMap(commitToReqs, allCommitFiles);

            var filteredFileToReqs = new Dictionary<string, HashSet<string>>();
            foreach (var file in fileToReqs)
            {
                if (file.Value.Contains(requirementId))
                {
                    filteredFileToReqs[file.Key] = file.Value;
                }
            }

            var analysis = new AnalysisResult
            {
                CommitToRequirements = commitToReqs.Where(c => c.Value.Contains(requirementId))
                    .ToDictionary(x => x.Key, x => x.Value),
                FileToRequirements = filteredFileToReqs,
                MethodToRequirements = BuildMethodToRequirementsMap(commitToReqs, allCommitFiles),
                AnalysisDate = DateTime.Now,
                RepositoryPath = Directory.GetCurrentDirectory(),
                FilteredByRequirementId = requirementId
            };

            return analysis;
        }

        // Public API-friendly method to analyze repositories and return merged AnalysisResult
        public AnalysisResult AnalyzeRepositoriesForApi(List<string> repositories, string requirementId)
        {
            _logger.Info($"API: Analyzing {(repositories?.Count > 0 ? repositories.Count + " repositories" : "current repository")}...");

            if (repositories == null || repositories.Count == 0)
            {
                repositories = new List<string> { Directory.GetCurrentDirectory() };
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
                        var tempDir = CloneRepository(repo);
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
                Directory.SetCurrentDirectory(originalDirectory);
            }
        }

        // Minimal web host + API for UI
        public void StartWebHost()
        {
            var builder = WebApplication.CreateBuilder();
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

                    var analysis = AnalyzeRepositoriesForApi(repos, reqId);
                    var format = (request.format ?? "json").ToLower();

                    if (format == "json")
                    {
                        var json = SerializeAnalysisToJsonString(analysis);
                        ctx.Response.ContentType = "application/json";
                        await ctx.Response.WriteAsync(json);
                        return;
                    }
                    else if (format == "html")
                    {
                        var html = GenerateHtmlReport(analysis);
                        ctx.Response.ContentType = "text/html";
                        await ctx.Response.WriteAsync(html);
                        return;
                    }
                    else if (format == "csv")
                    {
                        var csv = GenerateCsvFromAnalysis(analysis);
                        ctx.Response.ContentType = "text/csv";
                        ctx.Response.Headers.Add("Content-Disposition", "attachment; filename=traceability-report.csv");
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

            var port = 5000;
            _logger.Info($"Starting web server on http://localhost:{port}");
            app.Run($"http://0.0.0.0:{port}");
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
                // Merge commits (with repo prefix to avoid duplicates)
                var repoPrefix = Path.GetFileName(result.RepositoryPath) ?? "repo";
                foreach (var (commit, reqs) in result.CommitToRequirements)
                {
                    var key = $"{repoPrefix}:{commit}";
                    mergedAnalysis.CommitToRequirements[key] = reqs;
                }

                // Merge files
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

                // Merge methods
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
            var logLines = RunGitCommand("log --pretty=format:\"%H %s\" --all");
            if (string.IsNullOrWhiteSpace(logLines))
            {
                return new Dictionary<string, List<string>>();
            }

            var lines = logLines.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
            var commitToRequirements = new Dictionary<string, List<string>>();

            foreach (var line in lines)
            {
                var matches = _config.RequirementRegex.Matches(line);
                if (matches.Count == 0) continue;
                if (line.Length < 40) continue;

                var commitHash = line.Substring(0, 40);
                var requirements = matches.Select(m => m.Value).Distinct().ToList();
                commitToRequirements[commitHash] = requirements;
            }

            return commitToRequirements;
        }

        // private Dictionary<string, HashSet<string>> BuildFileToRequirementsMap(
        //     Dictionary<string, List<string>> commitToRequirements)
        // {
        //     commitToRequirements ??= BuildCommitToRequirementsMap();
        //     var fileToRequirements = new Dictionary<string, HashSet<string>>();

        //     foreach (var (commitHash, requirements) in commitToRequirements)
        //     {
        //         var filesChanged = GetFilesChangedInCommit(commitHash);

        //         foreach (var file in filesChanged)
        //         {
        //             if (!fileToRequirements.ContainsKey(file))
        //             {
        //                 fileToRequirements[file] = new HashSet<string>();
        //             }

        //             foreach (var req in requirements)
        //             {
        //                 fileToRequirements[file].Add(req);
        //             }
        //         }
        //     }

        //     return fileToRequirements;
        // }

        // private Dictionary<string, MethodInfo> BuildMethodToRequirementsMap(
        //     Dictionary<string, List<string>> commitToRequirements)
        // {
        //     var methodToReqs = new Dictionary<string, MethodInfo>();
            
        //     foreach (var (commitHash, requirements) in commitToRequirements)
        //     {
        //         var filesChanged = GetFilesChangedInCommit(commitHash);
        //         var changedLineRanges = GetChangedLineRanges(commitHash);

        //         foreach (var file in filesChanged.Where(f => f.EndsWith(".cs")))
        //         {
        //             var absolutePath = Path.Combine(Directory.GetCurrentDirectory(), file);
        //             if (!File.Exists(absolutePath)) continue;

        //             var methods = GetMethodsFromFile(absolutePath);

        //             foreach (var method in methods)
        //             {
        //                 var (methodStart, methodEnd) = GetMethodLineRange(method);
                        
        //                 foreach (var change in changedLineRanges)
        //                 {
        //                     if (Overlaps((methodStart, methodEnd), change))
        //                     {
        //                         var key = $"{file}::{method.Identifier.Text}";
                                
        //                         if (!methodToReqs.ContainsKey(key))
        //                         {
        //                             methodToReqs[key] = new MethodInfo
        //                             {
        //                                 FilePath = file,
        //                                 MethodName = method.Identifier.Text,
        //                                 Requirements = new HashSet<string>(),
        //                                 ChangeCount = 0,
        //                                 LineStart = methodStart,
        //                                 LineEnd = methodEnd
        //                             };
        //                         }

        //                         foreach (var req in requirements)
        //                         {
        //                             methodToReqs[key].Requirements.Add(req);
        //                         }
        //                         methodToReqs[key].ChangeCount++;
        //                     }
        //                 }
        //             }
        //         }
        //     }

        //     return methodToReqs;
        // }

        private List<string> GetCommitsForRequirement(string requirementId)
        {
            var output = RunGitCommand($"log --grep={requirementId} --oneline");
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
            // Implementation similar to BuildMethodToRequirementsMap
            return methods;
        }

        private List<string> AnalyzeDependencies(HashSet<string> files)
        {
            var dependencies = new List<string>();
            // Analyze using statements, project references, etc.
            return dependencies;
        }

        private double CalculateRiskScore(HashSet<string> files, HashSet<string> methods, List<string> dependencies)
        {
            // Risk scoring algorithm
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
            // Analyze which files import/reference this file
            return new List<string>();
        }

        private List<string> GetFileConsumers(string filePath)
        {
            // Find files that consume this file's classes/methods
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
                    
                    // Simple complexity: count of methods, classes, conditionals
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
                    // Skip files that can't be parsed
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
            var html = GenerateHtmlReport(analysis);
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
            // Count total requirements
            var uniqueRequirements = new HashSet<string>();
            foreach (var reqs in analysis.CommitToRequirements.Values)
            {
                foreach (var req in reqs)
                {
                    uniqueRequirements.Add(req);
                }
            }

            // Generate commit rows
            var commitRows = string.Join("", analysis.CommitToRequirements
    .Take(50)
    .Select(kvp => {

        var reqs = kvp.Value;

        // Extract actual commit hash
        var fullKey = kvp.Key;
        var commitHash = fullKey.Contains(":")
            ? fullKey.Split(':')[1]
            : fullKey;

        var commitShort = commitHash.Length > 8
            ? commitHash.Substring(0, 8)
            : commitHash;

        var badgesHtml = GenerateBadgeHtml(reqs);

        return $"<tr class='commit-row'><td class='commit-hash'><code>{commitShort}</code></td><td>{badgesHtml}</td></tr>";
    }));

            // Generate file rows
            var fileRows = string.Join("", analysis.FileToRequirements
                .OrderByDescending(f => f.Value.Count)
                .Select(kvp => {
                    var reqs = kvp.Value.ToList();
                    var riskLevel = GetRiskLevel(reqs.Count);
                    var badgesHtml = GenerateBadgeHtml(reqs);
                    return $"<tr class='file-row' data-risk='{GetRiskNumericValue(reqs.Count)}'><td class='file-name'>{kvp.Key}</td><td>{badgesHtml}</td><td class='risk-cell'>{riskLevel}</td></tr>";
                }));

            // Generate method rows (limited to first 30)
            var methodRows = string.Join("", (analysis.MethodToRequirements ?? new Dictionary<string, MethodInfo>())
                .Take(30)
                .OrderByDescending(m => m.Value.ChangeCount)
                .Select(kvp => {
                    var method = kvp.Value;
                    var methodName = method.MethodName;
                    var fileName = Path.GetFileName(method.FilePath);
                    var reqs = method.Requirements?.ToList() ?? new List<string>();
                    var badgesHtml = GenerateBadgeHtml(reqs);
                    return $"<tr class='method-row'><td class='method-name'>{methodName}</td><td class='file-ref'>{fileName}</td><td class='lines'>{method.LineStart} - {method.LineEnd}</td><td class='changes'>{method.ChangeCount}</td><td>{badgesHtml}</td></tr>";
                }));

            var repoPath = analysis.RepositoryPath ?? (analysis.RepositoryPaths?.FirstOrDefault() ?? "Not Provided");

            return $@"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Enterprise Scalpel – Traceability Report</title>
    <link href='https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Geist:wght@300;400;600;700&display=swap' rel='stylesheet'>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        :root {{
            --primary: #3b82f6;
            --primary-dark: #1e40af;
            --primary-light: #eff6ff;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
            --neutral-900: #111827;
            --neutral-800: #1f2937;
            --neutral-700: #374151;
            --neutral-600: #4b5563;
            --neutral-200: #e5e7eb;
            --neutral-100: #f3f4f6;
            --neutral-50: #f9fafb;
            --bg-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --surface-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --surface-shadow-lg: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
        }}

        body {{
            font-family: 'Geist', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(180deg, var(--neutral-50) 0%, #f0f9ff 100%);
            color: var(--neutral-800);
            line-height: 1.6;
        }}

        /* ====== HEADER ====== */
        header {{
            background: var(--bg-gradient);
            color: white;
            padding: 3rem 2rem;
            box-shadow: var(--surface-shadow-lg);
            position: relative;
            overflow: hidden;
        }}

        header::before {{
            content: '';
            position: absolute;
            top: -50%;
            right: -10%;
            width: 400px;
            height: 400px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 50%;
            filter: blur(40px);
        }}

        header h1 {{
            font-size: 2.5rem;
            font-weight: 700;
            margin: 0 0 0.5rem 0;
            position: relative;
            z-index: 1;
            letter-spacing: -0.5px;
        }}

        header p {{
            font-size: 1rem;
            opacity: 0.95;
            position: relative;
            z-index: 1;
        }}

        /* ====== CONTAINER & LAYOUT ====== */
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 3rem 2rem;
        }}

        .card {{
            background: white;
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: var(--surface-shadow);
            border: 1px solid var(--neutral-200);
            transition: all 0.3s cubic-bezier(0.23, 1, 0.320, 1);
            animation: slideUp 0.6s ease-out;
        }}

        @keyframes slideUp {{
            from {{
                opacity: 0;
                transform: translateY(20px);
            }}
            to {{
                opacity: 1;
                transform: translateY(0);
            }}
        }}

        .card:hover {{
            box-shadow: var(--surface-shadow-lg);
            transform: translateY(-2px);
        }}

        .card.summary {{
            background: linear-gradient(135deg, var(--primary-light) 0%, #f0fdf4 100%);
            border: 1px solid var(--neutral-200);
        }}

        .card h2 {{
            font-size: 1.5rem;
            margin: 0 0 1.5rem 0;
            color: var(--neutral-900);
            display: flex;
            align-items: center;
            gap: 0.75rem;
            position: relative;
        }}

        .card h2::after {{
            content: '';
            flex-grow: 1;
            height: 2px;
            background: linear-gradient(90deg, var(--primary) 0%, transparent 100%);
        }}

        /* ====== SUMMARY GRID ====== */
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-top: 1.5rem;
        }}

        .stat-box {{
            background: white;
            padding: 1.5rem;
            border-radius: 10px;
            text-align: center;
            border: 2px solid var(--neutral-200);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }}

        .stat-box::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 3px;
            background: var(--primary);
        }}

        .stat-box:hover {{
            border-color: var(--primary);
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.15);
            transform: translateY(-4px);
        }}

        .stat-box .number {{
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--primary);
            margin: 0.5rem 0;
        }}

        .stat-box .label {{
            font-size: 0.85rem;
            color: var(--neutral-600);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
        }}

        /* ====== TABLES ====== */
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1.5rem;
        }}

        th {{
            background: linear-gradient(90deg, var(--neutral-100) 0%, var(--neutral-50) 100%);
            padding: 1rem;
            text-align: left;
            font-weight: 600;
            color: var(--neutral-700);
            border-bottom: 2px solid var(--primary);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        td {{
            padding: 1rem;
            border-bottom: 1px solid var(--neutral-200);
            color: var(--neutral-700);
        }}

        tr:hover {{
            background: var(--neutral-50);
            transition: background 0.2s ease;
        }}

        tr:last-child td {{
            border-bottom: none;
        }}

        /* ====== BADGES ====== */
        .badge {{
            display: inline-block;
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: white;
            padding: 0.4rem 0.9rem;
            border-radius: 6px;
            margin: 0.3rem 0.3rem 0.3rem 0;
            font-size: 0.8rem;
            font-weight: 600;
            white-space: nowrap;
            box-shadow: 0 2px 4px rgba(59, 130, 246, 0.2);
            transition: all 0.2s ease;
        }}

        .badge:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(59, 130, 246, 0.3);
        }}

        .expand-btn {{
            display: inline-block;
            background: var(--danger);
            color: white;
            border: none;
            padding: 0.4rem 0.8rem;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 600;
            cursor: pointer;
            margin-left: 0.4rem;
            transition: all 0.2s ease;
            box-shadow: 0 2px 4px rgba(239, 68, 68, 0.2);
        }}

        .expand-btn:hover {{
            background: #dc2626;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(239, 68, 68, 0.3);
        }}

        .expanded-badges {{
            display: inline-block;
            margin-left: 0.75rem;
            padding: 0.75rem;
            background: var(--neutral-100);
            border-radius: 8px;
            border-left: 3px solid var(--primary);
        }}

        /* ====== CODE & CELLS ====== */
        code {{
            background: var(--neutral-100);
            padding: 0.3rem 0.6rem;
            border-radius: 4px;
            font-family: 'Space Mono', monospace;
            font-size: 0.85rem;
            color: var(--primary-dark);
            border: 1px solid var(--neutral-200);
        }}

        .commit-hash {{
            font-weight: 600;
            color: var(--primary-dark);
        }}

        .file-name {{
            font-weight: 500;
            color: var(--neutral-800);
            word-break: break-word;
        }}

        .file-row[data-risk='5'],
        .file-row[data-risk='6'] {{
            background: rgba(239, 68, 68, 0.05) !important;
        }}

        .file-row[data-risk='3'],
        .file-row[data-risk='4'] {{
            background: rgba(245, 158, 11, 0.05) !important;
        }}

        .risk-cell {{
            font-weight: 600;
            text-align: center;
        }}

        .method-name {{
            font-weight: 600;
            color: var(--neutral-800);
            font-family: 'Space Mono', monospace;
        }}

        .file-ref, .lines, .changes {{
            font-family: 'Space Mono', monospace;
            font-size: 0.9rem;
            color: var(--neutral-600);
        }}

        /* ====== METADATA ====== */
        .metadata {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.5rem;
            margin-top: 1.5rem;
        }}

        .metadata-item {{
            padding: 1.25rem;
            background: linear-gradient(135deg, var(--primary-light) 0%, #fef2f2 100%);
            border-radius: 10px;
            border-left: 4px solid var(--primary);
            transition: all 0.3s ease;
        }}

        .metadata-item:hover {{
            transform: translateX(4px);
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.1);
        }}

        .metadata-item strong {{
            display: block;
            color: var(--neutral-900);
            margin-bottom: 0.5rem;
            font-weight: 600;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .metadata-item span {{
            color: var(--neutral-600);
            word-break: break-all;
            font-size: 0.95rem;
        }}

        /* ====== RESPONSIVE ====== */
        @media (max-width: 768px) {{
            .container {{
                padding: 1.5rem;
            }}

            .card {{
                padding: 1.5rem;
                margin-bottom: 1.5rem;
            }}

            header {{
                padding: 2rem 1.5rem;
            }}

            header h1 {{
                font-size: 1.75rem;
            }}

            table {{
                font-size: 0.9rem;
            }}

            th, td {{
                padding: 0.75rem;
            }}

            .summary-grid {{
                grid-template-columns: 1fr;
                gap: 1rem;
            }}

            .stat-box .number {{
                font-size: 2rem;
            }}

            .metadata {{
                grid-template-columns: 1fr;
            }}
        }}

        /* ====== ANIMATIONS ====== */
        @keyframes fadeIn {{
            from {{
                opacity: 0;
            }}
            to {{
                opacity: 1;
            }}
        }}

        .card {{
            animation: fadeIn 0.5s ease-out;
        }}
    </style>
</head>
<body>
    <header>
        <h1>📊 Enterprise Scalpel</h1>
        <p>Requirement Traceability & Impact Analysis Report</p>
    </header>

    <div class='container'>
        
        <!-- Summary Card -->
        <div class='card summary'>
            <h2>📈 Analysis Summary</h2>
            <div class='summary-grid'>
                <div class='stat-box'>
                    <div class='label'>Requirements</div>
                    <div class='number'>{uniqueRequirements.Count}</div>
                </div>
                <div class='stat-box'>
                    <div class='label'>Commits</div>
                    <div class='number'>{analysis.CommitToRequirements.Count}</div>
                </div>
                <div class='stat-box'>
                    <div class='label'>Files</div>
                    <div class='number'>{analysis.FileToRequirements.Count}</div>
                </div>
                <div class='stat-box'>
                    <div class='label'>Methods</div>
                    <div class='number'>{analysis.MethodToRequirements?.Count ?? 0}</div>
                </div>
            </div>
        </div>

        <!-- Commit to Requirements -->
        <div class='card'>
            <h2>🔗 Commits to Requirements</h2>
            <p style='color: var(--neutral-600); margin-bottom: 1rem; font-size: 0.9rem;'>Mapping of commits to their associated requirements</p>
            <table>
                <thead>
                    <tr>
                        <th>Commit Hash</th>
                        <th>Requirements</th>
                    </tr>
                </thead>
                <tbody>
                    {commitRows}
                </tbody>
            </table>
        </div>

        <!-- File to Requirements -->
        <div class='card'>
            <h2>📁 Files to Requirements</h2>
            <p style='color: var(--neutral-600); margin-bottom: 1rem; font-size: 0.9rem;'>Source files mapped to their requirements and risk levels</p>
            <table>
                <thead>
                    <tr>
                        <th>File Path</th>
                        <th>Requirements</th>
                        <th>Risk Level</th>
                    </tr>
                </thead>
                <tbody>
                    {fileRows}
                </tbody>
            </table>
        </div>

        <!-- Method Traceability -->
        <div class='card'>
            <h2>⚙️ Method Traceability</h2>
            <p style='color: var(--neutral-600); margin-bottom: 1rem; font-size: 0.9rem;'>Methods tracked by requirements with change history</p>
            <table>
                <thead>
                    <tr>
                        <th>Method Name</th>
                        <th>File</th>
                        <th>Lines</th>
                        <th>Changes</th>
                        <th>Requirements</th>
                    </tr>
                </thead>
                <tbody>
                    {methodRows}
                </tbody>
            </table>
        </div>

        <!-- Metadata -->
        <div class='card'>
            <h2>📅 Report Metadata</h2>
            <div class='metadata'>
                <div class='metadata-item'>
                    <strong>Analysis Date</strong>
                    <span>{analysis.AnalysisDate:yyyy-MM-dd HH:mm:ss}</span>
                </div>
                <div class='metadata-item'>
                    <strong>Repository Path</strong>
                    <span>{repoPath}</span>
                </div>
                <div class='metadata-item'>
                    <strong>Filtered Requirement</strong>
                    <span>{(string.IsNullOrEmpty(analysis.FilteredByRequirementId) ? "None - Full Analysis" : analysis.FilteredByRequirementId)}</span>
                </div>
                <div class='metadata-item'>
                    <strong>Report Type</strong>
                    <span>Complete Traceability Analysis</span>
                </div>
            </div>
        </div>

    </div>

    <script>
        function expandBadges(btn) {{
            const expanded = btn.nextElementSibling;
            if (expanded && expanded.classList.contains('expanded-badges')) {{
                const isVisible = expanded.style.display !== 'none';
                expanded.style.display = isVisible ? 'none' : 'inline-block';
                const count = parseInt(btn.textContent.match(/\d+/)[0]);
                btn.textContent = isVisible ? '+' + count : '−' + count + ' less';
            }}
        }}

        // Add interactivity: highlight rows on hover
        document.querySelectorAll('table tbody tr').forEach(row => {{
            row.addEventListener('mouseenter', function() {{
                this.style.boxShadow = 'inset 0 0 10px rgba(59, 130, 246, 0.1)';
            }});
            row.addEventListener('mouseleave', function() {{
                this.style.boxShadow = 'none';
            }});
        }});
    </script>
</body>
</html>";
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

//         private string GenerateHtmlReport(AnalysisResult analysis)
//         {
//             return $@"
// <!DOCTYPE html>
// <html>
// <head>
//     <title>Requirement Traceability Report</title>
//     <style>
//         body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
//         .container {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
//         h1 {{ color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }}
//         .summary {{ background: #e3f2fd; padding: 20px; border-radius: 4px; margin: 20px 0; }}
//         table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
//         th {{ background: #4CAF50; color: white; padding: 12px; text-align: left; }}
//         td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
//         tr:hover {{ background: #f5f5f5; }}
//         .high-risk {{ color: #f44336; font-weight: bold; }}
//         .medium-risk {{ color: #ff9800; }}
//         .low-risk {{ color: #4CAF50; }}
//     </style>
// </head>
// <body>
//     <div class='container'>
//         <h1>📊 Requirement Traceability Report</h1>
//         <div class='summary'>
//             <p><strong>Generated:</strong> {analysis.AnalysisDate}</p>
//             <p><strong>Repository:</strong> {analysis.RepositoryPath}</p>
//             <p><strong>Total Commits:</strong> {analysis.CommitToRequirements.Count}</p>
//             <p><strong>Total Files:</strong> {analysis.FileToRequirements.Count}</p>
//         </div>
//         <h2>⚠️ High-Risk Files (Multiple Requirements)</h2>
//         <table>
//             <tr>
//                 <th>File</th>
//                 <th>Requirements</th>
//                 <th>Count</th>
//             </tr>
//             {string.Join("", analysis.FileToRequirements
//                 .Where(f => f.Value.Count > 1)
//                 .OrderByDescending(f => f.Value.Count)
//                 .Select(f => $@"
//             <tr>
//                 <td>{f.Key}</td>
//                 <td>{string.Join(", ", f.Value)}</td>
//                 <td class='{(f.Value.Count > 3 ? "high-risk" : "medium-risk")}'>{f.Value.Count}</td>
//             </tr>"))}
//         </table>
//     </div>
// </body>
// </html>";
//         }

        private string[] GetFilesChangedInCommit(string commitHash)
        {
            var filesOutput = RunGitCommand($"diff-tree --no-commit-id --name-only --root -r {commitHash}");
            return filesOutput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                              .Select(f => f.Trim())
                              .Where(f => !string.IsNullOrWhiteSpace(f))
                              .ToArray();
        }

        private List<(int start, int end)> GetChangedLineRanges(string commitHash)
        {
            var diffOutput = RunGitCommand($"show {commitHash}");
            var changedLineRanges = new List<(int start, int end)>();

            foreach (var line in diffOutput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (line.StartsWith("@@"))
                {
                    var parts = line.Split(' ');
                    if (parts.Length < 3) continue;
                    
                    var rangePart = parts[2];
                    var nums = rangePart.TrimStart('+').Split(',');
                    
                    if (int.TryParse(nums[0], out int start))
                    {
                        int length = nums.Length > 1 && int.TryParse(nums[1], out int len) ? len : 1;
                        changedLineRanges.Add((start, start + length));
                    }
                }
            }

            return changedLineRanges;
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

        private string RunGitCommand(string arguments)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "git",
                        Arguments = arguments,
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
                    _logger.Error($"Git error: {error}");
                }

                return output;
            }
            catch (Exception ex)
            {
                _logger.Error($"Failed to run git command: {ex.Message}");
                return string.Empty;
            }
        }

        private Dictionary<string, HashSet<string>> BuildFileToRequirementsMap(
            Dictionary<string, List<string>> commitToRequirements,
            Dictionary<string, string[]> allCommitFiles = null)
        {
            commitToRequirements ??= BuildCommitToRequirementsMap();
            allCommitFiles ??= GetAllCommitFiles(commitToRequirements.Keys);
            
            var fileToRequirements = new Dictionary<string, HashSet<string>>();

            foreach (var (commitHash, requirements) in commitToRequirements)
            {
                if (!allCommitFiles.ContainsKey(commitHash)) continue;
                
                var filesChanged = allCommitFiles[commitHash];

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

            return fileToRequirements;
        }

        private Dictionary<string, MethodInfo> BuildMethodToRequirementsMap(
            Dictionary<string, List<string>> commitToRequirements,
            Dictionary<string, string[]> allCommitFiles = null)
        {
            allCommitFiles ??= GetAllCommitFiles(commitToRequirements.Keys);
            var methodToReqs = new Dictionary<string, MethodInfo>();
            
            foreach (var (commitHash, requirements) in commitToRequirements)
            {
                if (!allCommitFiles.ContainsKey(commitHash)) continue;
                
                var filesChanged = allCommitFiles[commitHash];
                var changedLineRanges = GetChangedLineRanges(commitHash);

                foreach (var file in filesChanged.Where(f => f.EndsWith(".cs")))
                {
                    var absolutePath = Path.Combine(Directory.GetCurrentDirectory(), file);
                    if (!File.Exists(absolutePath)) continue;

                    var methods = GetMethodsFromFile(absolutePath);

                    foreach (var method in methods)
                    {
                        var (methodStart, methodEnd) = GetMethodLineRange(method);
                        
                        foreach (var change in changedLineRanges)
                        {
                            if (Overlaps((methodStart, methodEnd), change))
                            {
                                var key = $"{file}::{method.Identifier.Text}";
                                
                                if (!methodToReqs.ContainsKey(key))
                                {
                                    methodToReqs[key] = new MethodInfo
                                    {
                                        FilePath = file,
                                        MethodName = method.Identifier.Text,
                                        Requirements = new HashSet<string>(),
                                        ChangeCount = 0,
                                        LineStart = methodStart,
                                        LineEnd = methodEnd
                                    };
                                }

                                foreach (var req in requirements)
                                {
                                    methodToReqs[key].Requirements.Add(req);
                                }
                                methodToReqs[key].ChangeCount++;
                            }
                        }
                    }
                }
            }

            return methodToReqs;
        }

        // New method: single git call for all commits
        private Dictionary<string, string[]> GetAllCommitFiles(IEnumerable<string> commitHashes)
        {
            var result = new Dictionary<string, string[]>();
            var commits = string.Join(" ", commitHashes);
            
            // Use git show with --name-only for multiple commits
            // Format: commit hash on one line, files on subsequent lines, separated by empty line
            var output = RunGitCommand($"show --pretty=format:%H --name-only {commits}");
            
            if (string.IsNullOrWhiteSpace(output))
            {
                return result;
            }

            var lines = output.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
            string currentCommit = null;
            var currentFiles = new List<string>();

            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                
                // Check if this line is a commit hash (40 hex characters)
                if (trimmed.Length == 40 && Regex.IsMatch(trimmed, "^[0-9a-f]{40}$"))
                {
                    // Save previous commit's files
                    if (currentCommit != null && currentFiles.Any())
                    {
                        result[currentCommit] = currentFiles.ToArray();
                    }
                    
                    currentCommit = trimmed;
                    currentFiles = new List<string>();
                }
                else if (!string.IsNullOrWhiteSpace(trimmed))
                {
                    currentFiles.Add(trimmed);
                }
            }
            
            // Don't forget the last commit
            if (currentCommit != null && currentFiles.Any())
            {
                result[currentCommit] = currentFiles.ToArray();
            }

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
  
  reqId (optional)           Analyze specific requirement across repositories
                             If omitted, performs complete analysis

EXAMPLES:
  scalpel                                       (Full analysis of current repo)
  scalpel analyze --repos /path/to/repo1,/path/to/repo2
                                               (Full analysis of multiple repos)
  scalpel analyze Req123                        (Requirement in current repo)
  scalpel analyze --repos /path/to/repo1,/path/to/repo2 Req123
                                               (Requirement across multiple repos)
  scalpel analyze --repos https://github.com/org/repo.git,https://github.com/org/repo2.git Req456
                                               (Requirement across remote repos)
  scalpel impact Services/PaymentService.cs
  scalpel report html
  scalpel hotspots

REPOSITORY FORMATS:
  Local paths:     /absolute/path  or  C:\Windows\path
  Remote URLs:     https://github.com/org/repo.git
  Git SSH:         git@github.com:org/repo.git

CONFIG:
  Edit scalpel.config.json to customize:
  - Requirement ID patterns
  - Output directory
  - File filters
  - Risk thresholds
");
        }
    }

    #region Models

    public class GenerateRequest
    {
        public List<string> Repositories { get; set; }
        public List<string> RequirementIds { get; set; }
        public string format { get; set; }
    }

    public class Configuration
    {
        public string DefaultRequirementId { get; set; } = "REQ-111";
        public string RequirementPattern { get; set; } = @"(?i)Req-\d+";
        public Regex RequirementRegex => new Regex(RequirementPattern);
        public string OutputDirectory { get; set; } = "scalpel-reports";
        public string[] ExcludePatterns { get; set; } = { "**/bin/**", "**/obj/**", "**/packages/**" };
        public int RiskThresholdLow { get; set; } = 1;
        public int RiskThresholdMedium { get; set; } = 3;
        public int RiskThresholdHigh { get; set; } = 5;


        public static Configuration LoadFromFile(string path)
        {
            if (File.Exists(path))
            {
                var json = File.ReadAllText(path);
                return JsonSerializer.Deserialize<Configuration>(json) ?? new Configuration();
            }
            return new Configuration();
        }
    }

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

    public class RequirementImpact
    {
        public string RequirementId { get; set; }
        public int CommitCount { get; set; }
        public HashSet<string> AffectedFiles { get; set; }
        public HashSet<string> AffectedMethods { get; set; }
        public List<string> Dependencies { get; set; }
        public double RiskScore { get; set; }
    }

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

    public class Hotspot
    {
        public string FilePath { get; set; }
        public int ChangeFrequency { get; set; }
        public int Complexity { get; set; }
        public double HotspotScore { get; set; }
    }

    #endregion

    #region Logging

    public interface ILogger
    {
        void Info(string message);
        void Warning(string message);
        void Error(string message);
        void Success(string message);
    }

    public class ConsoleLogger : ILogger
    {
        public void Info(string message) => Console.WriteLine($"ℹ️  {message}");
        public void Warning(string message) => Console.WriteLine($"⚠️  {message}");
        public void Error(string message) => Console.WriteLine($"❌ {message}");
        public void Success(string message) => Console.WriteLine($"✅ {message}");
    }

    #endregion
}