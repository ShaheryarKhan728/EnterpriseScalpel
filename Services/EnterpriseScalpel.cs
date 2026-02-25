using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
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
                        _logger.Info("Performing complete analysis (no requirement ID specified)...");
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
                        var html = _reportService.GenerateHtmlReport(analysis);
                        ctx.Response.ContentType = "text/html";
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

        private Dictionary<string, string[]> GetAllCommitFiles(IEnumerable<string> commitHashes)
        {
            var result = new Dictionary<string, string[]>();
            var commits = string.Join(" ", commitHashes);

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

                if (trimmed.Length == 40 && Regex.IsMatch(trimmed, "^[0-9a-f]{40}$"))
                {
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
  Local paths:     /absolute/path  or  C:\\Windows\\path
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
}
