using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Text.Json;
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

            if (args.Length > 0)
            {
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
                    var reqId = args.Length > 1 ? args[1] : null;
                    AnalyzeRequirement(reqId);
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
            var fileToReqs = BuildFileToRequirementsMap(commitToReqs);
            var methodToReqs = BuildMethodToRequirementsMap(commitToReqs);
            
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
            var logLines = RunGitCommand("log --oneline --all");
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

                var commitHash = line.Split(' ')[0];
                var requirements = matches.Select(m => m.Value).Distinct().ToList();
                commitToRequirements[commitHash] = requirements;
            }

            return commitToRequirements;
        }

        private Dictionary<string, HashSet<string>> BuildFileToRequirementsMap(
            Dictionary<string, List<string>> commitToRequirements)
        {
            commitToRequirements ??= BuildCommitToRequirementsMap();
            var fileToRequirements = new Dictionary<string, HashSet<string>>();

            foreach (var (commitHash, requirements) in commitToRequirements)
            {
                var filesChanged = GetFilesChangedInCommit(commitHash);

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
            Dictionary<string, List<string>> commitToRequirements)
        {
            var methodToReqs = new Dictionary<string, MethodInfo>();
            
            foreach (var (commitHash, requirements) in commitToRequirements)
            {
                var filesChanged = GetFilesChangedInCommit(commitHash);
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
            var outputDir = _config.OutputDirectory;
            Directory.CreateDirectory(outputDir);
            
            ExportToJson(analysis);
            ExportToHtml(analysis);
            ExportToMarkdown(analysis);
            
            _logger.Success($"Reports exported to: {outputDir}");
        }

        private void ExportToJson(AnalysisResult analysis)
        {
            var json = JsonSerializer.Serialize(analysis, new JsonSerializerOptions { WriteIndented = true });
            var path = Path.Combine(_config.OutputDirectory, "traceability-report.json");
            File.WriteAllText(path, json);
            _logger.Success($"JSON report: {path}");
        }

        private void ExportToHtml(AnalysisResult analysis)
        {
            var html = GenerateHtmlReport(analysis);
            var path = Path.Combine(_config.OutputDirectory, "traceability-report.html");
            File.WriteAllText(path, html);
            _logger.Success($"HTML report: {path}");
        }

        private void ExportToCsv(AnalysisResult analysis)
        {
            var csv = new System.Text.StringBuilder();
            csv.AppendLine("File,Requirements,Risk Level,Change Count");
            
            foreach (var entry in analysis.FileToRequirements.OrderByDescending(f => f.Value.Count))
            {
                var reqs = string.Join(";", entry.Value);
                var riskLevel = GetRiskLevel(entry.Value.Count);
                csv.AppendLine($"\"{entry.Key}\",\"{reqs}\",\"{riskLevel}\",{entry.Value.Count}");
            }
            
            var path = Path.Combine(_config.OutputDirectory, "traceability-report.csv");
            File.WriteAllText(path, csv.ToString());
            _logger.Success($"CSV report: {path}");
        }

        private void ExportToMarkdown(AnalysisResult analysis)
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
            
            var path = Path.Combine(_config.OutputDirectory, "traceability-report.md");
            File.WriteAllText(path, md.ToString());
            _logger.Success($"Markdown report: {path}");
        }

        private string GenerateHtmlReport(AnalysisResult analysis)
        {
            return $@"
<!DOCTYPE html>
<html>
<head>
    <title>Requirement Traceability Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }}
        .summary {{ background: #e3f2fd; padding: 20px; border-radius: 4px; margin: 20px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th {{ background: #4CAF50; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background: #f5f5f5; }}
        .high-risk {{ color: #f44336; font-weight: bold; }}
        .medium-risk {{ color: #ff9800; }}
        .low-risk {{ color: #4CAF50; }}
    </style>
</head>
<body>
    <div class='container'>
        <h1>📊 Requirement Traceability Report</h1>
        <div class='summary'>
            <p><strong>Generated:</strong> {analysis.AnalysisDate}</p>
            <p><strong>Repository:</strong> {analysis.RepositoryPath}</p>
            <p><strong>Total Commits:</strong> {analysis.CommitToRequirements.Count}</p>
            <p><strong>Total Files:</strong> {analysis.FileToRequirements.Count}</p>
        </div>
        <h2>⚠️ High-Risk Files (Multiple Requirements)</h2>
        <table>
            <tr>
                <th>File</th>
                <th>Requirements</th>
                <th>Count</th>
            </tr>
            {string.Join("", analysis.FileToRequirements
                .Where(f => f.Value.Count > 1)
                .OrderByDescending(f => f.Value.Count)
                .Select(f => $@"
            <tr>
                <td>{f.Key}</td>
                <td>{string.Join(", ", f.Value)}</td>
                <td class='{(f.Value.Count > 3 ? "high-risk" : "medium-risk")}'>{f.Value.Count}</td>
            </tr>"))}
        </table>
    </div>
</body>
</html>";
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

            foreach (var line in diffOutput.Split('\n'))
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
  analyze [reqId]        Analyze specific requirement (default: from config)
  impact <filepath>      Show impact analysis for a specific file
  report <format>        Generate report (html|json|csv|markdown)
  hotspots              Find code hotspots (high change + complexity)

EXAMPLES:
  scalpel analyze Req123
  scalpel impact Services/PaymentService.cs
  scalpel report html
  scalpel hotspots

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

    public class Configuration
    {
        public string DefaultRequirementId { get; set; } = "Req1";
        public string RequirementPattern { get; set; } = @"Req\d+";
        public Regex RequirementRegex => new Regex(RequirementPattern);
        public string OutputDirectory { get; set; } = "./scalpel-reports";
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