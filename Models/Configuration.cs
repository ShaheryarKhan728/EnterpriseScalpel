using System.Text.Json;
using System.Text.RegularExpressions;

namespace Scalpel.Enterprise
{
    public class Configuration
    {
        public string DefaultRequirementId { get; set; } = "REQ-111";
        public string RequirementPattern { get; set; } = @"(?i)Req-\d+";
        public string OutputDirectory { get; set; } = "scalpel-reports";
        public string[] ExcludePatterns { get; set; } = { "**/bin/**", "**/obj/**", "**/packages/**" };
        public int RiskThresholdLow { get; set; } = 1;
        public int RiskThresholdMedium { get; set; } = 3;
        public int RiskThresholdHigh { get; set; } = 5;

        // Demo/sample repository: kept permanently cloned so sample reports are fast.
        // Set SampleRepository to null or "" to disable.
        public string? SampleRepository { get; set; } = "https://github.com/ShaheryarKhan728/EnterpriseScalpel";
        public string SampleCacheDirectory { get; set; } = "sample-repos";
        public int SampleRefreshMinutes { get; set; } = 60;
        // Requirement the demo button asks for (wwwroot/app.js); analysed at startup so the first click is instant.
        public string? SampleRequirementId { get; set; } = "REQ-123";

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
}