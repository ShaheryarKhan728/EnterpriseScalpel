using System.Text.Json;
using System.Text.RegularExpressions;

namespace Scalpel.Enterprise
{
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
}