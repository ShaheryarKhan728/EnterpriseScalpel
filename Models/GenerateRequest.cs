using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Scalpel.Enterprise
{
    public class GenerateRequest
    {
        [JsonPropertyName("repositories")]
        public List<string> Repositories { get; set; }

        [JsonPropertyName("requirementIds")]
        public List<string> RequirementIds { get; set; }

        [JsonPropertyName("format")]
        public string Format { get; set; }

        [JsonPropertyName("requirementPattern")]
        public string RequirementPattern { get; set; }
    }
}