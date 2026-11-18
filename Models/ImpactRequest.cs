using System.Text.Json.Serialization;

namespace Scalpel.Enterprise
{
    /// <summary>"What will my change affect?" request: repositories plus the files/methods being changed.</summary>
    public class ImpactRequest : GenerateRequest
    {
        /// <summary>
        /// Files or methods being changed, e.g. "PaymentService.cs", "Services/PaymentService.cs"
        /// or "PaymentService.cs::Refund" (method). "::Refund" matches the method in any file.
        /// </summary>
        [JsonPropertyName("targets")]
        public List<string>? Targets { get; set; }
    }

    public sealed record ImpactRequirement(string Id, string? Url);

    public sealed record ImpactMatch(string File, string? Method, IReadOnlyList<string> Requirements);

    public sealed record ImpactTargetResult(string Target, IReadOnlyList<ImpactMatch> Matches);

    public sealed record ImpactResponse(
        IReadOnlyList<ImpactRequirement> Requirements,
        IReadOnlyList<ImpactTargetResult> Targets,
        IReadOnlyList<string> Unmatched);
}
