namespace Scalpel.Enterprise
{
    public class GenerateRequest
    {
        public List<string> Repositories { get; set; }
        public List<string> RequirementIds { get; set; }
        public string format { get; set; }
    }
}