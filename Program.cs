using Scalpel.Enterprise;

internal class Program
{
    private static void Main(string[] args)
    {
        var config = Configuration.LoadFromFile("scalpel.config.json");
        var logger = new ConsoleLogger();
        var scalpel = new EnterpriseScalpel(config, logger);

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
}