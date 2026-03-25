namespace Scalpel.Enterprise
{
    public class ConsoleLogger : ILogger
    {
        public void Info(string message) => Console.WriteLine($"ℹ️  {message}");
        public void Warning(string message) => Console.WriteLine($"⚠️  {message}");
        public void Error(string message) => Console.WriteLine($"❌ {message}");
        public void Success(string message) => Console.WriteLine($"✅ {message}");
        public void Debug(string message)
        {
            // Only log debug messages if DEBUG level is enabled or in verbose mode
            if (Environment.GetEnvironmentVariable("SCALPEL_DEBUG") == "1" || Environment.GetEnvironmentVariable("SCALPEL_VERBOSE") == "1")
            {
                Console.WriteLine($"🔧 {message}");
            }
        }
    }
}