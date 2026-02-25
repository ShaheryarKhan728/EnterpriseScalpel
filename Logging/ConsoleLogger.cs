namespace Scalpel.Enterprise
{
    public class ConsoleLogger : ILogger
    {
        public void Info(string message) => Console.WriteLine($"ℹ️  {message}");
        public void Warning(string message) => Console.WriteLine($"⚠️  {message}");
        public void Error(string message) => Console.WriteLine($"❌ {message}");
        public void Success(string message) => Console.WriteLine($"✅ {message}");
    }
}