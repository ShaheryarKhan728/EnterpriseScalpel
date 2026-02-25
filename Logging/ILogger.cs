namespace Scalpel.Enterprise
{
    public interface ILogger
    {
        void Info(string message);
        void Warning(string message);
        void Error(string message);
        void Success(string message);
    }
}