using Scalpel.Enterprise;
using System.Diagnostics;
using System.Runtime.InteropServices;

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
            // Default behavior: Start web server and open browser
            logger.Info("Starting Enterprise Scalpel Web Server...");
            logger.Info("Opening browser in 2 seconds...");
            
            // Start web host in a separate thread so it doesn't block
            var webTask = Task.Run(() => scalpel.StartWebHost());
            
            // Give the server a moment to start
            Thread.Sleep(2000);
            
            // Open the default browser
            try
            {
                OpenBrowser("http://localhost:5001");
                logger.Success("Browser opened at http://localhost:5001");
            }
            catch (Exception ex)
            {
                logger.Warning($"Could not open browser automatically: {ex.Message}");
                logger.Info("Please open http://localhost:5001 in your browser manually");
            }
            
            // Keep the application running
            webTask.Wait();
        }
    }

    private static void OpenBrowser(string url)
    {
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "cmd",
                    Arguments = $"/c start {url}",
                    CreateNoWindow = true
                });
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                Process.Start("xdg-open", url);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                Process.Start("open", url);
            }
        }
        catch
        {
            // If opening browser fails, the app still continues
            throw;
        }
    }
}