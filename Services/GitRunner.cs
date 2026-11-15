using System.Diagnostics;

namespace Scalpel.Enterprise
{
    public sealed record GitResult(int ExitCode, string Output, string Error, bool TimedOut);

    /// <summary>
    /// Runs git with an argument vector (never a concatenated command line), so values such as
    /// branch names, URLs or requirement IDs can never be interpreted as additional git options.
    /// </summary>
    public static class GitRunner
    {
        public static readonly TimeSpan DefaultTimeout = TimeSpan.FromMinutes(5);

        public static GitResult Run(IEnumerable<string> arguments, string? workingDirectory = null, TimeSpan? timeout = null)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "git",
                WorkingDirectory = workingDirectory ?? string.Empty,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            foreach (var arg in arguments)
            {
                psi.ArgumentList.Add(arg);
            }

            // Never block waiting for credentials on a server, and only allow network transports.
            psi.Environment["GIT_TERMINAL_PROMPT"] = "0";
            psi.Environment["GCM_INTERACTIVE"] = "never";
            psi.Environment["GIT_ASKPASS"] = "";
            psi.Environment["SSH_ASKPASS"] = "";
            psi.Environment["GIT_ALLOW_PROTOCOL"] = "https:ssh";

            using var process = new Process { StartInfo = psi };
            process.Start();

            // Read both streams concurrently so a full stderr pipe can't deadlock the child.
            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();

            var limit = timeout ?? DefaultTimeout;
            if (!process.WaitForExit((int)limit.TotalMilliseconds))
            {
                try { process.Kill(entireProcessTree: true); } catch { /* already exited */ }
                process.WaitForExit();
                return new GitResult(-1, SafeResult(stdoutTask), SafeResult(stderrTask), TimedOut: true);
            }

            process.WaitForExit(); // flush async readers
            return new GitResult(process.ExitCode, stdoutTask.GetAwaiter().GetResult(), stderrTask.GetAwaiter().GetResult(), TimedOut: false);
        }

        private static string SafeResult(Task<string> task)
        {
            try { return task.Wait(TimeSpan.FromSeconds(5)) ? task.Result : string.Empty; }
            catch { return string.Empty; }
        }
    }
}
