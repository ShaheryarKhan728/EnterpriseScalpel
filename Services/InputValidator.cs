using System.Text.RegularExpressions;

namespace Scalpel.Enterprise
{
    /// <summary>
    /// Validation for values that reach git or the file system. Validation is a second layer:
    /// git is always invoked with an argument vector (see <see cref="GitRunner"/>).
    /// </summary>
    public static class InputValidator
    {
        public static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(1);
        public const int MaxPatternLength = 256;

        // Typical IDs: REQ-123, PSW-1234, ABC_DEF-7, PROJ.API-42. No spaces, quotes or leading '-'.
        private static readonly Regex RequirementIdRegex =
            new(@"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", RegexOptions.CultureInvariant, RegexTimeout);

        // Conservative subset of git ref-name rules (feature/PSW-1234-login, release/1.2, main).
        private static readonly Regex BranchRegex =
            new(@"^[A-Za-z0-9_][A-Za-z0-9._/+-]{0,199}$", RegexOptions.CultureInvariant, RegexTimeout);

        // git@host:owner/repo(.git)
        private static readonly Regex SshUrlRegex =
            new(@"^git@[A-Za-z0-9.-]+:[A-Za-z0-9._~/-]+$", RegexOptions.CultureInvariant, RegexTimeout);

        public static bool IsValidRequirementId(string? value) =>
            !string.IsNullOrEmpty(value) && RequirementIdRegex.IsMatch(value);

        public static bool IsValidBranchName(string? value) =>
            !string.IsNullOrEmpty(value)
            && BranchRegex.IsMatch(value)
            && !value.Contains("..")
            && !value.Contains("//")
            && !value.EndsWith("/")
            && !value.EndsWith(".lock", StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// Accepts https:// URLs (and git@host:path SSH URLs when <paramref name="allowSsh"/> is true).
        /// Rejects anything that could be read as a git option or a local/exotic transport (file://, ext::, ...).
        /// </summary>
        public static bool IsValidCloneUrl(string? value, bool allowSsh)
        {
            if (string.IsNullOrWhiteSpace(value) || value.StartsWith("-") || value.Any(char.IsWhiteSpace))
                return false;

            if (allowSsh && SshUrlRegex.IsMatch(value) && !value.Contains(".."))
                return true;

            return Uri.TryCreate(value, UriKind.Absolute, out var uri)
                   && uri.Scheme == Uri.UriSchemeHttps
                   && !string.IsNullOrEmpty(uri.Host);
        }

        /// <summary>Compiles a user-supplied requirement pattern with a match timeout.</summary>
        public static bool TryCreatePattern(string? pattern, out Regex? regex, out string? error)
        {
            regex = null;
            error = null;
            if (string.IsNullOrWhiteSpace(pattern))
            {
                error = "Requirement pattern is empty.";
                return false;
            }
            if (pattern.Length > MaxPatternLength)
            {
                error = $"Requirement pattern is longer than {MaxPatternLength} characters.";
                return false;
            }
            try
            {
                regex = new Regex(pattern, RegexOptions.CultureInvariant, RegexTimeout);
                return true;
            }
            catch (ArgumentException ex)
            {
                error = $"Invalid requirement pattern: {ex.Message}";
                return false;
            }
        }
    }
}
