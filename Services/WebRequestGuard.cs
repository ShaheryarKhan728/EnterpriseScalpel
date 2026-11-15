using System.Net.Http.Headers;
using Microsoft.AspNetCore.Http;

namespace Scalpel.Enterprise
{
    /// <summary>
    /// Cheap request checks for the state-changing API endpoint:
    /// - Content-Type must be application/json, which forces a CORS preflight for cross-site
    ///   requests (the server never answers preflights, so browsers block them).
    /// - If an Origin header is present it must match the Host the request was sent to.
    /// - When bound to loopback, the Host header must be a loopback name (blocks DNS rebinding).
    /// </summary>
    public static class WebRequestGuard
    {
        private static readonly HashSet<string> LoopbackHosts =
            new(StringComparer.OrdinalIgnoreCase) { "localhost", "127.0.0.1", "[::1]", "::1" };

        public static (int status, string reason)? Check(HttpRequest request, bool loopbackOnly)
        {
            if (!MediaTypeHeaderValue.TryParse(request.ContentType, out var mediaType) ||
                !string.Equals(mediaType.MediaType, "application/json", StringComparison.OrdinalIgnoreCase))
            {
                return (StatusCodes.Status415UnsupportedMediaType, "Content-Type must be application/json");
            }

            var host = request.Host;
            if (!host.HasValue)
            {
                return (StatusCodes.Status400BadRequest, "Missing Host header");
            }

            if (loopbackOnly && !LoopbackHosts.Contains(host.Host))
            {
                return (StatusCodes.Status403Forbidden, "Host not allowed");
            }

            var origin = request.Headers.Origin.ToString();
            if (!string.IsNullOrEmpty(origin))
            {
                if (!Uri.TryCreate(origin, UriKind.Absolute, out var originUri) ||
                    !string.Equals(originUri.Authority, host.Value, StringComparison.OrdinalIgnoreCase))
                {
                    return (StatusCodes.Status403Forbidden, "Cross-origin requests are not allowed");
                }
            }

            return null;
        }
    }
}
