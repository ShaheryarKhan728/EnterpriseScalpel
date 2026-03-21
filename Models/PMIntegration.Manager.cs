using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Scalpel.Enterprise
{
    /// <summary>
    /// Orchestrates PM platform integration with caching and parallel request handling
    /// </summary>
    public class PMPlatformManager
    {
        private readonly PMConfig _config;
        private readonly ILogger _logger;
        private readonly string _cacheFilePath;
        private readonly IPMPlatform _platform;
        private Dictionary<string, PMCacheEntry> _cache = new();
        private readonly SemaphoreSlim _concurrencyLimiter;

        public PMPlatformManager(PMConfig config, ILogger logger, string? outputDirectory = null)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _cacheFilePath = Path.Combine(outputDirectory ?? "scalpel-reports", "pm-cache.json");
            _platform = PMPlatformFactory.Create(config);
            _concurrencyLimiter = new SemaphoreSlim(config.MaxConcurrency, config.MaxConcurrency);

            // Validate platform configuration
            if (!_platform.ValidateConfig())
            {
                throw new PMIntegrationException($"Invalid configuration for {config.Platform} platform");
            }

            // Load cache from disk
            LoadCache();
        }

        /// <summary>
        /// Fetch ticket data for all discovered requirements
        /// </summary>
        /// <param name="requirements">Set of requirement IDs to fetch</param>
        /// <returns>Dictionary mapping requirement ID to PMTicket (null if not found)</returns>
        public async Task<Dictionary<string, PMTicket>> GetTicketsForRequirementsAsync(
            IEnumerable<string> requirements)
        {
            var requirementsList = requirements?.ToList() ?? new List<string>();
            if (requirementsList.Count == 0)
                return new Dictionary<string, PMTicket>();

            _logger.Info($"Fetching PM data for {requirementsList.Count} requirement(s)");

            var result = new Dictionary<string, PMTicket>();
            var tasks = new List<Task>();

            foreach (var requirement in requirementsList)
            {
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        // Acquire semaphore to limit concurrency
                        await _concurrencyLimiter.WaitAsync();
                        try
                        {
                            var ticket = await FetchTicketWithCacheAsync(requirement);
                            if (ticket != null)
                            {
                                lock (result)
                                {
                                    result[requirement] = ticket;
                                }
                            }
                        }
                        finally
                        {
                            _concurrencyLimiter.Release();
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.Warning($"Failed to fetch PM data for {requirement}: {ex.Message}");
                    }
                }));
            }

            await Task.WhenAll(tasks);

            // Save updated cache
            SaveCache();

            _logger.Info($"Successfully fetched {result.Count} ticket(s)");
            return result;
        }

        /// <summary>
        /// Fetch a single ticket with cache checking
        /// </summary>
        private async Task<PMTicket?> FetchTicketWithCacheAsync(string requirementId)
        {
            // Check cache first
            if (_cache.TryGetValue(requirementId, out var cacheEntry) && !cacheEntry.IsExpired)
            {
                _logger.Info($"Using cached data for {requirementId}");
                return cacheEntry.Ticket;
            }

            // Fetch from platform
            try
            {
                _logger.Info($"Searching PM platform for {requirementId}");
                var results = await _platform.SearchTicketsByRequirementAsync(requirementId);

                if (results == null || results.Count == 0)
                {
                    _logger.Warning($"No PM ticket found for {requirementId}");
                    return null;
                }

                // Return first match (most relevant)
                var ticket = results[0];
                ticket.Platform = _config.Platform;

                // Update cache
                _cache[requirementId] = new PMCacheEntry
                {
                    Ticket = ticket,
                    ExpiresAt = DateTime.UtcNow.AddMinutes(_config.CacheTtlMinutes)
                };

                _logger.Info($"Found PM ticket for {requirementId}: {ticket.Key}");
                return ticket;
            }
            catch (PMIntegrationException ex)
            {
                _logger.Warning($"PM integration error for {requirementId}: {ex.Message}");
                return null;
            }
            catch (Exception ex)
            {
                _logger.Warning($"Error fetching PM data for {requirementId}: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Clear all cached ticket data
        /// </summary>
        public async Task ClearCacheAsync()
        {
            _logger.Info("Clearing PM ticket cache");
            _cache.Clear();

            // Delete cache file
            try
            {
                if (File.Exists(_cacheFilePath))
                {
                    File.Delete(_cacheFilePath);
                }
            }
            catch (Exception ex)
            {
                _logger.Warning($"Could not delete cache file: {ex.Message}");
            }

            await Task.CompletedTask;
        }

        /// <summary>
        /// Load cache from disk
        /// </summary>
        private void LoadCache()
        {
            try
            {
                if (!File.Exists(_cacheFilePath))
                    return;

                var json = File.ReadAllText(_cacheFilePath);
                var cacheDict = JsonSerializer.Deserialize<Dictionary<string, CacheEntryDto>>(json);

                if (cacheDict == null)
                    return;

                _cache = cacheDict.ToDictionary(
                    kvp => kvp.Key,
                    kvp => new PMCacheEntry
                    {
                        Ticket = kvp.Value.Ticket,
                        ExpiresAt = kvp.Value.ExpiresAt
                    }
                );

                // Remove expired entries
                var expiredKeys = _cache.Where(kvp => kvp.Value.IsExpired).Select(kvp => kvp.Key).ToList();
                foreach (var key in expiredKeys)
                {
                    _cache.Remove(key);
                }

                _logger.Info($"Loaded {_cache.Count} PM tickets from cache");
            }
            catch (Exception ex)
            {
                _logger.Warning($"Could not load cache: {ex.Message}");
                _cache = new Dictionary<string, PMCacheEntry>();
            }
        }

        /// <summary>
        /// Save cache to disk
        /// </summary>
        private void SaveCache()
        {
            try
            {
                // Ensure output directory exists
                var directory = Path.GetDirectoryName(_cacheFilePath);
                if (directory != null && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                var cacheDict = _cache.ToDictionary(
                    kvp => kvp.Key,
                    kvp => new CacheEntryDto
                    {
                        Ticket = kvp.Value.Ticket,
                        ExpiresAt = kvp.Value.ExpiresAt
                    }
                );

                var json = JsonSerializer.Serialize(cacheDict, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_cacheFilePath, json);
            }
            catch (Exception ex)
            {
                _logger.Warning($"Could not save cache: {ex.Message}");
            }
        }

        /// <summary>
        /// DTO for JSON serialization
        /// </summary>
        private class CacheEntryDto
        {
            public PMTicket? Ticket { get; set; }
            public DateTime ExpiresAt { get; set; }
        }
    }
}
