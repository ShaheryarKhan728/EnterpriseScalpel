using System;

namespace Scalpel.Enterprise
{
    /// <summary>
    /// Factory for creating platform-specific PM integration instances
    /// </summary>
    public class PMPlatformFactory
    {
        /// <summary>
        /// Create a platform-specific IPMPlatform instance
        /// </summary>
        /// <param name="config">PM configuration</param>
        /// <returns>IPMPlatform implementation for the configured platform</returns>
        /// <exception cref="PMIntegrationException">If platform is not supported</exception>
        public static IPMPlatform Create(PMConfig config)
        {
            if (config == null)
                throw new PMIntegrationException("PMConfig cannot be null");

            if (string.IsNullOrWhiteSpace(config.Platform))
                throw new PMIntegrationException("Platform must be specified in configuration");

            return config.Platform.ToLower() switch
            {
                "jira" => new JiraPlatform(config),
                "clickup" => new ClickUpPlatform(config),
                "azuredevops" or "ado" => new AzureDevOpsPlatform(config),
                _ => throw new PMIntegrationException($"Unsupported platform: {config.Platform}. " +
                    "Supported platforms: jira, clickup, azuredevops")
            };
        }
    }
}
