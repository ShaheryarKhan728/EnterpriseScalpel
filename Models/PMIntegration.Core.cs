using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Scalpel.Enterprise
{
    /// <summary>
    /// Unified ticket/work item model across all PM platforms
    /// </summary>
    public class PMTicket
    {
        /// <summary>Platform-specific ID (PROJ-123, CLICK-456, #789)</summary>
        public string? Id { get; set; }

        /// <summary>Platform-specific key for display (PROJ-123, CLICK-456, #789)</summary>
        public string? Key { get; set; }

        /// <summary>Ticket title</summary>
        public string? Title { get; set; }

        /// <summary>Current status (In Progress, Done, To Do, etc)</summary>
        public string? Status { get; set; }

        /// <summary>Priority level (High, Medium, Low, Critical)</summary>
        public string? Priority { get; set; }

        /// <summary>Assigned person's name</summary>
        public string? Assignee { get; set; }

        /// <summary>Due date if available</summary>
        public DateTime? DueDate { get; set; }

        /// <summary>Direct URL to open ticket in PM platform</summary>
        public string? Url { get; set; }

        /// <summary>Platform name for badge display (JIRA, ClickUp, ADO)</summary>
        public string? Platform { get; set; }

        /// <summary>Timestamp when ticket data was fetched</summary>
        public DateTime FetchedAt { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// PM integration configuration
    /// </summary>
    public class PMConfig
    {
        /// <summary>Platform name: jira, clickup, or azuredevops</summary>
        public string? Platform { get; set; }

        /// <summary>Enable or disable PM integration</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>Base URL for the PM platform</summary>
        public string? BaseUrl { get; set; }

        /// <summary>API token/key for authentication</summary>
        public string? ApiToken { get; set; }

        /// <summary>JIRA only: email address for Basic Auth</summary>
        public string? Email { get; set; }

        /// <summary>JIRA/ADO: organization name</summary>
        public string? Organization { get; set; }

        /// <summary>ADO/ClickUp: project name</summary>
        public string? Project { get; set; }

        /// <summary>ClickUp only: workspace ID</summary>
        public string? WorkspaceId { get; set; }

        /// <summary>ClickUp only: list ID for searching tasks</summary>
        public string? ListId { get; set; }

        /// <summary>Cache TTL in minutes (default 60)</summary>
        public int CacheTtlMinutes { get; set; } = 60;

        /// <summary>Max concurrent HTTP requests (default 5)</summary>
        public int MaxConcurrency { get; set; } = 5;

        /// <summary>Request timeout in seconds (default 30)</summary>
        public int RequestTimeoutSeconds { get; set; } = 30;
    }

    /// <summary>
    /// Cache entry with expiration
    /// </summary>
    public class PMCacheEntry
    {
        /// <summary>Cached ticket data</summary>
        public PMTicket? Ticket { get; set; }

        /// <summary>When this cache entry expires</summary>
        public DateTime ExpiresAt { get; set; }

        /// <summary>Whether this cache entry has expired</summary>
        public bool IsExpired => DateTime.UtcNow > ExpiresAt;
    }

    /// <summary>
    /// Base interface for PM platform integrations
    /// </summary>
    public interface IPMPlatform
    {
        /// <summary>
        /// Fetch a single ticket by ID
        /// </summary>
        /// <param name="ticketId">Platform-specific ticket ID</param>
        /// <returns>PMTicket with full metadata</returns>
        /// <exception cref="PMIntegrationException">If ticket not found or authentication fails</exception>
        Task<PMTicket> GetTicketAsync(string ticketId);

        /// <summary>
        /// Search for tickets matching the requirement ID
        /// </summary>
        /// <param name="requirementId">Requirement ID to search for (e.g., "Req-123")</param>
        /// <returns>List of matching PMTickets</returns>
        /// <remarks>
        /// Implementation searches PM platform's text fields for requirementId.
        /// Returns empty list if no matches found (not an error).
        /// </remarks>
        Task<List<PMTicket>> SearchTicketsByRequirementAsync(string requirementId);

        /// <summary>
        /// Validate configuration is complete and correct
        /// </summary>
        /// <returns>True if configuration is valid</returns>
        bool ValidateConfig();
    }

    /// <summary>
    /// Exception for PM integration errors
    /// </summary>
    public class PMIntegrationException : Exception
    {
        public PMIntegrationException(string message) : base(message) { }
        public PMIntegrationException(string message, Exception innerException) 
            : base(message, innerException) { }
    }
}
