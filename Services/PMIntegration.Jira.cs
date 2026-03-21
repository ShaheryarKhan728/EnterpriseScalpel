using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Scalpel.Enterprise
{
    /// <summary>
    /// JIRA Cloud API v3 integration
    /// </summary>
    public class JiraPlatform : IPMPlatform
    {
        private readonly PMConfig _config;
        private readonly HttpClient _httpClient;

        public JiraPlatform(PMConfig config)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _httpClient = new HttpClient();
            _httpClient.Timeout = TimeSpan.FromSeconds(config.RequestTimeoutSeconds);
        }

        public bool ValidateConfig()
        {
            return !string.IsNullOrWhiteSpace(_config.BaseUrl) &&
                   !string.IsNullOrWhiteSpace(_config.Email) &&
                   !string.IsNullOrWhiteSpace(_config.ApiToken);
        }

        public async Task<PMTicket> GetTicketAsync(string ticketId)
        {
            if (string.IsNullOrWhiteSpace(ticketId))
                throw new ArgumentException("Ticket ID cannot be empty", nameof(ticketId));

            try
            {
                var url = $"{_config.BaseUrl?.TrimEnd('/')}/rest/api/3/issue/{ticketId}";
                var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.Add("Authorization", GetBasicAuthHeader());
                request.Headers.Add("Accept", "application/json");

                var response = await _httpClient.SendAsync(request);
                response.EnsureSuccessStatusCode();

                var json = await response.Content.ReadAsStringAsync();
                var issue = JsonSerializer.Deserialize<JiraIssueDto>(json);

                var ticket = MapToTicket(issue);
                if (ticket == null)
                    throw new PMIntegrationException($"Could not map JIRA issue to ticket: {ticketId}");
                    
                return ticket;
            }
            catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                throw new PMIntegrationException($"JIRA ticket not found: {ticketId}", ex);
            }
            catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                throw new PMIntegrationException("JIRA authentication failed. Check email and API token.", ex);
            }
            catch (Exception ex)
            {
                throw new PMIntegrationException($"Error fetching JIRA ticket {ticketId}: {ex.Message}", ex);
            }
        }

        public async Task<List<PMTicket>> SearchTicketsByRequirementAsync(string requirementId)
        {
            if (string.IsNullOrWhiteSpace(requirementId))
                return new List<PMTicket>();

            try
            {
                // Search for requirement ID in text fields (summary, description, comments)
                var jql = $"text ~ \"{requirementId}\"";
                var url = $"{_config.BaseUrl?.TrimEnd('/')}/rest/api/3/search?jql={Uri.EscapeDataString(jql)}&maxResults=50";

                var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.Add("Authorization", GetBasicAuthHeader());
                request.Headers.Add("Accept", "application/json");

                var response = await _httpClient.SendAsync(request);
                response.EnsureSuccessStatusCode();

                var json = await response.Content.ReadAsStringAsync();
                var searchResult = JsonSerializer.Deserialize<JiraSearchResultDto>(json);

                var result = searchResult?.Issues?                    .Select(i => MapToTicket(i))
                    .Where(t => t != null)
                    .Cast<PMTicket>()
                    .ToList() ?? new List<PMTicket>();
                    
                return result;
            }
            catch (Exception ex)
            {
                throw new PMIntegrationException($"Error searching JIRA for {requirementId}: {ex.Message}", ex);
            }
        }

        private PMTicket? MapToTicket(JiraIssueDto? issue)
        {
            if (issue == null) return null;

            var dueDate = issue.Fields?.DueDate;
            return new PMTicket
            {
                Id = issue.Id,
                Key = issue.Key,
                Title = issue.Fields?.Summary ?? "No Title",
                Status = issue.Fields?.Status?.Name ?? "Unknown",
                Priority = issue.Fields?.Priority?.Name ?? "Medium",
                Assignee = issue.Fields?.Assignee?.DisplayName ?? "Unassigned",
                DueDate = dueDate != null ? DateTime.Parse(dueDate) : null,
                Url = $"{_config.BaseUrl?.TrimEnd('/')}/browse/{issue?.Key}",
                Platform = "JIRA"
            };
        }

        private string GetBasicAuthHeader()
        {
            var credentials = $"{_config.Email}:{_config.ApiToken}";
            var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials));
            return $"Basic {encoded}";
        }

        // DTOs for JSON deserialization
        private class JiraIssueDto
        {
            public string? Id { get; set; }
            public string? Key { get; set; }
            public JiraFieldsDto? Fields { get; set; }
        }

        private class JiraFieldsDto
        {
            [System.Text.Json.Serialization.JsonPropertyName("summary")]
            public string? Summary { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("status")]
            public JiraStatusDto? Status { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("priority")]
            public JiraPriorityDto? Priority { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("assignee")]
            public JiraAssigneeDto? Assignee { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("duedate")]
            public string? DueDate { get; set; }
        }

        private class JiraStatusDto
        {
            [System.Text.Json.Serialization.JsonPropertyName("name")]
            public string? Name { get; set; }
        }

        private class JiraPriorityDto
        {
            [System.Text.Json.Serialization.JsonPropertyName("name")]
            public string? Name { get; set; }
        }

        private class JiraAssigneeDto
        {
            [System.Text.Json.Serialization.JsonPropertyName("displayName")]
            public string? DisplayName { get; set; }
        }

        private class JiraSearchResultDto
        {
            [System.Text.Json.Serialization.JsonPropertyName("issues")]
            public List<JiraIssueDto>? Issues { get; set; }
        }
    }
}
