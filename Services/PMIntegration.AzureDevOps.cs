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
    /// Azure DevOps REST API 7.0 integration
    /// </summary>
    public class AzureDevOpsPlatform : IPMPlatform
    {
        private readonly PMConfig _config;
        private readonly HttpClient _httpClient;

        public AzureDevOpsPlatform(PMConfig config)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _httpClient = new HttpClient();
            _httpClient.Timeout = TimeSpan.FromSeconds(config.RequestTimeoutSeconds);
        }

        public bool ValidateConfig()
        {
            return !string.IsNullOrWhiteSpace(_config.Organization) &&
                   !string.IsNullOrWhiteSpace(_config.Project) &&
                   !string.IsNullOrWhiteSpace(_config.ApiToken);
        }

        public async Task<PMTicket> GetTicketAsync(string workItemId)
        {
            if (string.IsNullOrWhiteSpace(workItemId) || !int.TryParse(workItemId, out _))
                throw new ArgumentException("Work item ID must be a numeric value", nameof(workItemId));

            try
            {
                var url = $"https://dev.azure.com/{_config.Organization}/{_config.Project}/" +
                         $"_apis/wit/workitems/{workItemId}?api-version=7.0";

                var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.Add("Authorization", GetBasicAuthHeader());

                var response = await _httpClient.SendAsync(request);
                response.EnsureSuccessStatusCode();

                var json = await response.Content.ReadAsStringAsync();
                var workItem = JsonSerializer.Deserialize<AzureDevOpsWorkItemDto>(json);

                var ticket = MapToTicket(workItem);
                if (ticket == null)
                    throw new PMIntegrationException($"Could not map Azure DevOps work item to ticket: {workItemId}");
                    
                return ticket;
            }
            catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                throw new PMIntegrationException($"Azure DevOps work item not found: {workItemId}", ex);
            }
            catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                throw new PMIntegrationException("Azure DevOps authentication failed. Check organization and PAT token.", ex);
            }
            catch (Exception ex)
            {
                throw new PMIntegrationException($"Error fetching Azure DevOps work item {workItemId}: {ex.Message}", ex);
            }
        }

        public async Task<List<PMTicket>> SearchTicketsByRequirementAsync(string requirementId)
        {
            if (string.IsNullOrWhiteSpace(requirementId))
                return new List<PMTicket>();

            try
            {
                // Use WIQL to search for requirement ID in title
                var wiqlQuery = new
                {
                    query = $"SELECT [System.Id] FROM WorkItems " +
                           $"WHERE [System.Title] CONTAINS '{EscapeWiql(requirementId)}' " +
                           $"AND [System.TeamProject] = '{EscapeWiql(_config.Project ?? "")}'"
                };

                var url = $"https://dev.azure.com/{_config.Organization}/{_config.Project}/_apis/wit/wiql?api-version=7.0";

                var request = new HttpRequestMessage(HttpMethod.Post, url);
                request.Headers.Add("Authorization", GetBasicAuthHeader());

                var jsonContent = JsonSerializer.Serialize(wiqlQuery);
                request.Content = new StringContent(jsonContent, Encoding.UTF8, "application/json");

                var response = await _httpClient.SendAsync(request);
                response.EnsureSuccessStatusCode();

                var json = await response.Content.ReadAsStringAsync();
                var searchResult = JsonSerializer.Deserialize<AzureDevOpsQueryResultDto>(json);

                if (searchResult?.WorkItems == null || searchResult.WorkItems.Count == 0)
                    return new List<PMTicket>();

                // Fetch full details for each work item
                var tickets = new List<PMTicket>();
                foreach (var workItemRef in searchResult.WorkItems.Take(10)) // Limit to 10 results
                {
                    try
                    {
                        var ticket = await GetTicketAsync(workItemRef.Id.ToString());
                        if (ticket != null)
                        {
                            tickets.Add(ticket);
                        }
                    }
                    catch (PMIntegrationException)
                    {
                        // Skip items that can't be fetched
                    }
                }

                return tickets;
            }
            catch (Exception ex)
            {
                throw new PMIntegrationException($"Error searching Azure DevOps for {requirementId}: {ex.Message}", ex);
            }
        }

        private PMTicket? MapToTicket(AzureDevOpsWorkItemDto? workItem)
        {
            if (workItem == null) return null;

            var fields = workItem.Fields ?? new Dictionary<string, object>();

            // Extract field values with fallback
            var title = GetFieldValue(fields, "System.Title", "No Title");
            var state = GetFieldValue(fields, "System.State", "Unknown");
            var priority = GetFieldValue(fields, "System.Priority", "3");
            var assignedTo = GetFieldValue(fields, "System.AssignedTo", "Unassigned");
            var iterationPath = GetFieldValue(fields, "System.IterationPath", "");

            // Parse assignee display name if it's in complex format
            if (assignedTo.Contains("<"))
            {
                assignedTo = assignedTo.Split('<')[0].Trim();
            }

            return new PMTicket
            {
                Id = workItem.Id.ToString(),
                Key = $"#{workItem.Id}",
                Title = title,
                Status = state,
                Priority = GetPriorityLabel(priority),
                Assignee = assignedTo,
                DueDate = null, // ADO doesn't have built-in due date
                Url = workItem.Url,
                Platform = "ADO"
            };
        }

        private string GetFieldValue(Dictionary<string, object> fields, string fieldName, string defaultValue)
        {
            if (fields.TryGetValue(fieldName, out var value))
            {
                return value?.ToString() ?? defaultValue;
            }
            return defaultValue;
        }

        private string GetPriorityLabel(string priority)
        {
            return priority switch
            {
                "1" => "Highest",
                "2" => "High",
                "3" => "Medium",
                "4" => "Low",
                _ => priority ?? "Medium"
            };
        }

        private string EscapeWiql(string value)
        {
            // WIQL uses single quotes for strings and escapes them by doubling
            return value.Replace("'", "''");
        }

        private string GetBasicAuthHeader()
        {
            var credentials = $":{_config.ApiToken}"; // Empty user, PAT as password
            var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials));
            return $"Basic {encoded}";
        }

        // DTOs for JSON deserialization
        private class AzureDevOpsWorkItemDto
        {
            [System.Text.Json.Serialization.JsonPropertyName("id")]
            public int Id { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("url")]
            public string? Url { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("fields")]
            public Dictionary<string, object>? Fields { get; set; }
        }

        private class AzureDevOpsWorkItemRefDto
        {
            [System.Text.Json.Serialization.JsonPropertyName("id")]
            public int Id { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("url")]
            public string? Url { get; set; }
        }

        private class AzureDevOpsQueryResultDto
        {
            [System.Text.Json.Serialization.JsonPropertyName("workItems")]
            public List<AzureDevOpsWorkItemRefDto>? WorkItems { get; set; }
        }
    }
}
