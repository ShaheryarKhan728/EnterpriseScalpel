using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace Scalpel.Enterprise
{
    /// <summary>
    /// ClickUp API v2 integration
    /// </summary>
    public class ClickUpPlatform : IPMPlatform
    {
        private readonly PMConfig _config;
        private readonly HttpClient _httpClient;
        private const string BaseUrl = "https://api.clickup.com/api/v2";

        public ClickUpPlatform(PMConfig config)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _httpClient = new HttpClient();
            _httpClient.Timeout = TimeSpan.FromSeconds(config.RequestTimeoutSeconds);
            _httpClient.DefaultRequestHeaders.Add("Authorization", config.ApiToken);
        }

        public bool ValidateConfig()
        {
            return !string.IsNullOrWhiteSpace(_config.ApiToken) &&
                   !string.IsNullOrWhiteSpace(_config.WorkspaceId);
            // ListId is optional (only required for search)
        }

        public async Task<PMTicket> GetTicketAsync(string ticketId)
        {
            if (string.IsNullOrWhiteSpace(ticketId))
                throw new ArgumentException("Task ID cannot be empty", nameof(ticketId));

            try
            {
                // [TEMPORARILY DISABLED] API call to ClickUp - using URL template instead
                /*
                var url = $"{BaseUrl}/task/{ticketId}";
                var response = await _httpClient.GetAsync(url);
                response.EnsureSuccessStatusCode();

                var json = await response.Content.ReadAsStringAsync();
                var task = JsonSerializer.Deserialize<ClickUpTaskDto>(json);

                var ticket = MapToTicket(task);
                if (ticket == null)
                    throw new PMIntegrationException($"Could not map ClickUp task to ticket: {ticketId}");
                    
                return ticket;
                */

                // Generate task URL using template: https://app.clickup.com/t/{WorkspaceId}/{TicketId}
                var taskUrl = $"https://app.clickup.com/t/{_config.WorkspaceId}/{ticketId}";
                var ticket = new PMTicket
                {
                    Id = ticketId,
                    Key = ticketId,
                    Title = $"Task: {ticketId}",
                    Status = "Unknown",
                    Priority = "Normal",
                    Assignee = "Unknown",
                    Url = taskUrl,
                    Platform = "ClickUp"
                };

                return await Task.FromResult(ticket);
            }
            catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                throw new PMIntegrationException($"ClickUp task not found: {ticketId}", ex);
            }
            catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                throw new PMIntegrationException("ClickUp authentication failed. Check API token.", ex);
            }
            catch (Exception ex)
            {
                throw new PMIntegrationException($"Error fetching ClickUp task {ticketId}: {ex.Message}", ex);
            }
        }

        public async Task<List<PMTicket>> SearchTicketsByRequirementAsync(string requirementId)
        {
            if (string.IsNullOrWhiteSpace(requirementId))
                return new List<PMTicket>();

            if (string.IsNullOrWhiteSpace(_config.ListId))
            {
                // Cannot search without list ID - fall back to URL generation
                // return new List<PMTicket>();
            }

            try
            {
                // [TEMPORARILY DISABLED] API call to ClickUp - using URL template instead
                /*
                var url = $"{BaseUrl}/list/{_config.ListId}/task?archived=false";
                var response = await _httpClient.GetAsync(url);
                response.EnsureSuccessStatusCode();

                var json = await response.Content.ReadAsStringAsync();
                var result = JsonSerializer.Deserialize<ClickUpTaskListDto>(json);

                // Filter tasks that contain requirement ID in name or description
                var matchingTasks = result?.Tasks?
                    .Where(t => (t?.Name?.Contains(requirementId, StringComparison.OrdinalIgnoreCase) ?? false) ||
                                (t?.Description?.Contains(requirementId, StringComparison.OrdinalIgnoreCase) ?? false))
                    .Select(t => MapToTicket(t))
                    .Where(t => t != null)
                    .Cast<PMTicket>()
                    .ToList() ?? new List<PMTicket>();

                return matchingTasks;
                */

                // Generate task URL using template: https://app.clickup.com/t/{WorkspaceId}/{RequirementId}
                var taskUrl = $"https://app.clickup.com/t/{_config.WorkspaceId}/{requirementId}";
                var ticket = new PMTicket
                {
                    Id = requirementId,
                    Key = requirementId,
                    Title = $"Task: {requirementId}",
                    Status = "Unknown",
                    Priority = "Normal",
                    Assignee = "Unknown",
                    Url = taskUrl,
                    Platform = "ClickUp"
                };

                return await Task.FromResult(new List<PMTicket> { ticket });
            }
            catch (Exception ex)
            {
                throw new PMIntegrationException($"Error searching ClickUp for {requirementId}: {ex.Message}", ex);
            }
        }

        private PMTicket? MapToTicket(ClickUpTaskDto? task)
        {
            if (task == null) return null;

            DateTime? dueDate = null;
            if (task.DueDate.HasValue)
            {
                dueDate = UnixTimeStampToDateTime(task.DueDate.Value / 1000);
            }

            return new PMTicket
            {
                Id = task.Id,
                Key = task.CustomId ?? task.Id,
                Title = task.Name ?? "No Title",
                Status = task.Status?.Status ?? "No Status",
                Priority = task.Priority?.Priority ?? "Normal",
                Assignee = task.Assignee?.Username ?? task.Assignee?.Email ?? "Unassigned",
                DueDate = dueDate,
                Url = task.Url ?? $"https://app.clickup.com/t/{task.Id}",
                Platform = "ClickUp"
            };
        }

        private static DateTime UnixTimeStampToDateTime(long unixTimeStamp)
        {
            var dateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            dateTime = dateTime.AddSeconds(unixTimeStamp).ToLocalTime();
            return dateTime;
        }

        // DTOs for JSON deserialization
        private class ClickUpTaskDto
        {
            [System.Text.Json.Serialization.JsonPropertyName("id")]
            public string? Id { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("custom_id")]
            public string? CustomId { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("name")]
            public string? Name { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("description")]
            public string? Description { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("status")]
            public ClickUpStatusDto? Status { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("priority")]
            public ClickUpPriorityDto? Priority { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("assignee")]
            public ClickUpAssigneeDto? Assignee { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("due_date")]
            public long? DueDate { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("url")]
            public string? Url { get; set; }
        }

        private class ClickUpStatusDto
        {
            [System.Text.Json.Serialization.JsonPropertyName("status")]
            public string? Status { get; set; }
        }

        private class ClickUpPriorityDto
        {
            [System.Text.Json.Serialization.JsonPropertyName("priority")]
            public string? Priority { get; set; }
        }

        private class ClickUpAssigneeDto
        {
            [System.Text.Json.Serialization.JsonPropertyName("username")]
            public string? Username { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("email")]
            public string? Email { get; set; }
        }

        private class ClickUpTaskListDto
        {
            [System.Text.Json.Serialization.JsonPropertyName("tasks")]
            public List<ClickUpTaskDto>? Tasks { get; set; }
        }
    }
}
