using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace Scalpel.Enterprise
{
    public class ReportService
    {
        public string SerializeAnalysisToJsonString(AnalysisResult analysis)
        {
            return JsonSerializer.Serialize(analysis, new JsonSerializerOptions { WriteIndented = true });
        }

        public string GenerateCsvFromAnalysis(AnalysisResult analysis)
        {
            var csv = new System.Text.StringBuilder();
            csv.AppendLine("File,Requirements,Risk Level,Change Count");

            foreach (var entry in analysis.FileToRequirements.OrderByDescending(f => f.Value.Count))
            {
                var reqs = string.Join(";", entry.Value);
                var riskLevel = GetRiskLevel(entry.Value.Count);
                csv.AppendLine($"\"{entry.Key}\",\"{reqs}\",\"{riskLevel}\",{entry.Value.Count}");
            }

            return csv.ToString();
        }

        private string GetRiskLevel(int requirementCount)
        {
            return requirementCount switch
            {
                0 => "None",
                1 => "Low",
                2 or 3 => "Medium",
                4 or 5 => "High",
                _ => "Critical"
            };
        }

        public string GenerateHtmlReport(AnalysisResult analysis, Dictionary<string, PMTicket>? ticketData = null)
        {
            ticketData ??= new Dictionary<string, PMTicket>();
            
            // Count total requirements
            var uniqueRequirements = new HashSet<string>();
            foreach (var reqs in analysis.CommitToRequirements.Values)
            {
                foreach (var req in reqs)
                {
                    uniqueRequirements.Add(req);
                }
            }

            // Generate commit rows - show only 5 with see more button
            var totalCommits = analysis.CommitToRequirements.Count;
            var visibleCommits = Math.Min(5, totalCommits);
            
            var commitRows = string.Join("", analysis.CommitToRequirements
                .Take(visibleCommits)
                .Select(kvp => {
                    var reqs = kvp.Value;
                    var fullKey = kvp.Key;
                    var commitHash = fullKey.Contains(":")
                        ? fullKey.Split(':')[1]
                        : fullKey;
                    var commitShort = commitHash.Length > 8
                        ? commitHash.Substring(0, 8)
                        : commitHash;
                    var badgesHtml = GenerateBadgeHtml(reqs, ticketData);
                    return $"<tr class='commit-row'><td class='commit-hash'><code>{commitShort}</code></td><td>{badgesHtml}</td></tr>";
                }));
            
            // Add hidden rows for remaining commits
            var hiddenCommitRows = string.Join("", analysis.CommitToRequirements
                .Skip(visibleCommits)
                .Select(kvp => {
                    var reqs = kvp.Value;
                    var fullKey = kvp.Key;
                    var commitHash = fullKey.Contains(":")
                        ? fullKey.Split(':')[1]
                        : fullKey;
                    var commitShort = commitHash.Length > 8
                        ? commitHash.Substring(0, 8)
                        : commitHash;
                    var badgesHtml = GenerateBadgeHtml(reqs, ticketData);
                    return $"<tr class='commit-row hidden-row'><td class='commit-hash'><code>{commitShort}</code></td><td>{badgesHtml}</td></tr>";
                }));
            
            var commitTableRows = commitRows + hiddenCommitRows;
            var seeMoreCommitsBtn = totalCommits > visibleCommits ? $"<tr><td colspan='2' style='text-align:center; padding: 1rem;'><button onclick='toggleCommitRows(event)' class='see-more-btn' data-state='hidden'>See More ({totalCommits - visibleCommits} more)</button></td></tr>" : "";

            // Generate file rows
            var fileRows = string.Join("", analysis.FileToRequirements
                .OrderByDescending(f => f.Value.Count)
                .Select(kvp => {
                    var reqs = kvp.Value.ToList();
                    var riskLevel = GetRiskLevel(reqs.Count);
                    var badgesHtml = GenerateBadgeHtml(reqs, ticketData);
                    return $"<tr class='file-row' data-risk='{GetRiskNumericValue(reqs.Count)}'><td class='file-name'>{kvp.Key}</td><td>{badgesHtml}</td><td class='risk-cell'>{riskLevel}</td></tr>";
                }));

            // Generate method rows (limited to first 30)
            var methodRows = string.Join("", (analysis.MethodToRequirements ?? new Dictionary<string, MethodInfo>())
                .Take(30)
                .OrderByDescending(m => m.Value.ChangeCount)
                .Select(kvp => {
                    var method = kvp.Value;
                    var methodName = method.MethodName;
                    var fileName = Path.GetFileName(method.FilePath);
                    var reqs = method.Requirements?.ToList() ?? new List<string>();
                    var badgesHtml = GenerateBadgeHtml(reqs, ticketData);
                    return $"<tr class='method-row'><td class='method-name'>{methodName}</td><td class='file-ref'>{fileName}</td><td class='lines'>{method.LineStart} - {method.LineEnd}</td><td class='changes'>{method.ChangeCount}</td><td>{badgesHtml}</td></tr>";
                }));

            var repoPath = analysis.RepositoryPath ?? (analysis.RepositoryPaths?.FirstOrDefault() ?? "Not Provided");

            return $@"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Enterprise Scalpel – Traceability Report</title>
    <link href='https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Geist:wght@300;400;600;700&display=swap' rel='stylesheet'>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        :root {{
            --primary: #3b82f6;
            --primary-dark: #1e40af;
            --primary-light: #eff6ff;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
            --neutral-900: #111827;
            --neutral-800: #1f2937;
            --neutral-700: #374151;
            --neutral-600: #4b5563;
            --neutral-200: #e5e7eb;
            --neutral-100: #f3f4f6;
            --neutral-50: #f9fafb;
            --bg-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --surface-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --surface-shadow-lg: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
        }}

        body {{
            font-family: 'Geist', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(180deg, var(--neutral-50) 0%, #f0f9ff 100%);
            color: var(--neutral-800);
            line-height: 1.6;
        }}

        /* ====== HEADER ====== */
        header {{
            background: var(--bg-gradient);
            color: white;
            padding: 3rem 2rem;
            box-shadow: var(--surface-shadow-lg);
            position: relative;
            overflow: hidden;
        }}

        header::before {{
            content: '';
            position: absolute;
            top: -50%;
            right: -10%;
            width: 400px;
            height: 400px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 50%;
            filter: blur(40px);
        }}

        header h1 {{
            font-size: 2.5rem;
            font-weight: 700;
            margin: 0 0 0.5rem 0;
            position: relative;
            z-index: 1;
            letter-spacing: -0.5px;
        }}

        header p {{
            font-size: 1rem;
            opacity: 0.95;
            position: relative;
            z-index: 1;
        }}

        /* ====== CONTAINER & LAYOUT ====== */
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 3rem 2rem;
        }}

        .card {{
            background: white;
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: var(--surface-shadow);
            border: 1px solid var(--neutral-200);
            transition: all 0.3s cubic-bezier(0.23, 1, 0.320, 1);
            animation: slideUp 0.6s ease-out;
        }}

        @keyframes slideUp {{
            from {{
                opacity: 0;
                transform: translateY(20px);
            }}
            to {{
                opacity: 1;
                transform: translateY(0);
            }}
        }}

        .card:hover {{
            box-shadow: var(--surface-shadow-lg);
            transform: translateY(-2px);
        }}

        .card.summary {{
            background: linear-gradient(135deg, var(--primary-light) 0%, #f0fdf4 100%);
            border: 1px solid var(--neutral-200);
        }}

        .card h2 {{
            font-size: 1.5rem;
            margin: 0 0 1.5rem 0;
            color: var(--neutral-900);
            display: flex;
            align-items: center;
            gap: 0.75rem;
            position: relative;
        }}

        .card h2::after {{
            content: '';
            flex-grow: 1;
            height: 2px;
            background: linear-gradient(90deg, var(--primary) 0%, transparent 100%);
        }}

        /* ====== SUMMARY GRID ====== */
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-top: 1.5rem;
        }}

        .stat-box {{
            background: white;
            padding: 1.5rem;
            border-radius: 10px;
            text-align: center;
            border: 2px solid var(--neutral-200);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }}

        .stat-box::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 3px;
            background: var(--primary);
        }}

        .stat-box:hover {{
            border-color: var(--primary);
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.15);
            transform: translateY(-4px);
        }}

        .stat-box .number {{
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--primary);
            margin: 0.5rem 0;
        }}

        .stat-box .label {{
            font-size: 0.85rem;
            color: var(--neutral-600);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
        }}

        /* ====== TABLES ====== */
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1.5rem;
        }}

        th {{
            background: linear-gradient(90deg, var(--neutral-100) 0%, var(--neutral-50) 100%);
            padding: 1rem;
            text-align: left;
            font-weight: 600;
            color: var(--neutral-700);
            border-bottom: 2px solid var(--primary);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        td {{
            padding: 1rem;
            border-bottom: 1px solid var(--neutral-200);
            color: var(--neutral-700);
        }}

        tr:hover {{
            background: var(--neutral-50);
            transition: background 0.2s ease;
        }}

        tr:last-child td {{
            border-bottom: none;
        }}

        /* ====== BADGES ====== */
        .badge {{
            display: inline-block;
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: white;
            padding: 0.4rem 0.9rem;
            border-radius: 6px;
            margin: 0.3rem 0.3rem 0.3rem 0;
            font-size: 0.8rem;
            font-weight: 600;
            white-space: nowrap;
            box-shadow: 0 2px 4px rgba(59, 130, 246, 0.2);
            transition: all 0.2s ease;
        }}

        .badge:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(59, 130, 246, 0.3);
        }}

        /* ====== BADGE LINKS (PM INTEGRATION) ====== */
        .badge-link {{
            text-decoration: none;
            cursor: pointer;
            display: inline-block;
            transition: all 0.3s ease;
        }}

        .badge-link:hover {{
            text-decoration: none;
        }}

        .badge-link .badge {{
            transition: all 0.3s ease;
        }}

        .badge-link:hover .badge {{
            transform: translateY(-3px) scale(1.05);
            box-shadow: 0 6px 12px rgba(59, 130, 246, 0.4);
        }}

        /* ====== TICKET LINKS (PM INTEGRATION) ====== */
        .ticket-link {{
            color: #0066cc;
            text-decoration: none;
            font-weight: 600;
            padding: 6px 10px;
            border-radius: 6px;
            display: inline-block;
            transition: all 0.2s ease;
            margin-right: 8px;
            border: 1px solid #e0e7ff;
        }}

        .ticket-link:hover {{
            background: #e3f2fd;
            text-decoration: none;
            transform: translateX(2px);
            border-color: #0066cc;
            box-shadow: 0 2px 8px rgba(0, 102, 204, 0.15);
        }}

        .ticket-link::before {{
            content: '🔗 ';
            opacity: 0.7;
            margin-right: 4px;
        }}

        /* Platform badges */
        .platform-badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: bold;
            margin-left: 6px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: white;
            vertical-align: middle;
        }}

        .badge-jira {{
            background: #0052cc;
        }}

        .badge-clickup {{
            background: #7b68ee;
        }}

        .badge-ado {{
            background: #0078d4;
        }}

        .ticket-data {{
            font-size: 0.9rem;
            color: var(--neutral-600);
            margin: 4px 0;
        }}

        .no-ticket-data {{
            color: #999;
            font-style: italic;
            font-size: 0.9rem;
        }}

        .expand-btn {{
            display: inline-block;
            background: var(--danger);
            color: white;
            border: none;
            padding: 0.4rem 0.8rem;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 600;
            cursor: pointer;
            margin-left: 0.4rem;
            transition: all 0.2s ease;
            box-shadow: 0 2px 4px rgba(239, 68, 68, 0.2);
        }}

        .expand-btn:hover {{
            background: #dc2626;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(239, 68, 68, 0.3);
        }}

        .expanded-badges {{
            display: inline-block;
            margin-left: 0.75rem;
            padding: 0.75rem;
            background: var(--neutral-100);
            border-radius: 8px;
            border-left: 3px solid var(--primary);
        }}

        .hidden-row {{
            display: none;
        }}

        .see-more-btn {{
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: white;
            border: none;
            padding: 0.6rem 1.2rem;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 2px 8px rgba(59, 130, 246, 0.2);
        }}

        .see-more-btn:hover {{
            background: var(--primary-dark);
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
        }}

        /* ====== CODE & CELLS ====== */
        code {{
            background: var(--neutral-100);
            padding: 0.3rem 0.6rem;
            border-radius: 4px;
            font-family: 'Space Mono', monospace;
            font-size: 0.85rem;
            color: var(--primary-dark);
            border: 1px solid var(--neutral-200);
        }}

        .commit-hash {{
            font-weight: 600;
            color: var(--primary-dark);
        }}

        .file-name {{
            font-weight: 500;
            color: var(--neutral-800);
            word-break: break-word;
        }}

        .file-row[data-risk='5'],
        .file-row[data-risk='6'] {{
            background: rgba(239, 68, 68, 0.05) !important;
        }}

        .file-row[data-risk='3'],
        .file-row[data-risk='4'] {{
            background: rgba(245, 158, 11, 0.05) !important;
        }}

        .risk-cell {{
            font-weight: 600;
            text-align: center;
        }}

        .method-name {{
            font-weight: 600;
            color: var(--neutral-800);
            font-family: 'Space Mono', monospace;
        }}

        .file-ref, .lines, .changes {{
            font-family: 'Space Mono', monospace;
            font-size: 0.9rem;
            color: var(--neutral-600);
        }}

        /* ====== METADATA ====== */
        .metadata {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.5rem;
            margin-top: 1.5rem;
        }}

        .metadata-item {{
            padding: 1.25rem;
            background: linear-gradient(135deg, var(--primary-light) 0%, #fef2f2 100%);
            border-radius: 10px;
            border-left: 4px solid var(--primary);
            transition: all 0.3s ease;
        }}

        .metadata-item:hover {{
            transform: translateX(4px);
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.1);
        }}

        .metadata-item strong {{
            display: block;
            color: var(--neutral-900);
            margin-bottom: 0.5rem;
            font-weight: 600;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .metadata-item span {{
            color: var(--neutral-600);
            word-break: break-all;
            font-size: 0.95rem;
        }}

        /* ====== RESPONSIVE ====== */
        @media (max-width: 768px) {{
            .container {{
                padding: 1.5rem;
            }}

            .card {{
                padding: 1.5rem;
                margin-bottom: 1.5rem;
            }}

            header {{
                padding: 2rem 1.5rem;
            }}

            header h1 {{
                font-size: 1.75rem;
            }}

            table {{
                font-size: 0.9rem;
            }}

            th, td {{
                padding: 0.75rem;
            }}

            .summary-grid {{
                grid-template-columns: 1fr;
                gap: 1rem;
            }}

            .stat-box .number {{
                font-size: 2rem;
            }}

            .metadata {{
                grid-template-columns: 1fr;
            }}
        }}

        /* ====== ANIMATIONS ====== */
        @keyframes fadeIn {{
            from {{
                opacity: 0;
            }}
            to {{
                opacity: 1;
            }}
        }}

        .card {{
            animation: fadeIn 0.5s ease-out;
        }}
    </style>
</head>
<body>
    <header>
        <h1>📊 Enterprise Scalpel</h1>
        <p>Requirement Traceability & Impact Analysis Report</p>
    </header>

    <div class='container'>
        
        <!-- Summary Card -->
        <div class='card summary'>
            <h2>📈 Analysis Summary</h2>
            <div class='summary-grid'>
                <div class='stat-box'>
                    <div class='label'>Requirements</div>
                    <div class='number'>{uniqueRequirements.Count}</div>
                </div>
                <div class='stat-box'>
                    <div class='label'>Commits</div>
                    <div class='number'>{analysis.CommitToRequirements.Count}</div>
                </div>
                <div class='stat-box'>
                    <div class='label'>Files</div>
                    <div class='number'>{analysis.FileToRequirements.Count}</div>
                </div>
                <div class='stat-box'>
                    <div class='label'>Methods</div>
                    <div class='number'>{analysis.MethodToRequirements?.Count ?? 0}</div>
                </div>
            </div>
        </div>

        <!-- Commit to Requirements -->
        <div class='card'>
            <h2>🔗 Commits to Requirements</h2>
            <p style='color: var(--neutral-600); margin-bottom: 1rem; font-size: 0.9rem;'>Mapping of commits to their associated requirements</p>
            <table>
                <thead>
                    <tr>
                        <th>Commit Hash</th>
                        <th>Requirements</th>
                    </tr>
                </thead>
                <tbody>
                    {commitTableRows}
                    {seeMoreCommitsBtn}
                </tbody>
            </table>
        </div>

        <!-- File to Requirements -->
        <div class='card'>
            <h2>📁 Files to Requirements</h2>
            <p style='color: var(--neutral-600); margin-bottom: 1rem; font-size: 0.9rem;'>Source files mapped to their requirements and risk levels</p>
            <table>
                <thead>
                    <tr>
                        <th>File Path</th>
                        <th>Requirements</th>
                        <th>Risk Level</th>
                    </tr>
                </thead>
                <tbody>
                    {fileRows}
                </tbody>
            </table>
        </div>

        <!-- PM Integration Section (if tickets available) -->
        {(ticketData.Count > 0 ? $@"
        <div class='card'>
            <h2>✨ Requirements with PM Integration</h2>
            <p style='color: var(--neutral-600); margin-bottom: 1rem; font-size: 0.9rem;'>Requirements enriched with ticket data from your PM platform</p>
            <table>
                <thead>
                    <tr>
                        <th>Requirement ID</th>
                        <th>Ticket</th>
                        <th>Status</th>
                        <th>Priority</th>
                        <th>Assignee</th>
                        <th>Risk Score</th>
                        <th>Files Affected</th>
                    </tr>
                </thead>
                <tbody>
                    {string.Join("", uniqueRequirements
                        .OrderBy(r => r)
                        .Select(req => GenerateEnrichedRequirementRow(req, ticketData, analysis.FileToRequirements)))}
                </tbody>
            </table>
        </div>
        " : "")}

        <!-- Method Traceability -->
        <div class='card'>
            <h2>⚙️ Method Traceability</h2>
            <p style='color: var(--neutral-600); margin-bottom: 1rem; font-size: 0.9rem;'>Methods tracked by requirements with change history</p>
            <table>
                <thead>
                    <tr>
                        <th>Method Name</th>
                        <th>File</th>
                        <th>Lines</th>
                        <th>Changes</th>
                        <th>Requirements</th>
                    </tr>
                </thead>
                <tbody>
                    {methodRows}
                </tbody>
            </table>
        </div>

        <!-- Metadata -->
        <div class='card'>
            <h2>📅 Report Metadata</h2>
            <div class='metadata'>
                <div class='metadata-item'>
                    <strong>Analysis Date</strong>
                    <span>{analysis.AnalysisDate:yyyy-MM-dd HH:mm:ss}</span>
                </div>
                <div class='metadata-item'>
                    <strong>Repository Path</strong>
                    <span>{repoPath}</span>
                </div>
                <div class='metadata-item'>
                    <strong>Filtered Requirement</strong>
                    <span>{(string.IsNullOrEmpty(analysis.FilteredByRequirementId) ? "None - Full Analysis" : analysis.FilteredByRequirementId)}</span>
                </div>
                <div class='metadata-item'>
                    <strong>Report Type</strong>
                    <span>{(ticketData.Count > 0 ? "✨ Enriched with PM Data" : "Complete Traceability Analysis")}</span>
        <script>
        document.querySelectorAll('table tbody tr').forEach(row => {{
            row.addEventListener('mouseenter', function() {{
                this.style.boxShadow = 'inset 0 0 10px rgba(59, 130, 246, 0.1)';
            }});
            row.addEventListener('mouseleave', function() {{
                this.style.boxShadow = 'none';
            }});
        }});

        // Expand badge details
        function expandBadges(btn) {{
            var expandedDiv = btn.nextElementSibling;
            if (expandedDiv && expandedDiv.classList.contains('expanded-badges')) {{
                var computedStyle = window.getComputedStyle(expandedDiv);
                var isHidden = computedStyle.display === 'none';
                
                if (isHidden) {{
                    expandedDiv.style.display = 'inline-block';
                    var count = expandedDiv.querySelectorAll('.badge').length;
                    btn.textContent = '-' + count;
                    btn.style.background = '#dc2626';
                    btn.style.color = 'white';
                }} else {{
                    expandedDiv.style.display = 'none';
                    var count = expandedDiv.querySelectorAll('.badge').length;
                    btn.textContent = '+' + count;
                    btn.style.background = '#ef4444';
                    btn.style.color = 'white';
                }}
            }}
        }}

        // Toggle commit rows visibility
        function toggleCommitRows(event) {{
            event.preventDefault();
            var btn = event.target;
            var hiddenRows = document.querySelectorAll('tr.hidden-row');
            var isHidden = btn.getAttribute('data-state') === 'hidden';
            
            hiddenRows.forEach(row => {{
                row.style.display = isHidden ? 'table-row' : 'none';
            }});
            
            btn.setAttribute('data-state', isHidden ? 'visible' : 'hidden');
            btn.textContent = isHidden ? 'See Less' : ('See More (' + (hiddenRows.length) + ' more)');
        }}
    </script>
</body>
</html>";
        }

        private string GenerateBadgeHtml(List<string> reqs, Dictionary<string, PMTicket>? ticketData = null)
        {
            ticketData ??= new Dictionary<string, PMTicket>();
            
            // Helper function to generate badge HTML (clickable if PM data available)
            Func<string, string> GenerateBadge = (req) =>
            {
                if (ticketData.TryGetValue(req, out var ticket) && !string.IsNullOrEmpty(ticket.Url))
                {
                    return $"<a href='{ticket.Url}' target='_blank' class='badge-link'><span class='badge'>{req}</span></a>";
                }
                return $"<span class='badge'>{req}</span>";
            };

            if (reqs.Count <= 3)
            {
                return string.Join("", reqs.Select(GenerateBadge));
            }

            var badgesHtml = GenerateBadge(reqs[0]) +
                           $"<button class='expand-btn' onclick='expandBadges(this)'>+{reqs.Count - 1}</button>" +
                           $"<div class='expanded-badges' style='display:none'>" +
                           string.Join("", reqs.Skip(1).Select(GenerateBadge)) +
                           $"</div>";
            return badgesHtml;
        }

        private int GetRiskNumericValue(int requirementCount)
        {
            return requirementCount switch
            {
                0 => 0,
                1 => 1,
                2 or 3 => 3,
                4 or 5 => 4,
                _ => 6
            };
        }

        private string GenerateEnrichedRequirementRow(string requirement, 
            Dictionary<string, PMTicket> ticketData,
            Dictionary<string, HashSet<string>> fileToRequirements)
        {
            var hasTicketData = ticketData.TryGetValue(requirement, out var ticket);
            var filesAffected = fileToRequirements
                .Count(f => f.Value.Contains(requirement));
            var sharedFiles = fileToRequirements
                .Count(f => f.Value.Contains(requirement) && f.Value.Count > 1);

            // Calculate risk
            var riskScore = Math.Min(filesAffected * 10 + sharedFiles * 20, 100);
            var riskClass = riskScore >= 80 ? "risk-critical" :
                           riskScore >= 60 ? "risk-high" :
                           riskScore >= 30 ? "risk-medium" : "risk-low";

            var html = "<tr>";
            html += $"<td><strong>{requirement}</strong></td>";

            // Ticket cell with clickable link
            if (hasTicketData && ticket is not null && !string.IsNullOrEmpty(ticket.Url))
            {
                var platformBadgeClass = ticket.Url.Contains("atlassian") ? "badge-jira" :
                                        ticket.Url.Contains("clickup") ? "badge-clickup" : "badge-ado";

                html += "<td>";
                html += $"<a href='{EscapeHtml(ticket.Url)}' target='_blank' class='ticket-link' title='Open {ticket.Platform} ticket'>";
                html += $"{EscapeHtml(ticket.Key ?? "N/A")}: {EscapeHtml(ticket.Title ?? "N/A")}";
                html += "</a>";
                html += $"<span class='platform-badge {platformBadgeClass}'>{ticket.Platform}</span>";
                html += "</td>";
                html += $"<td class='ticket-data'>{EscapeHtml(ticket.Status ?? "-")}</td>";
                html += $"<td class='ticket-data'>{EscapeHtml(ticket.Priority ?? "-")}</td>";
                html += $"<td class='ticket-data'>{EscapeHtml(ticket.Assignee ?? "Unassigned")}</td>";
            }
            else
            {
                html += "<td class='no-ticket-data'>No ticket data</td>";
                html += "<td class='no-ticket-data'>-</td>";
                html += "<td class='no-ticket-data'>-</td>";
                html += "<td class='no-ticket-data'>-</td>";
            }

            html += $"<td class='{riskClass}'>{riskScore}/100</td>";
            html += $"<td>{filesAffected} files ({sharedFiles} shared)</td>";
            html += "</tr>";

            return html;
        }

        private string EscapeHtml(string? text)
        {
            if (string.IsNullOrEmpty(text))
                return text ?? "";

            return text
                .Replace("&", "&amp;")
                .Replace("<", "&lt;")
                .Replace(">", "&gt;")
                .Replace("\"", "&quot;")
                .Replace("'", "&#39;");
        }
    }
}
