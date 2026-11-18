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
                csv.AppendLine($"{CsvField(entry.Key)},{CsvField(reqs)},{CsvField(riskLevel)},{entry.Value.Count}");
            }

            return csv.ToString();
        }

        /// <summary>Quotes a CSV field and neutralises spreadsheet formulas (=, +, -, @ prefixes).</summary>
        internal static string CsvField(string? value)
        {
            var text = value ?? string.Empty;
            if (text.Length > 0 && "=+-@\t\r".IndexOf(text[0]) >= 0)
            {
                text = "'" + text;
            }
            return "\"" + text.Replace("\"", "\"\"") + "\"";
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
                    return $"<tr class='commit-row'><td class='commit-hash'><code>{EscapeHtml(commitShort)}</code></td><td>{badgesHtml}</td></tr>";
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
                    return $"<tr class='commit-row hidden-row'><td class='commit-hash'><code>{EscapeHtml(commitShort)}</code></td><td>{badgesHtml}</td></tr>";
                }));
            
            var commitTableRows = commitRows + hiddenCommitRows;
            var seeMoreCommitsBtn = totalCommits > visibleCommits ? $"<tr><td colspan='2' style='text-align:center; padding: 1rem;'><button onclick='toggleCommitRows(event)' class='see-more-btn' data-state='hidden'>See More ({totalCommits - visibleCommits} more)</button></td></tr>" : "";

            // Files and methods: one collapsible section per repository (service) when several were
            // analysed, otherwise a single flat table.
            var filesSectionHtml = BuildFilesSection(analysis, ticketData);
            var methodsSectionHtml = BuildMethodsSection(analysis, ticketData);

            var repoPath = analysis.RepositoryPath ?? (analysis.RepositoryPaths?.FirstOrDefault() ?? "Not Provided");

            return $@"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Trace Matrix – Traceability Report</title>
    <link href='https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Sora:wght@400;500;600;700&display=swap' rel='stylesheet'>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        :root {{
            --primary: #06b6d4;
            --primary-dark: #0284c7;
            --primary-light: #e0f2fe;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --slate-950: #030712;
            --slate-900: #0f172a;
            --slate-800: #1e293b;
            --slate-700: #334155;
            --slate-600: #475569;
            --slate-500: #64748b;
            --slate-400: #94a3b8;
            --slate-300: #cbd5e1;
            --slate-200: #e2e8f0;
            --slate-100: #f1f5f9;
            --slate-50: #f8fafc;
        }}

        body {{
            font-family: 'Sora', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(180deg, var(--slate-900) 0%, #1a1f35 100%);
            color: var(--slate-200);
            line-height: 1.6;
            letter-spacing: -0.2px;
        }}

        /* ====== HEADER ====== */
        header {{
            background: linear-gradient(135deg, var(--slate-900) 0%, var(--slate-800) 100%);
            color: white;
            padding: 4rem 2rem;
            position: relative;
            overflow: hidden;
            border-bottom: 2px solid transparent;
            border-image: linear-gradient(90deg, transparent, var(--primary), transparent) 1;
            box-shadow: 0 20px 40px -10px rgba(0, 0, 0, 0.4);
        }}

        header::before {{
            content: '';
            position: absolute;
            top: -60%;
            right: -5%;
            width: 500px;
            height: 500px;
            background: radial-gradient(circle, rgba(6, 182, 212, 0.12) 0%, transparent 70%);
            border-radius: 50%;
            filter: blur(60px);
        }}

        header::after {{
            content: '';
            position: absolute;
            bottom: -30%;
            left: -10%;
            width: 350px;
            height: 350px;
            background: radial-gradient(circle, rgba(6, 182, 212, 0.08) 0%, transparent 70%);
            border-radius: 50%;
            filter: blur(60px);
        }}

        header h1 {{
            font-size: 2.5rem;
            font-weight: 700;
            margin: 0 0 0.5rem 0;
            position: relative;
            z-index: 1;
            letter-spacing: -0.8px;
            background: linear-gradient(135deg, white 0%, rgba(255, 255, 255, 0.85) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}

        header p {{
            font-size: 1.05rem;
            opacity: 0.85;
            position: relative;
            z-index: 1;
            color: var(--slate-200);
            font-weight: 400;
            line-height: 1.7;
        }}

        /* ====== CONTAINER & LAYOUT ====== */
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 3rem 2rem;
        }}

        .card {{
            background: linear-gradient(135deg, var(--slate-800) 0%, #1a2332 100%);
            border-radius: 16px;
            padding: 2.5rem;
            margin-bottom: 2.5rem;
            box-shadow: 0 20px 40px -10px rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(6, 182, 212, 0.12);
            transition: all 0.3s cubic-bezier(0.23, 1, 0.32, 1);
            animation: slideUp 0.6s ease-out;
            position: relative;
            overflow: hidden;
        }}

        .card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, rgba(6, 182, 212, 0.2), transparent);
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
            box-shadow: 0 30px 60px -15px rgba(0, 0, 0, 0.4);
            border-color: rgba(6, 182, 212, 0.2);
            transform: translateY(-4px);
        }}

        .card.summary {{
            background: linear-gradient(135deg, rgba(6, 182, 212, 0.1) 0%, rgba(6, 182, 212, 0.05) 100%);
            border: 1.5px solid rgba(6, 182, 212, 0.2);
        }}

        .card h2 {{
            font-size: 1.5rem;
            margin: 0 0 1.5rem 0;
            color: white;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            position: relative;
            font-weight: 700;
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
            background: linear-gradient(135deg, var(--slate-700) 0%, var(--slate-800) 100%);
            padding: 1.75rem;
            border-radius: 12px;
            text-align: center;
            border: 1px solid rgba(6, 182, 212, 0.15);
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
            background: linear-gradient(90deg, var(--primary), transparent);
        }}

        .stat-box:hover {{
            border-color: rgba(6, 182, 212, 0.4);
            box-shadow: 0 10px 30px rgba(6, 182, 212, 0.15);
            transform: translateY(-6px);
            background: linear-gradient(135deg, var(--slate-700) 0%, var(--slate-750) 100%);
        }}

        .stat-box .number {{
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--primary);
            margin: 0.5rem 0;
            background: linear-gradient(135deg, var(--primary), #0ea5e9);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}

        .stat-box .label {{
            font-size: 0.8rem;
            color: var(--slate-400);
            text-transform: uppercase;
            letter-spacing: 0.6px;
            font-weight: 600;
        }}

        /* ====== TABLES ====== */
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1.5rem;
        }}

        th {{
            background: linear-gradient(90deg, rgba(6, 182, 212, 0.08) 0%, rgba(6, 182, 212, 0.04) 100%);
            padding: 1.25rem;
            text-align: left;
            font-weight: 700;
            color: var(--primary);
            border-bottom: 2px solid rgba(6, 182, 212, 0.3);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.6px;
            background-color: rgba(6, 182, 212, 0.08);
        }}

        td {{
            padding: 1.25rem;
            border-bottom: 1px solid rgba(6, 182, 212, 0.1);
            color: var(--slate-200);
            font-size: 0.95rem;
        }}

        tr {{
            transition: all 0.2s ease;
        }}

        tr:hover {{
            background: rgba(6, 182, 212, 0.05);
            box-shadow: inset 0 0 10px rgba(6, 182, 212, 0.08);
        }}

        tr:last-child td {{
            border-bottom: none;
        }}

        /* ====== BADGES ====== */
        .badge {{
            display: inline-block;
            background: linear-gradient(135deg, var(--primary) 0%, #0e7490 100%);
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 8px;
            margin: 0.3rem 0.3rem 0.3rem 0;
            font-size: 0.75rem;
            font-weight: 700;
            white-space: nowrap;
            box-shadow: 0 4px 12px rgba(6, 182, 212, 0.25);
            transition: all 0.2s ease;
            letter-spacing: 0.3px;
        }}

        .badge:hover {{
            transform: translateY(-3px) scale(1.05);
            box-shadow: 0 6px 20px rgba(6, 182, 212, 0.35);
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
            transform: translateY(-4px) scale(1.08);
            box-shadow: 0 8px 24px rgba(6, 182, 212, 0.4);
        }}

        /* ====== TICKET LINKS (PM INTEGRATION) ====== */
        .ticket-link {{
            color: var(--primary);
            text-decoration: none;
            font-weight: 700;
            padding: 0.5rem 0.875rem;
            border-radius: 6px;
            display: inline-block;
            transition: all 0.2s ease;
            margin-right: 0.5rem;
            border: 1px solid rgba(6, 182, 212, 0.3);
            background: rgba(6, 182, 212, 0.08);
            font-size: 0.85rem;
        }}

        .ticket-link:hover {{
            background: rgba(6, 182, 212, 0.15);
            text-decoration: none;
            transform: translateX(2px);
            border-color: var(--primary);
            box-shadow: 0 4px 12px rgba(6, 182, 212, 0.2);
        }}

        .ticket-link::before {{
            content: '🔗 ';
            opacity: 0.8;
            margin-right: 4px;
        }}

        /* Platform badges */
        .platform-badge {{
            display: inline-block;
            padding: 0.4rem 0.875rem;
            border-radius: 12px;
            font-size: 0.7rem;
            font-weight: 700;
            margin-left: 0.5rem;
            text-transform: uppercase;
            letter-spacing: 0.4px;
            color: white;
            vertical-align: middle;
        }}

        .badge-jira {{
            background: linear-gradient(135deg, #0052cc 0%, #003d99 100%);
        }}

        .badge-clickup {{
            background: linear-gradient(135deg, #7b68ee 0%, #6f5dd9 100%);
        }}

        .badge-ado {{
            background: linear-gradient(135deg, #0078d4 0%, #005ba1 100%);
        }}

        .ticket-data {{
            font-size: 0.85rem;
            color: var(--slate-300);
            margin: 0.5rem 0;
            font-weight: 500;
        }}

        .no-ticket-data {{
            color: var(--slate-500);
            font-style: italic;
            font-size: 0.85rem;
        }}

        .expand-btn {{
            display: inline-block;
            background: linear-gradient(135deg, var(--danger) 0%, #dc2626 100%);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 700;
            cursor: pointer;
            margin-left: 0.5rem;
            transition: all 0.2s ease;
            box-shadow: 0 4px 12px rgba(239, 68, 68, 0.25);
            letter-spacing: 0.3px;
        }}

        .expand-btn:hover {{
            background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(239, 68, 68, 0.35);
        }}

        .expanded-badges {{
            display: inline-block;
            margin-left: 0.875rem;
            margin-top: 0.875rem;
            padding: 1rem;
            background: rgba(6, 182, 212, 0.08);
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
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 12px rgba(6, 182, 212, 0.25);
            font-size: 0.85rem;
            letter-spacing: 0.3px;
            text-transform: uppercase;
        }}

        .see-more-btn:hover {{
            background: linear-gradient(135deg, var(--primary-dark) 0%, #0369a1 100%);
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(6, 182, 212, 0.35);
        }}

        .see-more-btn:active {{
            transform: translateY(0);
        }}

        /* ====== CODE & CELLS ====== */
        code {{
            background: rgba(6, 182, 212, 0.1);
            padding: 0.4rem 0.75rem;
            border-radius: 6px;
            font-family: 'Space Mono', monospace;
            font-size: 0.8rem;
            color: #22d3ee;
            border: 1px solid rgba(6, 182, 212, 0.2);
            font-weight: 500;
        }}

        .commit-hash {{
            font-weight: 700;
            color: var(--primary);
            font-family: 'Space Mono', monospace;
        }}

        .file-name {{
            font-weight: 600;
            color: var(--slate-100);
            word-break: break-word;
            font-family: 'Space Mono', monospace;
        }}

        .file-row[data-risk='5'],
        .file-row[data-risk='6'] {{
            background: rgba(239, 68, 68, 0.08) !important;
        }}

        .file-row[data-risk='3'],
        .file-row[data-risk='4'] {{
            background: rgba(245, 158, 11, 0.08) !important;
        }}

        /* Repository (service) groups */
        .group-toolbar {{
            display: flex;
            justify-content: flex-end;
            gap: 0.5rem;
            margin-bottom: 1rem;
        }}

        .group-toolbar button {{
            background: transparent;
            color: var(--slate-300, #cbd5e1);
            border: 1px solid rgba(6, 182, 212, 0.35);
            border-radius: 6px;
            padding: 0.35rem 0.8rem;
            font: inherit;
            font-size: 0.8rem;
            cursor: pointer;
        }}

        .group-toolbar button:hover {{
            background: rgba(6, 182, 212, 0.12);
        }}

        details.repo-group {{
            border: 1px solid rgba(6, 182, 212, 0.2);
            border-radius: 10px;
            margin-bottom: 1rem;
            overflow: hidden;
        }}

        details.repo-group > summary {{
            list-style: none;
            cursor: pointer;
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 0.5rem 1rem;
            padding: 0.9rem 1.1rem;
            background: rgba(6, 182, 212, 0.07);
        }}

        details.repo-group > summary::-webkit-details-marker {{
            display: none;
        }}

        details.repo-group > summary::before {{
            content: '\25B8';
            color: #67e8f9;
            transition: transform 0.2s ease;
        }}

        details.repo-group[open] > summary::before {{
            transform: rotate(90deg);
        }}

        details.repo-group > summary:focus-visible {{
            outline: 3px solid #67e8f9;
            outline-offset: -3px;
        }}

        .repo-name {{
            font-weight: 700;
            color: #e2e8f0;
            font-size: 1rem;
        }}

        .repo-stats {{
            color: #94a3b8;
            font-size: 0.85rem;
        }}

        .risk-pill {{
            margin-left: auto;
            font-size: 0.75rem;
            font-weight: 700;
            padding: 0.2rem 0.65rem;
            border-radius: 999px;
            border: 1px solid currentColor;
        }}

        .risk-pill.risk-6 {{ color: #f87171; }}
        .risk-pill.risk-4 {{ color: #fb923c; }}
        .risk-pill.risk-3 {{ color: #fbbf24; }}
        .risk-pill.risk-1 {{ color: #34d399; }}
        .risk-pill.risk-0 {{ color: #94a3b8; }}

        details.repo-group table {{
            margin: 0;
        }}

        .group-note {{
            color: #94a3b8;
            font-size: 0.8rem;
            padding: 0.6rem 1.1rem;
        }}

        .risk-cell {{
            font-weight: 700;
            text-align: center;
            color: var(--primary);
        }}

        .method-name {{
            font-weight: 700;
            color: var(--slate-100);
            font-family: 'Space Mono', monospace;
            font-size: 0.85rem;
        }}

        .file-ref, .lines, .changes {{
            font-family: 'Space Mono', monospace;
            font-size: 0.85rem;
            color: var(--slate-300);
            font-weight: 500;
        }}

        /* ====== METADATA ====== */
        .metadata {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.5rem;
            margin-top: 1.5rem;
        }}

        .metadata-item {{
            padding: 1.5rem;
            background: linear-gradient(135deg, rgba(6, 182, 212, 0.08) 0%, rgba(6, 182, 212, 0.03) 100%);
            border-radius: 12px;
            border-left: 4px solid var(--primary);
            border: 1px solid rgba(6, 182, 212, 0.15);
            transition: all 0.3s ease;
        }}

        .metadata-item:hover {{
            transform: translateX(4px);
            box-shadow: 0 8px 24px rgba(6, 182, 212, 0.12);
            border-color: rgba(6, 182, 212, 0.3);
        }}

        .metadata-item strong {{
            display: block;
            color: var(--slate-100);
            margin-bottom: 0.75rem;
            font-weight: 700;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.6px;
            color: var(--primary);
        }}

        .metadata-item span {{
            color: var(--slate-300);
            word-break: break-all;
            font-size: 0.95rem;
            font-weight: 500;
        }}

        /* ====== RESPONSIVE ====== */
        /* Phones: file and method rows become stacked blocks so names never break mid-word */
        @media (max-width: 640px) {{
            table:has(tr.file-row) thead,
            table:has(tr.method-row) thead {{
                display: none;
            }}

            tr.file-row,
            tr.method-row {{
                display: grid;
                grid-template-columns: repeat(3, auto) 1fr;
                gap: 0.35rem 1rem;
                align-items: center;
                padding: 0.9rem 1rem;
                border-bottom: 1px solid rgba(148, 163, 184, 0.12);
            }}

            tr.file-row td,
            tr.method-row td {{
                padding: 0;
                border: none;
                text-align: left;
            }}

            tr.file-row td.file-name,
            tr.method-row td.method-name,
            tr.method-row td.file-ref {{
                grid-column: 1 / -1;
                word-break: normal;
                overflow-wrap: anywhere;
            }}

            tr.file-row td.reqs-cell,
            tr.method-row td.reqs-cell {{
                grid-column: 1 / -1;
            }}

            tr.file-row td[data-label]::before,
            tr.method-row td[data-label]::before {{
                content: attr(data-label);
                display: block;
                font-size: 0.7rem;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                color: #94a3b8;
                margin-bottom: 0.2rem;
            }}
        }}

        @media (max-width: 768px) {{
            .container {{
                padding: 1.5rem;
            }}

            .card {{
                padding: 1.75rem;
                margin-bottom: 1.5rem;
            }}

            header {{
                padding: 2.5rem 1.5rem;
            }}

            header h1 {{
                font-size: 1.75rem;
            }}

            header p {{
                font-size: 0.95rem;
            }}

            table {{
                font-size: 0.85rem;
            }}

            th, td {{
                padding: 0.875rem;
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

            .badge {{
                padding: 0.375rem 0.75rem;
                font-size: 0.7rem;
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
        .traceicon {{
            -webkit-text-fill-color: #4CAF50;
        }}
    </style>
</head>
<body>
    <header>
        <h1><span class='traceicon'>📊</span> Trace Matrix</h1>
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
            <p style='color: var(--slate-400); margin-bottom: 1rem; font-size: 0.9rem; font-weight: 500;'>Mapping of commits to their associated requirements</p>
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
            <p style='color: var(--slate-400); margin-bottom: 1rem; font-size: 0.9rem; font-weight: 500;'>Source files mapped to their requirements and risk levels</p>
            {filesSectionHtml}
        </div>

        <!-- PM Integration Section (if tickets available) -->
        {(ticketData.Count > 0 ? $@"
        <div class='card'>
            <h2>✨ Requirements with PM Integration</h2>
            <p style='color: var(--slate-400); margin-bottom: 1rem; font-size: 0.9rem; font-weight: 500;'>Requirements enriched with ticket data from your PM platform</p>
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
            <p style='color: var(--slate-400); margin-bottom: 1rem; font-size: 0.9rem; font-weight: 500;'>Methods tracked by requirements with change history</p>
            {methodsSectionHtml}
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
                    <span>{EscapeHtml(repoPath)}</span>
                </div>
                <div class='metadata-item'>
                    <strong>Filtered Requirement</strong>
                    <span>{(string.IsNullOrEmpty(analysis.FilteredByRequirementId) ? "None - Full Analysis" : analysis.FilteredByRequirementId)}</span>
                </div>
                <div class='metadata-item'>
                    <strong>Report Type</strong>
                    <span>{(ticketData.Count > 0 ? "✨ Enriched with PM Data" : "Complete Traceability Analysis")}</span>
                </div>
            </div>
        </div>

    </div>

    <script>
        document.querySelectorAll('table tbody tr').forEach(row => {{
            row.addEventListener('mouseenter', function() {{
                this.style.boxShadow = 'inset 0 0 10px rgba(6, 182, 212, 0.1)';
            }});
            row.addEventListener('mouseleave', function() {{
                this.style.boxShadow = 'none';
            }});
        }});

        // Expand or collapse every repository section in one table
        function setRepoGroups(btn, open) {{
            var card = btn.closest('.card');
            card.querySelectorAll('details.repo-group').forEach(function (d) {{ d.open = open; }});
        }}

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
                    btn.style.background = 'linear-gradient(135deg, #dc2626 0%, #b91c1c 100%)';
                    btn.style.color = 'white';
                }} else {{
                    expandedDiv.style.display = 'none';
                    var count = expandedDiv.querySelectorAll('.badge').length;
                    btn.textContent = '+' + count;
                    btn.style.background = 'linear-gradient(135deg, var(--danger) 0%, #dc2626 100%)';
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

        private const int MaxMethodsPerTable = 30;

        /// <summary>
        /// Splits "{repo}/{path}" into its repository name and repository-relative path.
        /// Returns null as the repository when the path has no known prefix.
        /// </summary>
        internal static (string? repository, string relativePath) SplitRepository(string path, IReadOnlyList<string> repositoryNames)
        {
            foreach (var name in repositoryNames.OrderByDescending(n => n.Length))
            {
                if (path.StartsWith(name + "/", StringComparison.Ordinal))
                    return (name, path.Substring(name.Length + 1));
            }
            return (null, path);
        }

        private static bool IsGrouped(AnalysisResult analysis) => (analysis.RepositoryNames?.Count ?? 0) > 1;

        /// <summary>Single-repository reports drop the redundant "{repo}/" prefix from paths.</summary>
        private static string DisplayPath(AnalysisResult analysis, string path) =>
            analysis.RepositoryNames?.Count == 1 ? SplitRepository(path, analysis.RepositoryNames).relativePath : path;

        private string FileRowHtml(string displayPath, ICollection<string> requirements, Dictionary<string, PMTicket> ticketData)
        {
            var reqs = requirements.ToList();
            // data-label is shown as a caption when rows are stacked on narrow screens
            return $"<tr class='file-row' data-risk='{GetRiskNumericValue(reqs.Count)}'><td class='file-name'>{EscapeHtml(displayPath)}</td>" +
                   $"<td class='reqs-cell' data-label='Requirements'>{GenerateBadgeHtml(reqs, ticketData)}</td><td class='risk-cell' data-label='Risk'>{GetRiskLevel(reqs.Count)}</td></tr>";
        }

        private string MethodRowHtml(MethodInfo method, Dictionary<string, PMTicket> ticketData)
        {
            var reqs = method.Requirements?.ToList() ?? new List<string>();
            return $"<tr class='method-row'><td class='method-name'>{EscapeHtml(method.MethodName)}</td><td class='file-ref'>{EscapeHtml(Path.GetFileName(method.FilePath))}</td>" +
                   $"<td class='lines' data-label='Lines'>{method.LineStart} - {method.LineEnd}</td><td class='changes' data-label='Changes'>{method.ChangeCount}</td>" +
                   $"<td class='reqs-cell' data-label='Requirements'>{GenerateBadgeHtml(reqs, ticketData)}</td></tr>";
        }

        private static string FileTableHtml(string rows) =>
            "<table><thead><tr><th>File Path</th><th>Requirements</th><th>Risk Level</th></tr></thead>" +
            $"<tbody>{rows}</tbody></table>";

        private static string MethodTableHtml(string rows) =>
            "<table><thead><tr><th>Method Name</th><th>File</th><th>Lines</th><th>Changes</th><th>Requirements</th></tr></thead>" +
            $"<tbody>{rows}</tbody></table>";

        private const string GroupToolbarHtml =
            "<div class='group-toolbar'>" +
            "<button type='button' onclick='setRepoGroups(this, true)'>Expand all</button>" +
            "<button type='button' onclick='setRepoGroups(this, false)'>Collapse all</button></div>";

        private string GroupHtml(string repository, string stats, int highestRequirementCount, string tableHtml, string? note = null) =>
            "<details class='repo-group' open><summary>" +
            $"<span class='repo-name'>{EscapeHtml(repository)}</span>" +
            $"<span class='repo-stats'>{EscapeHtml(stats)}</span>" +
            $"<span class='risk-pill risk-{GetRiskNumericValue(highestRequirementCount)}'>Highest risk: {GetRiskLevel(highestRequirementCount)}</span>" +
            $"</summary>{tableHtml}{(note != null ? $"<div class='group-note'>{EscapeHtml(note)}</div>" : "")}</details>";

        private string BuildFilesSection(AnalysisResult analysis, Dictionary<string, PMTicket> ticketData)
        {
            var files = analysis.FileToRequirements ?? new Dictionary<string, HashSet<string>>();

            if (!IsGrouped(analysis))
            {
                return FileTableHtml(string.Join("", files
                    .OrderByDescending(f => f.Value.Count)
                    .Select(f => FileRowHtml(DisplayPath(analysis, f.Key), f.Value, ticketData))));
            }

            var groups = files
                .Select(f => (split: SplitRepository(f.Key, analysis.RepositoryNames), reqs: f.Value))
                .GroupBy(f => f.split.repository ?? "Other")
                .Select(g => new
                {
                    Name = g.Key,
                    Files = g.OrderByDescending(f => f.reqs.Count).ThenBy(f => f.split.relativePath, StringComparer.OrdinalIgnoreCase).ToList(),
                    Highest = g.Max(f => f.reqs.Count),
                    Requirements = g.SelectMany(f => f.reqs).Distinct().Count()
                })
                // Riskiest service first, so the overall "what is most at risk" view is kept.
                .OrderByDescending(g => g.Highest).ThenByDescending(g => g.Files.Count).ThenBy(g => g.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (groups.Count == 0)
                return FileTableHtml("");

            return GroupToolbarHtml + string.Join("", groups.Select(g =>
                GroupHtml(
                    g.Name,
                    $"{g.Files.Count} file{(g.Files.Count == 1 ? "" : "s")} · {g.Requirements} requirement{(g.Requirements == 1 ? "" : "s")}",
                    g.Highest,
                    FileTableHtml(string.Join("", g.Files.Select(f => FileRowHtml(f.split.relativePath, f.reqs, ticketData)))))));
        }

        private string BuildMethodsSection(AnalysisResult analysis, Dictionary<string, PMTicket> ticketData)
        {
            var methods = (analysis.MethodToRequirements ?? new Dictionary<string, MethodInfo>()).Values.ToList();

            if (!IsGrouped(analysis) || methods.Count == 0)
            {
                return MethodTableHtml(string.Join("", methods
                    .OrderByDescending(m => m.ChangeCount)
                    .Take(MaxMethodsPerTable)
                    .Select(m => MethodRowHtml(m, ticketData))));
            }

            var groups = methods
                .GroupBy(m => SplitRepository(m.FilePath ?? "", analysis.RepositoryNames).repository ?? "Other")
                .Select(g => new
                {
                    Name = g.Key,
                    Methods = g.OrderByDescending(m => m.ChangeCount).ToList(),
                    Highest = g.Max(m => m.Requirements?.Count ?? 0),
                    Requirements = g.SelectMany(m => m.Requirements ?? new HashSet<string>()).Distinct().Count()
                })
                .OrderByDescending(g => g.Highest).ThenByDescending(g => g.Methods.Count).ThenBy(g => g.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();

            return GroupToolbarHtml + string.Join("", groups.Select(g =>
                GroupHtml(
                    g.Name,
                    $"{g.Methods.Count} method{(g.Methods.Count == 1 ? "" : "s")} · {g.Requirements} requirement{(g.Requirements == 1 ? "" : "s")}",
                    g.Highest,
                    MethodTableHtml(string.Join("", g.Methods.Take(MaxMethodsPerTable).Select(m => MethodRowHtml(m, ticketData)))),
                    g.Methods.Count > MaxMethodsPerTable
                        ? $"Showing the {MaxMethodsPerTable} most-changed of {g.Methods.Count} methods. The JSON export has all of them."
                        : null)));
        }

        private string GenerateBadgeHtml(List<string> reqs, Dictionary<string, PMTicket>? ticketData = null)
        {
            ticketData ??= new Dictionary<string, PMTicket>();
            
            // Helper function to generate badge HTML (clickable if PM data available)
            Func<string, string> GenerateBadge = (req) =>
            {
                var safeUrl = ticketData.TryGetValue(req, out var ticket) ? SafeHttpUrl(ticket.Url) : null;
                if (safeUrl != null)
                {
                    return $"<a href='{EscapeHtml(safeUrl)}' target='_blank' rel='noopener noreferrer' class='badge-link'><span class='badge'>{EscapeHtml(req)}</span></a>";
                }
                return $"<span class='badge'>{EscapeHtml(req)}</span>";
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
            html += $"<td><strong>{EscapeHtml(requirement)}</strong></td>";

            // Ticket cell with clickable link
            var safeTicketUrl = hasTicketData && ticket is not null ? SafeHttpUrl(ticket.Url) : null;
            if (hasTicketData && ticket is not null && safeTicketUrl != null)
            {
                var platformBadgeClass = ticket.Url.Contains("atlassian") ? "badge-jira" :
                                        ticket.Url.Contains("clickup") ? "badge-clickup" : "badge-ado";

                html += "<td>";
                html += $"<a href='{EscapeHtml(safeTicketUrl)}' target='_blank' rel='noopener noreferrer' class='ticket-link' title='Open {EscapeHtml(ticket.Platform)} ticket'>";
                html += $"{EscapeHtml(ticket.Key ?? "N/A")}: {EscapeHtml(ticket.Title ?? "N/A")}";
                html += "</a>";
                html += $"<span class='platform-badge {platformBadgeClass}'>{EscapeHtml(ticket.Platform)}</span>";
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

        /// <summary>Returns the URL only if it is an absolute http(s) URL (blocks javascript:, data:, ...).</summary>
        private static string? SafeHttpUrl(string? url)
        {
            return Uri.TryCreate(url, UriKind.Absolute, out var uri) &&
                   (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp)
                ? uri.AbsoluteUri
                : null;
        }

        internal static string EscapeHtml(string? text)
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
