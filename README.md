# Enterprise Scalpel

**Trace requirements through your codebase and actually understand what changed.**

Enterprise Scalpel is a CLI + web tool I built to solve a very real problem:
Figuring out what a requirement actually touched across a large codebase — especially when changes are spread across multiple commits, files, and branches.
Instead of guessing, this tool goes through your git history, picks out requirement IDs from commits, and maps them to the exact files and methods that were affected.

## Why this exists

In complex systems (especially where requirements like REQ-1234 are tied to commits), it's hard to answer questions like:

- What exactly did this requirement change?
- Which files are now risky because multiple requirements touched them?
- If I modify this file, what might I break?

I ran into this problem while working on enterprise systems. So I built something to make this visible.

## What it does
- Tracks requirements across commits using patterns like REQ-1234
- Maps them to files and actual methods that changed
- Works across branches and multiple repositories
- Filters out merge commits (to avoid duplicate/noisy data)
- Highlights:
  - high-risk files (touched by multiple requirements)
  - frequently changing areas (hotspots)
- Generates reports in HTML, JSON, CSV, or Markdown
- Can also run as a small web service with REST APIs

## Integration with Project Management Tools

You can link requirement IDs in your reports to your project management platform, so they’re not just static references.

While generating reports, you can configure your platform (e.g., ClickUp, Jira, or Azure DevOps). Once set up, every requirement ID (like REQ-1234) becomes clickable in the report.

Instead of manually searching for a task, you can just click and jump straight to it.

# This is especially useful when:

- reviewing impact during QA or release cycles
- discussing changes with stakeholders
- quickly validating what a requirement was supposed to do

It keeps the analysis connected to the actual source of truth, your task tracking system, instead of treating them as separate worlds.
  
## Requirements

- .NET 8+
- Git installed and available in PATH
- Access to the repositories you want to analyze

## Installation

### Clone the Repository
```bash
git clone https://github.com/ShaheryarKhan728/EnterpriseScalpel.git
cd EnterpriseScalpel
```

### Build the Project
```bash
dotnet build
```

### Run Tests
```bash
dotnet test
```

## 💻 Usage

### Command Line Interface

### Commands

#### 1. Analyze Requirements
Analyze one or more requirements across repositories:

```bash
# Analyze current repository
dotnet run analyze

# Analyze specific requirement in current repo
dotnet run analyze REQ-1234

# Analyze multiple repositories
dotnet run analyze --repos /path/to/repo1,/path/to/repo2

# Analyze requirement across multiple repos
dotnet run analyze --repos /path/to/repo1,/path/to/repo2 REQ-1234

# Analyze remote repositories
dotnet run analyze --repos https://github.com/org/repo.git REQ-1234
```

#### 2. File Impact Analysis
Analyze the impact of changes to a specific file:

```bash
dotnet run impact Services/PaymentService.cs
```

#### 3. Generate Reports
Generate analysis reports in different formats:

```bash
dotnet run report html
dotnet run report json
dotnet run report csv
dotnet run report markdown
```

#### 4. Find Code Hotspots
Identify high-risk areas with frequent changes and high complexity:

```bash
dotnet run hotspots
```

### Repository URL Formats

Enterprise Scalpel supports various repository URL formats with automatic branch detection:

#### GitHub Formats
```bash
# GitHub tree URL (branch will be extracted)
https://github.com/org/repo/tree/develop

# GitHub with hash notation
https://github.com/org/repo.git#main

# Standard Git URL (uses default branch)
https://github.com/org/repo.git
```

#### GitLab Formats
```bash
# GitLab tree URL (branch will be extracted)
https://gitlab.com/group/project/-/tree/develop

# GitLab with query parameters
https://gitlab.com/group/project/-/tree/staging?ref_type=heads

# GitLab with hash notation
https://gitlab.com/group/project.git#develop
```

#### Git SSH Format
```bash
# SSH URL with branch
git@github.com:org/repo.git#develop

# Standard SSH URL (uses default branch)
git@github.com:org/repo.git
```

## Web Interface

Enterprise Scalpel includes a web-based interface for analysis via REST API.

### Start Web Server
```bash
dotnet run serve
```

The server will start on `http://localhost:5001`

### REST API Endpoints

#### Generate Report
```
POST /api/generate-report
Content-Type: application/json

Request Body:
{
  "repositories": ["https://github.com/org/repo.git"],
  "requirementIds": ["REQ-1234"],
  "requirementPattern": "[A-Z]+-\\d+",
  "format": "html"  // or "json", "csv"
}

Response: Generated report in requested format
```

## How It Works

1. Scan git commits for requirement IDs
2. Ignore merge commits (they create noise)
3. Track which files changed per requirement
4. Parse C# files using Roslyn to find methods
5. Match actual changed lines to method ranges
6. Build a mapping:
   - requirement → file → method
7. Calculate risk based on overlap and change frequency

## A few important notes
- Merge commits are ignored on purpose
→ they often duplicate requirement IDs and distort results
- If you're analyzing a remote repo, always specify the branch
→ otherwise git defaults might give misleading results
- Method-level tracking is based on actual line changes
→ not just file-level guesses

## Project Structure

```
EnterpriseScalpel/
├── Services/
│   ├── EnterpriseScalpel.cs          # Main analysis engine
│   └── ReportService.cs              # Report generation
├── Models/
│   ├── AnalysisResult.cs             # Analysis output structure
│   ├── MethodInfo.cs                 # Method metadata
│   ├── RequirementImpact.cs          # Requirement impact data
│   ├── Hotspot.cs                    # Code hotspot definition
│   ├── Configuration.cs              # Configuration model
│   └── GenerateRequest.cs            # API request model
├── Logging/
│   ├── ILogger.cs                    # Logging interface
│   └── ConsoleLogger.cs              # Console implementation
├── wwwroot/                          # Web UI assets
├── scalpel.config.json               # Configuration file
├── Program.cs                        # Entry point
└── EnterpriseScalpel.csproj         # Project file
```
## Contributing

If you find something missing or want to improve it:

1. Fork the repo
2. Create a branch
3. Open a PR

**Author**
Shaheryar Khan
https://www.linkedin.com/in/shaheryarkhan28/
Emailshaheryar@gmail.com
