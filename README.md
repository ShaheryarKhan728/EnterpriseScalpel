# Enterprise Scalpel

**Enterprise-grade requirement traceability and impact analysis tool for software projects.**

Enterprise Scalpel is a powerful CLI and web-based tool that traces software requirements through your codebase by analyzing git commits, identifying affected files and methods, and providing comprehensive impact analysis reports. Perfect for enterprises managing complex regulatory requirements and change management.

## 🎯 Key Features

- **Requirement Traceability**: Automatically trace requirements across all commits in your repository
- **Method-Level Impact Analysis**: See exactly which methods are affected by each requirement
- **Branch Support**: Analyze specific branches using tree URLs or branch names
- **Multi-Repository Analysis**: Analyze requirements across multiple repositories simultaneously
- **Merge Commit Filtering**: Automatically excludes merge commits to avoid duplicate requirement tracking
- **File-Level Impact**: Identify which files are impacted by specific requirements
- **Risk Assessment**: Calculate risk scores based on file and method changes
- **Code Hotspots**: Detect high-change, high-complexity areas in your codebase
- **Multiple Report Formats**: Generate reports in HTML, JSON, CSV, and Markdown
- **Web Interface**: Run analysis through a REST API and web interface
- **Flexible Configuration**: Customize requirement patterns and analysis parameters

## 📋 Requirements

- **.NET 8.0** or higher
- **Git** (installed and available in PATH)
- Access to git repositories (local paths or remote URLs)

## 🚀 Installation

### Clone the Repository
```bash
git clone https://github.com/yourusername/EnterpriseScalpel.git
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

#### Basic Syntax
```bash
dotnet run [command] [options]
```

### Commands

#### 1. Analyze Requirements
Analyze one or more requirements across repositories:

```bash
# Analyze current repository
dotnet run analyze

# Analyze specific requirement in current repo
dotnet run analyze PSW-1234

# Analyze multiple repositories
dotnet run analyze --repos /path/to/repo1,/path/to/repo2

# Analyze requirement across multiple repos
dotnet run analyze --repos /path/to/repo1,/path/to/repo2 PSW-1234

# Analyze remote repositories
dotnet run analyze --repos https://github.com/org/repo.git PSW-1234
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

#### Local Paths
```bash
# Absolute path
/absolute/path/to/repository
C:\\Windows\\path\\to\\repository
```

### Usage Examples

#### Analyze PSW-79958 across multiple branches
```bash
# Analyze in develop branch
dotnet run analyze --repos 'https://git.psw.gov.pk/dev/oga/-/tree/develop' PSW-79958

# Analyze in main branch
dotnet run analyze --repos 'https://git.psw.gov.pk/dev/oga/-/tree/main' PSW-79958

# Analyze both branches
dotnet run analyze --repos \
  'https://git.psw.gov.pk/dev/oga/-/tree/develop,https://git.psw.gov.pk/dev/oga/-/tree/main' \
  PSW-79958
```

#### Multi-repository analysis
```bash
dotnet run analyze --repos \
  'https://github.com/org/repo1/tree/develop,https://github.com/org/repo2.git#v2.0' \
  REQ-2024-001
```

#### Full repository analysis
```bash
# Analyze all requirements in current repo
dotnet run analyze

# Generate complete report
dotnet run report html
```

## 🌐 Web Interface

Enterprise Scalpel includes a web-based interface for analysis via REST API.

### Start Web Server
```bash
dotnet run serve
```

The server will start on `http://localhost:5000`

### REST API Endpoints

#### Generate Report
```
POST /api/generate-report
Content-Type: application/json

Request Body:
{
  "repositories": ["https://github.com/org/repo.git"],
  "requirementIds": ["PSW-1234"],
  "requirementPattern": "[A-Z]+-\\d+",
  "format": "html"  // or "json", "csv"
}

Response: Generated report in requested format
```

#### Health Check
```
GET /api/health

Response: { "status": "ok" }
```

## ⚙️ Configuration

Create a `scalpel.config.json` file in the project root to customize settings:

```json
{
  "RequirementPattern": "PSW-\\d+",
  "OutputDirectory": "./reports",
  "DefaultRequirementId": null,
  "FileFilters": [
    "*.cs"
  ]
}
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `RequirementPattern` | Regex pattern to match requirement IDs in commit messages | `[A-Z]+-\d+` |
| `OutputDirectory` | Directory where reports are generated | `./reports` |
| `DefaultRequirementId` | Default requirement ID if none specified | `null` |
| `FileFilters` | File extensions to include in analysis | `["*.cs"]` |

## 📊 How It Works

### Processing Pipeline

1. **Commit Analysis**: Scans git commit messages using the configured requirement pattern
2. **File Tracking**: Identifies which files changed in each requirement-related commit
3. **Method Detection**: Parses C# files using Roslyn to extract method definitions
4. **Line Range Matching**: Uses git diffs to find exact line ranges changed per file
5. **Traceability Mapping**: Associates methods/files to requirements based on actual code changes
6. **Impact Calculation**: Computes risk scores and identifies entangled requirements
7. **Report Generation**: Creates visualizations and detailed reports

### Key Algorithms

#### Branch-Specific Analysis
- Automatically extracts branch names from tree URLs and hash-based notation
- Clones with `git clone --branch` to analyze only the specified branch
- Eliminates cross-branch contamination in results

#### Merge Commit Filtering
- Uses `git log --no-merges` flag to exclude merge commits
- Prevents duplicate requirement IDs from appearing in merge messages
- Ensures accurate one-to-one requirement-to-change mapping

#### Per-File Line Range Tracking
- Parses git diff output to determine file sections changed
- Matches method line ranges against actual changed lines
- Ensures methods are only traced if their code was actually modified
- Prevents false associations from unrelated files in multi-file commits

#### Risk Scoring
Risk is calculated based on:
- Number of requirements per file (multiple = higher risk)
- Number of affected methods
- Complexity metrics (method count, branching, loops)

## 📁 Project Structure

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

## 📈 Report Types

### HTML Report
Interactive HTML report with:
- Summary statistics
- Entangled files (multiple requirements)
- Method traceability table
- Risk level indicators
- Visual badges for requirements

### JSON Report
Machine-readable JSON with complete analysis data:
- Commit-to-requirements mapping
- File-to-requirements mapping
- Method-level traceability
- Timestamps and metadata

### CSV Report
Spreadsheet-compatible format:
- File paths
- Associated requirements
- Risk levels
- Change counts

### Markdown Report
Human-readable markdown with:
- Formatted summary
- High-risk files table
- Requirement details

## 🔍 Output Example

```
╔═══════════════════════════════════════════════╗
║     REQUIREMENT TRACEABILITY ANALYSIS         ║
╚═══════════════════════════════════════════════╝

📊 Summary:
   Total Commits with Requirements: 5
   Total Files Affected: 12
   Total Methods Tracked: 28
   High-Risk Files (multiple requirements): 3

⚠️  Top 10 Entangled Files:
   src/psw.oga.service/Helpers/ExportCertificateTemplateHelper.cs
      Requirements: PSW-79958, PSW-79959 (2 reqs)
   src/common/CommonHelper.cs
      Requirements: PSW-79958, PSW-80001, PSW-80002 (3 reqs)
```

## ⚠️ Important Notes

### Merge Commit Handling
- The tool **automatically filters out merge commits** to avoid duplicate requirement tracking
- Merge commits inherit requirement IDs from their commit messages, which can cause false positives
- Using `--no-merges` flag ensures accurate one-to-one requirement mapping

### Branch Specification
- **Always specify the branch** when analyzing remote repositories to avoid analyzing the wrong branch
- The tool will clone only the specified branch using `git clone --branch`
- If no branch is specified, git defaults to the repository's primary branch

### Line Range Accuracy
- The tool tracks actual line changes per file to ensure method associations are accurate
- Methods are only associated with requirements if their code was actually modified
- This prevents false associations from unrelated files in multi-file commits

## 🛠️ Development

### Build
```bash
dotnet build
```

### Run Tests
```bash
dotnet test
```

### Format Code
```bash
dotnet format
```

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature with PSW-1234'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📧 Support

For issues, questions, or suggestions, please open an issue on GitHub or contact the maintainers.

## 🔖 Changelog

### v1.0.0 (2026-02-26)
- Initial release
- Requirement traceability analysis
- Method-level impact detection
- Branch specification support
- Multi-repository analysis
- Multiple report formats
- Web API interface
- Code hotspot detection

## ✨ Features Roadmap

- [ ] Dependency graph visualization
- [ ] Requirement coverage metrics
- [ ] Integration with CI/CD pipelines
- [ ] Support for multiple programming languages
- [ ] Custom requirement pattern management UI
- [ ] Historical trend analysis
- [ ] Integration with issue tracking systems
- [ ] Docker support

---

**Developed by Shaheryar Khan**
https://www.linkedin.com/in/shaheryarkhan28/
Emailshaheryar@gmail.com
