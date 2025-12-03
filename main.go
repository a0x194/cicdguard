package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	version = "1.0.0"
	banner  = `
 ██████╗██╗ ██████╗██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
██╔════╝██║██╔════╝██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██║     ██║██║     ██║  ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██║     ██║██║     ██║  ██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
╚██████╗██║╚██████╗██████╔╝╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
 ╚═════╝╚═╝ ╚═════╝╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝

    CI/CD Pipeline Security Scanner v%s

    Author: a0x194
    Team:   TryHarder | https://www.tryharder.space
    Tools:  https://www.tryharder.space/tools/
`
)

type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
	Info     Severity = "INFO"
)

type Finding struct {
	File        string
	Line        int
	Severity    Severity
	Category    string
	Title       string
	Description string
	Remediation string
}

type Scanner struct {
	verbose bool
	findings []Finding
	mu       sync.Mutex
}

func NewScanner(verbose bool) *Scanner {
	return &Scanner{
		verbose:  verbose,
		findings: []Finding{},
	}
}

// Secret patterns to detect
var secretPatterns = []struct {
	Name    string
	Pattern *regexp.Regexp
}{
	{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"AWS Secret Key", regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`)},
	{"GitHub Token", regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`)},
	{"GitHub OAuth", regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`)},
	{"GitLab Token", regexp.MustCompile(`glpat-[a-zA-Z0-9\-]{20}`)},
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}`)},
	{"Slack Webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}`)},
	{"Private Key", regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{"Heroku API Key", regexp.MustCompile(`(?i)heroku[a-z0-9_ .\-,]{0,25}['"][0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}['"]`)},
	{"Generic API Key", regexp.MustCompile(`(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['"]?[a-zA-Z0-9]{16,}['"]?`)},
	{"Generic Password", regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,}['"]`)},
	{"JWT Token", regexp.MustCompile(`eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`)},
	{"Basic Auth", regexp.MustCompile(`(?i)basic\s+[a-zA-Z0-9+/=]{20,}`)},
	{"Bearer Token", regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9_\-\.]+`)},
}

// Dangerous workflow patterns
var dangerousPatterns = []struct {
	Name        string
	Pattern     *regexp.Regexp
	Severity    Severity
	Description string
	Remediation string
}{
	{
		"Pull Request Target Trigger",
		regexp.MustCompile(`(?i)on:\s*\n\s*pull_request_target:`),
		Critical,
		"pull_request_target runs in the context of the base repository with write permissions",
		"Use pull_request trigger instead, or carefully validate the PR source",
	},
	{
		"Workflow Run Trigger",
		regexp.MustCompile(`(?i)on:\s*\n\s*workflow_run:`),
		High,
		"workflow_run can be triggered by forked repositories",
		"Validate the triggering workflow and add proper checks",
	},
	{
		"Unsafe Checkout PR Head",
		regexp.MustCompile(`(?i)ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.sha\s*\}\}`),
		Critical,
		"Checking out untrusted PR code with elevated permissions",
		"Only checkout trusted code or use a separate job",
	},
	{
		"Command Injection via Title",
		regexp.MustCompile(`(?i)\$\{\{\s*github\.event\.(issue|pull_request)\.title\s*\}\}`),
		Critical,
		"User-controlled input directly used in command - potential command injection",
		"Use environment variables or sanitize the input",
	},
	{
		"Command Injection via Body",
		regexp.MustCompile(`(?i)\$\{\{\s*github\.event\.(issue|pull_request|comment)\.body\s*\}\}`),
		Critical,
		"User-controlled input directly used - potential command injection",
		"Use environment variables or sanitize the input",
	},
	{
		"Script Injection",
		regexp.MustCompile(`(?i)run:\s*.*\$\{\{\s*github\.event`),
		High,
		"GitHub event data used directly in run command",
		"Use environment variables instead of direct interpolation",
	},
	{
		"Secrets in Logs",
		regexp.MustCompile(`(?i)echo\s+.*\$\{\{\s*secrets\.[^}]+\}\}`),
		High,
		"Secret may be exposed in workflow logs",
		"Avoid echoing secrets, use masking if necessary",
	},
	{
		"Privileged Container",
		regexp.MustCompile(`(?i)privileged:\s*true`),
		High,
		"Container running in privileged mode",
		"Remove privileged mode unless absolutely necessary",
	},
	{
		"Self-Hosted Runner",
		regexp.MustCompile(`(?i)runs-on:\s*self-hosted`),
		Medium,
		"Self-hosted runners can be a security risk if not properly isolated",
		"Ensure self-hosted runners are properly secured and isolated",
	},
	{
		"Artifact Upload Without Retention",
		regexp.MustCompile(`(?i)actions/upload-artifact@`),
		Low,
		"Artifacts without retention policy may persist indefinitely",
		"Set retention-days to limit artifact lifetime",
	},
	{
		"Unpinned Action Version",
		regexp.MustCompile(`uses:\s*[^@]+@(master|main|latest|v\d+)\s*$`),
		Medium,
		"Using unpinned or mutable action version",
		"Pin actions to specific commit SHA for security",
	},
	{
		"GITHUB_TOKEN Write Permissions",
		regexp.MustCompile(`(?i)permissions:\s*\n\s*(contents|issues|pull-requests|packages):\s*write`),
		Info,
		"Workflow has write permissions",
		"Ensure write permissions are necessary and properly scoped",
	},
}

func (s *Scanner) addFinding(finding Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.findings = append(s.findings, finding)
}

func (s *Scanner) scanSecrets(content string, filePath string) {
	lines := strings.Split(content, "\n")
	for lineNum, line := range lines {
		for _, pattern := range secretPatterns {
			if pattern.Pattern.MatchString(line) {
				s.addFinding(Finding{
					File:        filePath,
					Line:        lineNum + 1,
					Severity:    Critical,
					Category:    "Secrets",
					Title:       fmt.Sprintf("Potential %s detected", pattern.Name),
					Description: "Hardcoded secret or credential found in CI/CD configuration",
					Remediation: "Remove the secret and use repository secrets or a secrets manager",
				})
			}
		}
	}
}

func (s *Scanner) scanDangerousPatterns(content string, filePath string) {
	for _, pattern := range dangerousPatterns {
		if pattern.Pattern.MatchString(content) {
			// Find the line number
			lines := strings.Split(content, "\n")
			lineNum := 1
			for i, line := range lines {
				if pattern.Pattern.MatchString(line) {
					lineNum = i + 1
					break
				}
			}

			s.addFinding(Finding{
				File:        filePath,
				Line:        lineNum,
				Severity:    pattern.Severity,
				Category:    "Workflow Security",
				Title:       pattern.Name,
				Description: pattern.Description,
				Remediation: pattern.Remediation,
			})
		}
	}
}

func (s *Scanner) scanGitHubActions(content string, filePath string) {
	s.scanSecrets(content, filePath)
	s.scanDangerousPatterns(content, filePath)

	// Parse YAML for deeper analysis
	var workflow map[string]interface{}
	if err := yaml.Unmarshal([]byte(content), &workflow); err != nil {
		if s.verbose {
			fmt.Printf("[!] Could not parse YAML: %s\n", filePath)
		}
		return
	}

	// Check for dangerous triggers
	if on, ok := workflow["on"]; ok {
		s.analyzeWorkflowTriggers(on, filePath)
	}
}

func (s *Scanner) analyzeWorkflowTriggers(on interface{}, filePath string) {
	switch v := on.(type) {
	case map[string]interface{}:
		for trigger := range v {
			if trigger == "pull_request_target" || trigger == "workflow_run" {
				// Already caught by regex patterns
				continue
			}
			if trigger == "issue_comment" {
				s.addFinding(Finding{
					File:        filePath,
					Line:        1,
					Severity:    Medium,
					Category:    "Workflow Security",
					Title:       "Issue Comment Trigger",
					Description: "Workflow triggered by issue comments can be abused",
					Remediation: "Add checks to validate the commenter's permissions",
				})
			}
		}
	}
}

func (s *Scanner) scanGitLabCI(content string, filePath string) {
	s.scanSecrets(content, filePath)

	// GitLab-specific patterns
	gitlabPatterns := []struct {
		Name        string
		Pattern     *regexp.Regexp
		Severity    Severity
		Description string
	}{
		{
			"Unprotected Variables",
			regexp.MustCompile(`(?i)variables:\s*\n\s*[A-Z_]+:\s*[^$]`),
			Medium,
			"Variables without $ prefix may expose values in logs",
		},
		{
			"Allow Failure",
			regexp.MustCompile(`(?i)allow_failure:\s*true`),
			Low,
			"Job failures are ignored which may hide security issues",
		},
	}

	for _, pattern := range gitlabPatterns {
		if pattern.Pattern.MatchString(content) {
			s.addFinding(Finding{
				File:        filePath,
				Line:        1,
				Severity:    pattern.Severity,
				Category:    "GitLab CI Security",
				Title:       pattern.Name,
				Description: pattern.Description,
			})
		}
	}
}

func (s *Scanner) scanJenkinsfile(content string, filePath string) {
	s.scanSecrets(content, filePath)

	// Jenkins-specific patterns
	jenkinsPatterns := []struct {
		Name        string
		Pattern     *regexp.Regexp
		Severity    Severity
		Description string
	}{
		{
			"Script Security Bypass",
			regexp.MustCompile(`(?i)@NonCPS`),
			High,
			"NonCPS annotation bypasses script security sandbox",
		},
		{
			"Groovy Eval",
			regexp.MustCompile(`(?i)evaluate\s*\(`),
			Critical,
			"Dynamic code evaluation can lead to code injection",
		},
		{
			"Unsanitized Parameters",
			regexp.MustCompile(`(?i)params\.[a-zA-Z]+`),
			Medium,
			"User-controlled parameters should be sanitized",
		},
	}

	for _, pattern := range jenkinsPatterns {
		if pattern.Pattern.MatchString(content) {
			s.addFinding(Finding{
				File:        filePath,
				Line:        1,
				Severity:    pattern.Severity,
				Category:    "Jenkins Security",
				Title:       pattern.Name,
				Description: pattern.Description,
			})
		}
	}
}

func (s *Scanner) ScanFile(filePath string) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		if s.verbose {
			fmt.Printf("[!] Error reading file: %s\n", filePath)
		}
		return
	}

	fileName := filepath.Base(filePath)
	contentStr := string(content)

	if s.verbose {
		fmt.Printf("[*] Scanning: %s\n", filePath)
	}

	// Detect CI/CD type and scan accordingly
	switch {
	case strings.Contains(filePath, ".github/workflows"):
		s.scanGitHubActions(contentStr, filePath)
	case fileName == ".gitlab-ci.yml" || strings.HasSuffix(fileName, ".gitlab-ci.yml"):
		s.scanGitLabCI(contentStr, filePath)
	case fileName == "Jenkinsfile" || strings.HasSuffix(fileName, ".jenkinsfile"):
		s.scanJenkinsfile(contentStr, filePath)
	case strings.HasSuffix(fileName, ".yml") || strings.HasSuffix(fileName, ".yaml"):
		// Generic YAML scan
		s.scanSecrets(contentStr, filePath)
		s.scanDangerousPatterns(contentStr, filePath)
	}
}

func (s *Scanner) ScanDirectory(dir string) {
	cicdPatterns := []string{
		".github/workflows/*.yml",
		".github/workflows/*.yaml",
		".gitlab-ci.yml",
		"**/.gitlab-ci.yml",
		"Jenkinsfile",
		"**/Jenkinsfile",
		".circleci/config.yml",
		".travis.yml",
		"azure-pipelines.yml",
		"bitbucket-pipelines.yml",
	}

	for _, pattern := range cicdPatterns {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			continue
		}
		for _, match := range matches {
			s.ScanFile(match)
		}
	}

	// Also walk directory for any CI files
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}

		fileName := info.Name()
		if strings.Contains(path, ".github/workflows") ||
			fileName == ".gitlab-ci.yml" ||
			fileName == "Jenkinsfile" ||
			fileName == ".travis.yml" ||
			fileName == "azure-pipelines.yml" {
			s.ScanFile(path)
		}
		return nil
	})
}

func (s *Scanner) ScanGitHubRepo(owner, repo, token string) error {
	fmt.Printf("[*] Scanning GitHub repository: %s/%s\n", owner, repo)

	client := &http.Client{Timeout: 30 * time.Second}

	// Fetch workflow files
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/.github/workflows", owner, repo)

	req, _ := http.NewRequest("GET", url, nil)
	if token != "" {
		req.Header.Set("Authorization", "token "+token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var files []struct {
		Name        string `json:"name"`
		DownloadURL string `json:"download_url"`
	}

	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &files)

	for _, file := range files {
		if strings.HasSuffix(file.Name, ".yml") || strings.HasSuffix(file.Name, ".yaml") {
			contentResp, err := http.Get(file.DownloadURL)
			if err != nil {
				continue
			}
			content, _ := io.ReadAll(contentResp.Body)
			contentResp.Body.Close()

			filePath := fmt.Sprintf(".github/workflows/%s", file.Name)
			s.scanGitHubActions(string(content), filePath)
		}
	}

	return nil
}

func printFinding(f Finding) {
	var severityColor string
	switch f.Severity {
	case Critical:
		severityColor = "\033[31m" // Red
	case High:
		severityColor = "\033[91m" // Light Red
	case Medium:
		severityColor = "\033[33m" // Yellow
	case Low:
		severityColor = "\033[36m" // Cyan
	default:
		severityColor = "\033[37m" // White
	}
	reset := "\033[0m"
	green := "\033[32m"

	fmt.Printf("\n%s[%s]%s %s\n", severityColor, f.Severity, reset, f.Title)
	fmt.Printf("  %s├─%s File: %s:%d\n", green, reset, f.File, f.Line)
	fmt.Printf("  %s├─%s Category: %s\n", green, reset, f.Category)
	fmt.Printf("  %s├─%s Description: %s\n", green, reset, f.Description)
	if f.Remediation != "" {
		fmt.Printf("  %s└─%s Remediation: %s\n", green, reset, f.Remediation)
	}
}

func main() {
	var (
		directory    string
		file         string
		githubRepo   string
		githubToken  string
		verbose      bool
		output       string
		jsonOutput   bool
		showVersion  bool
	)

	flag.StringVar(&directory, "d", "", "Directory to scan")
	flag.StringVar(&file, "f", "", "Single file to scan")
	flag.StringVar(&githubRepo, "repo", "", "GitHub repository (owner/repo)")
	flag.StringVar(&githubToken, "token", "", "GitHub token for API access")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.StringVar(&output, "o", "", "Output file for results")
	flag.BoolVar(&jsonOutput, "json", false, "Output results as JSON")
	flag.BoolVar(&showVersion, "version", false, "Show version")

	flag.Parse()

	fmt.Printf(banner, version)

	if showVersion {
		return
	}

	if directory == "" && file == "" && githubRepo == "" {
		fmt.Println("\nUsage:")
		fmt.Println("  cicdguard -d ./my-project")
		fmt.Println("  cicdguard -f .github/workflows/ci.yml")
		fmt.Println("  cicdguard -repo owner/repo -token ghp_xxx")
		fmt.Println("\nFlags:")
		flag.PrintDefaults()
		return
	}

	scanner := NewScanner(verbose)

	if file != "" {
		scanner.ScanFile(file)
	}

	if directory != "" {
		scanner.ScanDirectory(directory)
	}

	if githubRepo != "" {
		parts := strings.Split(githubRepo, "/")
		if len(parts) != 2 {
			fmt.Println("[!] Invalid repository format. Use owner/repo")
			return
		}
		if err := scanner.ScanGitHubRepo(parts[0], parts[1], githubToken); err != nil {
			fmt.Printf("[!] Error scanning repository: %v\n", err)
		}
	}

	// Print results
	if !jsonOutput {
		fmt.Printf("\n[*] Scan complete! Found %d issue(s)\n", len(scanner.findings))

		// Group by severity
		severities := []Severity{Critical, High, Medium, Low, Info}
		for _, sev := range severities {
			for _, f := range scanner.findings {
				if f.Severity == sev {
					printFinding(f)
				}
			}
		}
	} else {
		jsonBytes, _ := json.MarshalIndent(scanner.findings, "", "  ")
		fmt.Println(string(jsonBytes))
	}

	// Summary
	if !jsonOutput && len(scanner.findings) > 0 {
		critical, high, medium, low := 0, 0, 0, 0
		for _, f := range scanner.findings {
			switch f.Severity {
			case Critical:
				critical++
			case High:
				high++
			case Medium:
				medium++
			case Low:
				low++
			}
		}
		fmt.Printf("\n📊 Summary: %d Critical, %d High, %d Medium, %d Low\n", critical, high, medium, low)
	}

	// Save to file
	if output != "" && len(scanner.findings) > 0 {
		file, err := os.Create(output)
		if err != nil {
			fmt.Printf("[!] Error creating output file: %v\n", err)
			return
		}
		defer file.Close()

		if jsonOutput {
			jsonBytes, _ := json.MarshalIndent(scanner.findings, "", "  ")
			file.Write(jsonBytes)
		} else {
			for _, f := range scanner.findings {
				line := fmt.Sprintf("[%s] %s | %s:%d | %s\n", f.Severity, f.Title, f.File, f.Line, f.Description)
				file.WriteString(line)
			}
		}
		fmt.Printf("[*] Results saved to %s\n", output)
	}
}

// Helper function for base64 decoding (unused but kept for potential future use)
func decodeBase64(s string) string {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return s
	}
	return string(decoded)
}
