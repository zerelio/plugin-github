package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	plugintypes "github.com/zerelio/plugin-sdk/plugin"
	sdk "github.com/zerelio/plugin-sdk"
)

// ─── Config ──────────────────────────────────────────────────────────────────

// githubConfig holds the plugin configuration parsed from the discovery scope config.
// Supports both PAT and GitHub App authentication.
type githubConfig struct {
	// PAT auth
	Token string `json:"token"`
	Org   string `json:"org"`

	// GitHub App auth
	AppID          string `json:"app_id"`
	InstallationID string `json:"installation_id"`
	PrivateKey     string `json:"private_key"`
}

func (cfg *githubConfig) isAppAuth() bool {
	return cfg.AppID != "" && cfg.InstallationID != "" && cfg.PrivateKey != ""
}

func (cfg *githubConfig) effectiveToken(ctx context.Context, client *http.Client) (string, error) {
	if !cfg.isAppAuth() {
		return cfg.Token, nil
	}
	token, err := getInstallationToken(ctx, client, cfg.AppID, cfg.InstallationID, cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("github app auth: %w", err)
	}
	return token, nil
}

// ─── Plugin ──────────────────────────────────────────────────────────────────

// GitHubPlugin discovers GitHub organization resources.
type GitHubPlugin struct {
	sdk.BasePlugin
}

var _ plugintypes.DiscoveryPlugin = (*GitHubPlugin)(nil)

// ghOrganization represents a GitHub organization from the API.
type ghOrganization struct {
	Login       string `json:"login"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Plan        struct {
		Name string `json:"name"`
	} `json:"plan"`
}

// ghRepository represents a GitHub repository from the API.
type ghRepository struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	Language      string `json:"language"`
	Visibility    string `json:"visibility"`
	DefaultBranch string `json:"default_branch"`
	Stargazers    int    `json:"stargazers_count"`
	Forks         int    `json:"forks_count"`
	Private       bool   `json:"private"`
	Owner         struct {
		Login string `json:"login"`
	} `json:"owner"`
}

// ghTeam represents a GitHub team from the API.
type ghTeam struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Privacy     string `json:"privacy"`
	Description string `json:"description"`
	MembersURL  string `json:"members_url"`
}

// ghTeamMember is used to count team members.
type ghTeamMember struct {
	Login string `json:"login"`
}

// ghInstallationToken is the response from POST /app/installations/{id}/access_tokens.
type ghInstallationToken struct {
	Token               string    `json:"token"`
	ExpiresAt           time.Time `json:"expires_at"`
	RepositorySelection string    `json:"repository_selection"`
}

func (p *GitHubPlugin) Info(ctx context.Context) (*plugintypes.PluginInfo, error) {
	return &plugintypes.PluginInfo{
		Name:        "github",
		Version:     "1.0.0",
		Description: "GitHub organization discovery — repositories, organizations, and teams",
		Capabilities: []string{
			"source_control",
			"collaboration",
		},
		CredentialTypes: []string{
			"github_pat",
			"github_app",
		},
		ConfigSchema: `{
			"type": "object",
			"oneOf": [
				{
					"title": "Personal Access Token",
					"required": ["token", "org"],
					"properties": {
						"token": {"type": "string", "description": "GitHub personal access token (classic or fine-grained)"},
						"org": {"type": "string", "description": "GitHub organization name"}
					}
				},
				{
					"title": "GitHub App",
					"required": ["app_id", "installation_id", "private_key", "org"],
					"properties": {
						"app_id": {"type": "string", "description": "GitHub App ID"},
						"installation_id": {"type": "string", "description": "GitHub App installation ID"},
						"private_key": {"type": "string", "description": "GitHub App private key (PEM)"},
						"org": {"type": "string", "description": "GitHub organization name"}
					}
				}
			]
		}`,
	}, nil
}

func (p *GitHubPlugin) ValidateConfig(ctx context.Context, config map[string]string) (*plugintypes.ValidationResult, error) {
	var cfg githubConfig
	if err := sdk.ParseConfig(config, &cfg); err != nil {
		return &plugintypes.ValidationResult{Valid: false, Errors: []string{"invalid config: " + err.Error()}}, nil
	}
	var errors []string

	// Must have org regardless of auth method
	if cfg.Org == "" {
		errors = append(errors, "org is required")
	}

	// Either PAT or GitHub App auth must be configured
	hasPAT := cfg.Token != ""
	hasApp := cfg.AppID != "" && cfg.InstallationID != "" && cfg.PrivateKey != ""

	if !hasPAT && !hasApp {
		errors = append(errors, "either token (PAT) or app_id+installation_id+private_key (GitHub App) is required")
	}

	if hasApp {
		// Validate that the private key is valid PEM
		block, _ := pem.Decode([]byte(cfg.PrivateKey))
		if block == nil {
			errors = append(errors, "private_key must be a valid PEM-encoded RSA private key")
		} else if block.Type != "RSA PRIVATE KEY" && block.Type != "PRIVATE KEY" {
			errors = append(errors, fmt.Sprintf("private_key PEM must be RSA PRIVATE KEY or PRIVATE KEY, got %q", block.Type))
		} else {
			// Try to parse the key to validate it
			if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
				if _, err2 := x509.ParsePKCS1PrivateKey(block.Bytes); err2 != nil {
					errors = append(errors, "private_key: unable to parse RSA private key: "+err.Error())
				}
			}
		}
	}

	if len(errors) > 0 {
		return &plugintypes.ValidationResult{Valid: false, Errors: errors}, nil
	}
	return &plugintypes.ValidationResult{Valid: true}, nil
}

func (p *GitHubPlugin) Discover(ctx context.Context, req *plugintypes.DiscoverRequest) (<-chan plugintypes.DiscoveryEvent, error) {
	var cfg githubConfig
	if err := sdk.ParseConfig(req.Config, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	ch := make(chan plugintypes.DiscoveryEvent, 100)

	go func() {
		defer close(ch)

		client := &http.Client{Timeout: 30 * time.Second}
		baseURL := "https://api.github.com"

		// Resolve token (PAT or GitHub App installation token)
		token, err := cfg.effectiveToken(ctx, client)
		if err != nil {
			ch <- sdk.SendError("AUTH_ERROR", "failed to obtain GitHub token: "+err.Error(), false)
			return
		}

		// Discover organization
		org, err := getOrganization(ctx, client, token, baseURL, cfg.Org)
		if err != nil {
			ch <- sdk.SendError("API_ERROR", "failed to fetch organization: "+err.Error(), false)
		} else if org != nil {
			orgName := org.Name
			if orgName == "" {
				orgName = org.Login
			}
			orgID := fmt.Sprintf("github:org:%s", cfg.Org)
			r := sdk.NewResourceWithID(orgID, "github", "github.organization", "global", cfg.Org, orgName)
			r.Properties = map[string]string{
				"login":       org.Login,
				"description": org.Description,
				"plan":        org.Plan.Name,
			}
			sdk.EmitResource(ch, r)
		}

		ch <- sdk.SendProgress("Organization discovered", 20, 0, 0)
		if ctx.Err() != nil {
			return
		}

		// Discover repositories
		repos, err := listRepositories(ctx, client, token, baseURL, cfg.Org)
		if err != nil {
			ch <- sdk.SendError("API_ERROR", "failed to list repositories: "+err.Error(), false)
		} else {
			for _, repo := range repos {
				name := repo.Name
				visibility := repo.Visibility
				if visibility == "" {
					if repo.Private {
						visibility = "private"
					} else {
						visibility = "public"
					}
				}
				lang := repo.Language
				if lang == "" {
					lang = "unknown"
				}
				repoID := fmt.Sprintf("github:repo:%s/%s", cfg.Org, name)
				r := sdk.NewResourceWithID(repoID, "github", "github.repository", "global", cfg.Org, name)
				r.Properties = map[string]string{
					"description":    repo.Description,
					"language":       lang,
					"visibility":     visibility,
					"default_branch": repo.DefaultBranch,
					"stars":          strconv.Itoa(repo.Stargazers),
					"forks":          strconv.Itoa(repo.Forks),
				}
				sdk.EmitResource(ch, r)

				// Repository belongs to organization
				orgID := fmt.Sprintf("github:org:%s", cfg.Org)
				sdk.EmitRelationship(ch, sdk.NewRelationship(repoID, orgID, "BELONGS_TO"))
			}
		}

		ch <- sdk.SendProgress("Repositories discovered", 60, 0, 0)
		if ctx.Err() != nil {
			return
		}

		// Discover teams
		teams, err := listTeams(ctx, client, token, baseURL, cfg.Org)
		if err != nil {
			ch <- sdk.SendError("API_ERROR", "failed to list teams: "+err.Error(), false)
		} else {
			for _, team := range teams {
				teamID := fmt.Sprintf("github:team:%s/%s", cfg.Org, team.Slug)
				memberCount := countTeamMembers(ctx, client, token, team.MembersURL, team.Slug)
				r := sdk.NewResourceWithID(teamID, "github", "github.team", "global", cfg.Org, team.Name)
				r.Properties = map[string]string{
					"slug":         team.Slug,
					"privacy":      team.Privacy,
					"description":  team.Description,
					"member_count": strconv.Itoa(memberCount),
				}
				sdk.EmitResource(ch, r)

				// Team belongs to organization
				orgID := fmt.Sprintf("github:org:%s", cfg.Org)
				sdk.EmitRelationship(ch, sdk.NewRelationship(teamID, orgID, "BELONGS_TO"))
			}
		}

		ch <- sdk.SendProgress("Teams discovered", 100, 0, 0)
	}()

	return ch, nil
}

// ─── GitHub App Authentication ──────────────────────────────────────────────

// generateJWT creates a RS256-signed JWT for GitHub App authentication.
// The JWT contains the app ID as issuer and is valid for 10 minutes.
func generateJWT(appID string, privateKeyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", fmt.Errorf("no PEM block found in private key")
	}

	var key *rsa.PrivateKey
	var err error

	if block.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else {
		// Try PKCS8 (which covers RSA, ECDSA, Ed25519)
		k, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return "", fmt.Errorf("parse private key: PKCS1: %v, PKCS8: %v", err, parseErr)
		}
		var ok bool
		key, ok = k.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("private key is not RSA (got %T)", k)
		}
	}

	now := time.Now().Unix()
	header := `{"alg":"RS256","typ":"JWT"}`
	payload := fmt.Sprintf(`{"iss":"%s","iat":%d,"exp":%d}`, appID, now, now+600)

	// base64url encode header and payload
	b64Header := base64.RawURLEncoding.EncodeToString([]byte(header))
	b64Payload := base64.RawURLEncoding.EncodeToString([]byte(payload))

	// Sign
	message := b64Header + "." + b64Payload
	hashed := sha256.Sum256([]byte(message))
	sig, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}
	b64Sig := base64.RawURLEncoding.EncodeToString(sig)

	return b64Header + "." + b64Payload + "." + b64Sig, nil
}

// getInstallationToken exchanges a GitHub App JWT for an installation access token.
func getInstallationToken(ctx context.Context, client *http.Client, appID, installationID, privateKey string) (string, error) {
	jwt, err := generateJWT(appID, privateKey)
	if err != nil {
		return "", fmt.Errorf("generate JWT: %w", err)
	}

	url := fmt.Sprintf("https://api.github.com/app/installations/%s/access_tokens", installationID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader([]byte("{}")))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "zerelio-github-plugin/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request installation token: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp ghInstallationToken
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("decode installation token response: %w", err)
	}
	if tokenResp.Token == "" {
		return "", fmt.Errorf("installation token response did not contain a token")
	}

	return tokenResp.Token, nil
}

// ─── HTTP Helpers ──────────────────────────────────────────────────────────

func doGet(ctx context.Context, client *http.Client, token, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "zerelio-github-plugin/1.0")
	return client.Do(req)
}

func decodeJSON[T any](resp *http.Response) (*T, error) {
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}
	var v T
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &v, nil
}

func getOrganization(ctx context.Context, client *http.Client, token, baseURL, name string) (*ghOrganization, error) {
	url := fmt.Sprintf("%s/orgs/%s", baseURL, name)
	resp, err := doGet(ctx, client, token, url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 404 {
		resp.Body.Close()
		url = fmt.Sprintf("%s/users/%s", baseURL, name)
		resp, err = doGet(ctx, client, token, url)
		if err != nil {
			return nil, err
		}
	}
	return decodeJSON[ghOrganization](resp)
}

func listRepositories(ctx context.Context, client *http.Client, token, baseURL, name string) ([]ghRepository, error) {
	var all []ghRepository
	url := fmt.Sprintf("%s/orgs/%s/repos?per_page=100&sort=full_name&type=all", baseURL, name)
	orgURL := url

	for url != "" {
		resp, err := doGet(ctx, client, token, url)
		if err != nil {
			return all, err
		}

		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 404 {
			if url == orgURL {
				// Not an org — use authenticated user's repos (/user/repos)
				// /users/{name}/repos only returns PUBLIC repos for user accounts
				url = fmt.Sprintf("%s/user/repos?per_page=100&sort=full_name", baseURL)
				continue
			}
			return all, nil
		}

		// /user/repos returns all repos the authenticated token can access
		// (including org repos the user is a member of). No owner filter needed.
		var page []ghRepository
		if err := json.Unmarshal(raw, &page); err != nil {
			var ghErr struct{ Message string `json:"message"` }
			if json.Unmarshal(raw, &ghErr) == nil && ghErr.Message != "" {
				return all, fmt.Errorf("GitHub API error: %s", ghErr.Message)
			}
			return all, fmt.Errorf("decode repos: %w", err)
		}
		all = append(all, page...)

		// Follow pagination via Link header
		url = ""
		linkHeader := resp.Header.Get("Link")
		if linkHeader != "" {
			for _, part := range strings.Split(linkHeader, ",") {
				part = strings.TrimSpace(part)
				if strings.Contains(part, `rel="next"`) {
					start := strings.Index(part, "<")
					end := strings.Index(part, ">")
					if start >= 0 && end > start {
						url = part[start+1 : end]
					}
				}
			}
		}
	}

	return all, nil
}

func listTeams(ctx context.Context, client *http.Client, token, baseURL, org string) ([]ghTeam, error) {
	var all []ghTeam
	url := fmt.Sprintf("%s/orgs/%s/teams?per_page=100", baseURL, org)

	for url != "" {
		resp, err := doGet(ctx, client, token, url)
		if err != nil {
			return all, err
		}

		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// 403/404 means the org has no teams or token lacks scope — not a hard error
		if resp.StatusCode == 404 || resp.StatusCode == 403 {
			return all, nil
		}

		var page []ghTeam
		if err := json.Unmarshal(raw, &page); err != nil {
			var ghErr struct{ Message string `json:"message"` }
			if json.Unmarshal(raw, &ghErr) == nil && ghErr.Message != "" {
				return all, fmt.Errorf("GitHub API error: %s", ghErr.Message)
			}
			return all, fmt.Errorf("decode teams: %w", err)
		}

		all = append(all, page...)

		// Follow pagination via Link header
		url = ""
		linkHeader := resp.Header.Get("Link")
		if linkHeader != "" {
			for _, part := range strings.Split(linkHeader, ",") {
				part = strings.TrimSpace(part)
				if strings.Contains(part, `rel="next"`) {
					start := strings.Index(part, "<")
					end := strings.Index(part, ">")
					if start >= 0 && end > start {
						url = part[start+1 : end]
					}
				}
			}
		}
	}

	return all, nil
}

func countTeamMembers(ctx context.Context, client *http.Client, token, membersURL, slug string) int {
	// membersURL looks like "https://api.github.com/organizations/{org_id}/team/{team_id}/members{/member}"
	// Replace the template suffix to get the actual list endpoint
	url := strings.ReplaceAll(membersURL, "{/member}", "?per_page=1")

	resp, err := doGet(ctx, client, token, url)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	// Try to parse Link header for last page to infer count
	linkHeader := resp.Header.Get("Link")
	if linkHeader != "" {
		for _, part := range strings.Split(linkHeader, ",") {
			part = strings.TrimSpace(part)
			if strings.Contains(part, `rel="last"`) {
				// Extract page number from URL like <...?page=N>; rel="last"
				start := strings.Index(part, "<")
				end := strings.Index(part, ">")
				if start >= 0 && end > start {
					lastURL := part[start+1 : end]
					if pageStr := extractPageParam(lastURL); pageStr != "" {
						if n, err := strconv.Atoi(pageStr); err == nil {
							return n
						}
					}
				}
			}
		}
	}

	return 0
}

func extractPageParam(url string) string {
	idx := strings.LastIndex(url, "page=")
	if idx < 0 {
		return ""
	}
	after := url[idx+5:]
	if amp := strings.IndexByte(after, '&'); amp >= 0 {
		after = after[:amp]
	}
	return after
}
