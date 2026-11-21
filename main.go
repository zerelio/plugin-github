package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	sdk "github.com/zerelio/plugin-sdk"
)

func main() {
	standalone := flag.Bool("standalone", false, "Run in standalone mode (output JSON to stdout)")
	token := flag.String("token", "", "GitHub personal access token")
	org := flag.String("org", "", "GitHub organization name")
	flag.Parse()

	if *standalone {
		if *token == "" || *org == "" {
			log.Fatalf("--token and --org are required in standalone mode")
		}
		runStandalone(*token, *org)
		return
	}

	sdk.Serve(&GitHubPlugin{})
}

type standaloneResource struct {
	ID            string              `json:"id"`
	Type          string              `json:"type"`
	Provider      string              `json:"provider"`
	Name          string              `json:"name"`
	Properties    map[string]string   `json:"properties"`
	Relationships []map[string]string `json:"relationships,omitempty"`
}

func runStandalone(token, org string) {
	ctx := context.Background()
	client := &http.Client{Timeout: 30 * time.Second}
	baseURL := "https://api.github.com"
	var resources []standaloneResource

	// Organization
	orgObj, err := getOrganization(ctx, client, token, baseURL, org)
	if err == nil && orgObj != nil {
		orgName := orgObj.Name
		if orgName == "" {
			orgName = orgObj.Login
		}
		orgID := fmt.Sprintf("github:org:%s", org)
		resources = append(resources, standaloneResource{
			ID:       orgID,
			Type:     "github.organization",
			Provider: "github",
			Name:     orgName,
			Properties: map[string]string{
				"login":       orgObj.Login,
				"description": orgObj.Description,
				"plan":        orgObj.Plan.Name,
			},
		})
	}

	// Repositories
	repos, err := listRepositories(ctx, client, token, baseURL, org)
	if err == nil {
		for _, repo := range repos {
			repoID := fmt.Sprintf("github:repo:%s/%s", org, repo.Name)
			visibility := repo.Visibility
			if visibility == "" {
				if repo.Private {
					visibility = "private"
				} else {
					visibility = "public"
				}
			}
			resources = append(resources, standaloneResource{
				ID:       repoID,
				Type:     "github.repository",
				Provider: "github",
				Name:     repo.Name,
				Properties: map[string]string{
					"description":    repo.Description,
					"language":       repo.Language,
					"visibility":     visibility,
					"default_branch": repo.DefaultBranch,
					"stars":          fmt.Sprintf("%d", repo.Stargazers),
					"forks":          fmt.Sprintf("%d", repo.Forks),
				},
				Relationships: []map[string]string{
					{"source": repoID, "target": fmt.Sprintf("github:org:%s", org), "type": "BELONGS_TO"},
				},
			})
		}
	}

	// Teams
	teams, err := listTeams(ctx, client, token, baseURL, org)
	if err == nil {
		for _, team := range teams {
			teamID := fmt.Sprintf("github:team:%s/%s", org, team.Slug)
			resources = append(resources, standaloneResource{
				ID:       teamID,
				Type:     "github.team",
				Provider: "github",
				Name:     team.Name,
				Properties: map[string]string{
					"slug":        team.Slug,
					"privacy":     team.Privacy,
					"description": team.Description,
				},
				Relationships: []map[string]string{
					{"source": teamID, "target": fmt.Sprintf("github:org:%s", org), "type": "BELONGS_TO"},
				},
			})
		}
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.Encode(map[string]interface{}{
		"provider":  "github",
		"org":       org,
		"resources": resources,
	})
}
