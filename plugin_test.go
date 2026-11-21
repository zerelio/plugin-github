package main

import (
	"context"
	"testing"
)

func TestGitHubPlugin_ValidateConfig_Invalid(t *testing.T) {
	p := &GitHubPlugin{}
	r, err := p.ValidateConfig(context.Background(), map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Valid {
		t.Fatal("expected invalid for empty config")
	}
}

func TestGitHubPlugin_ValidateConfig_Valid(t *testing.T) {
	p := &GitHubPlugin{}
	r, err := p.ValidateConfig(context.Background(), map[string]string{
		"token": "test-token",
		"org":   "test-org",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Valid {
		t.Fatal("expected valid with token and org")
	}
}

func TestGitHubPlugin_Info(t *testing.T) {
	p := &GitHubPlugin{}
	info, err := p.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "github" {
		t.Fatalf("expected github, got %s", info.Name)
	}
}
