# Zerelio GitHub Plugin

Discovers GitHub organisation resources and streams them into the Zerelio knowledge graph.

## What It Discovers

| Resource type          | Description                                    |
|------------------------|------------------------------------------------|
| `github.organization`  | GitHub organisations                           |
| `github.repository`    | Repositories — public and private              |
| `github.team`          | Teams within an organisation                   |
| `github.member`        | Organisation members and their team membership |

## Configuration

### Personal Access Token

| Environment variable | Required | Description                                              |
|----------------------|----------|----------------------------------------------------------|
| `GITHUB_TOKEN`       | Yes      | Personal access token or fine-grained token              |

Required token scopes: `repo`, `read:org`

### GitHub App (recommended for organisations)

| Environment variable         | Required | Description                              |
|------------------------------|----------|------------------------------------------|
| `GITHUB_APP_ID`              | Yes      | GitHub App ID                            |
| `GITHUB_PRIVATE_KEY`         | Yes      | PEM-encoded private key (or path to file) |
| `GITHUB_INSTALLATION_ID`     | Yes      | Installation ID for the target org       |

GitHub App permissions needed: **Repository contents** (read), **Members** (read), **Administration** (read).

## Adding to a Zerelio Scope

```json
{
  "scope_name": "My GitHub Org",
  "plugin_name": "github",
  "config": {
    "org": "my-org"
  },
  "schedule": "@every 1h"
}
```

## Part of Zerelio

This plugin is part of the [Zerelio](https://github.com/zerelio/knowledge) infrastructure knowledge graph platform.
