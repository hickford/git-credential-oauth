package main

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var (
	clientId     = "clientId"
	clientSecret = "clientSecret"
	scopesInput  = "scope1 scope2"
	authUrl      = "/oauth/authorize"
	tokenUrl     = "/oauth/token"
)

func TestUpdateOauthConfigBasedOnGitConfig(t *testing.T) {
	temp, err := initializeGitRepo(t)
	gitDirectory := filepath.Join(temp, ".git")
	content := fmt.Sprintf(`
[credential "https://gitlab.com"]
  oauthClientId = %s
  oauthClientSecret = %s
  oauthScopes = %s
  oauthAuthUrl = %s
  oauthTokenUrl = %s
`, clientId, clientSecret, scopesInput, authUrl, tokenUrl)

	err = os.WriteFile(filepath.Join(gitDirectory, "config"), []byte(content), 0777)
	assert.NoError(t, err)

	c := oauth2.Config{}

	updateOauthConfigBasedOnGitConfig("https://gitlab.com", &c, "local")

	assert.Equal(t, c.ClientID, clientId)
	assert.Equal(t, c.ClientSecret, clientSecret)
	assert.Equal(t, c.Endpoint.AuthURL, fmt.Sprintf("https://gitlab.com%s", authUrl))
	assert.Equal(t, c.Endpoint.TokenURL, fmt.Sprintf("https://gitlab.com%s", tokenUrl))
	assert.Equal(t, c.Scopes, []string{scopesInput})
}

func TestUpdateOauthConfigEnvConfig(t *testing.T) {
	t.Setenv("GC_OAUTH_GITLAB_AUTH_URL", authUrl)
	t.Setenv("GC_OAUTH_GITLAB_TOKEN_URL", tokenUrl)
	t.Setenv("GC_OAUTH_GITLAB_CLIENT_ID", clientId)
	t.Setenv("GC_OAUTH_GITLAB_CLIENT_SECRET", clientSecret)
	t.Setenv("GC_OAUTH_GITLAB_SCOPES", scopesInput)
	c := oauth2.Config{}

	updateOauthConfigBasedOnEnvironmentVariables(&c, "https://gitlab.com")

	assert.Equal(t, c.ClientID, clientId)
	assert.Equal(t, c.ClientSecret, clientSecret)
	assert.Equal(t, c.Endpoint.AuthURL, fmt.Sprintf("https://gitlab.com%s", authUrl))
	assert.Equal(t, c.Endpoint.TokenURL, fmt.Sprintf("https://gitlab.com%s", tokenUrl))
	assert.Equal(t, c.Scopes, []string{scopesInput})
}

func initializeGitRepo(t *testing.T) (string, error) {
	temp, err := os.MkdirTemp("", "oauthGitConfig")
	assert.NoError(t, err)
	err = os.Chdir(temp)
	assert.NoError(t, err)
	path, err := exec.LookPath("git")
	assert.NoError(t, err)
	command := exec.Command(path, "init")
	_, err = command.Output()
	assert.NoError(t, err)
	return temp, err
}
