// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/hickford/git-credential-oauth/internal/devops"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/authhandler"
	"golang.org/x/oauth2/endpoints"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strings"
)

// configByHost lists default config for several public hosts.
var configByHost = map[string]oauth2.Config{
	// https://github.com/settings/applications/2017944
	"github.com": {
		ClientID: "",
		// IMPORTANT: The client "secret" below is non confidential.
		// This is expected for OAuth native apps which (unlike web apps) are public clients
		// "incapable of maintaining the confidentiality of their credentials"
		// "It is assumed that any client authentication credentials included in the application can be extracted"
		// https://datatracker.ietf.org/doc/html/rfc6749#section-2.1
		ClientSecret: "",
		Endpoint:     endpoints.GitHub,
		Scopes:       []string{"repo", "gist", "workflow"}},
	// https://gitlab.com/oauth/applications/232663
	"gitlab.com": {
		ClientID:     "",
		ClientSecret: "",
		Endpoint:     endpoints.GitLab,
		Scopes:       []string{"read_repository", "write_repository"}},
	// https://bitbucket.org/hickford/workspace/settings/oauth-consumers/983448/edit
	"bitbucket.org": {
		ClientID:     "",
		ClientSecret: "",
		Endpoint:     endpoints.Bitbucket,
		Scopes:       []string{"repository", "repository:write"}},
	"dev.azure.com": {
		ClientID:     "",
		ClientSecret: "",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://app.vssps.visualstudio.com/oauth2/authorize",
			TokenURL: "https://app.vssps.visualstudio.com/oauth2/token",
		},
		Scopes: []string{"vso.code_write"}},
}

type GitRepo string

const (
	letterBytes         = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	Gitlab      GitRepo = "gitlab"
	Github      GitRepo = "github"
	Bitbucket   GitRepo = "bitbucket"
	AzureDevops GitRepo = "devops"
)

var (
	verbose bool
	// populated by GoReleaser https://goreleaser.com/cookbooks/using-main.version
	version = "dev"
)

func printVersion() {
	info, ok := debug.ReadBuildInfo()
	if ok && version == "dev" {
		version = info.Main.Version
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "git-credential-oauth %s\n", version)
	}
}

func parse(input string) map[string]string {
	lines := strings.Split(string(input), "\n")
	pairs := map[string]string{}
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) >= 2 {
			pairs[parts[0]] = parts[1]
		}
	}
	return pairs
}

func main() {
	flag.BoolVar(&verbose, "verbose", false, "log debug information to stderr")
	flag.Usage = func() {
		printVersion()
		fmt.Fprintln(os.Stderr, "usage: git credential-oauth [<options>] <action>")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Actions:")
		fmt.Fprintln(os.Stderr, "  get            Generate credential")
		fmt.Fprintln(os.Stderr, "  configure      Configure as Git credential helper")
		fmt.Fprintln(os.Stderr, "  unconfigure    Unconfigure as Git credential helper")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "See also https://github.com/hickford/git-credential-oauth")
	}
	flag.Parse()
	args := flag.Args()
	if len(args) != 1 {
		flag.Usage()
		os.Exit(2)
	}
	switch args[0] {
	case "get":
		printVersion()
		input, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalln(err)
		}
		pairs := parse(string(input))
		if verbose {
			fmt.Fprintln(os.Stderr, "input:", pairs)
		}
		host := pairs["host"]
		looksLikeGitLab := strings.HasPrefix(host, "gitlab.") || strings.Contains(pairs["wwwauth[]"], `Realm="GitLab"`)
		urll := fmt.Sprintf("%s://%s", pairs["protocol"], host)
		c, found := configByHost[host]
		if !found && strings.HasSuffix(host, ".googlesource.com") {
			c = configByHost["android.googlesource.com"]
		}
		if !found && looksLikeGitLab {
			// TODO: universal GitLab support with constant client id
			// https://gitlab.com/gitlab-org/gitlab/-/issues/374172
			// c.ClientID = ...

			// assumes GitLab installed at domain root
			c.Endpoint = replaceHost(endpoints.GitLab, host)
			c.Scopes = configByHost["gitlab.com"].Scopes
		}
		if looksLikeGitLab {
			fmt.Fprintf(os.Stderr, "It looks like you're authenticating to a GitLab instance! To configure git-credential-oauth for host %s, follow the instructions at https://github.com/hickford/git-credential-oauth/issues/18. You may need to register an OAuth application at https://%s/-/profile/applications\n", host, host)
		}
		handleUsernamePrefixInCloneUrls(host, pairs)

		updateOauthConfigBasedOnGitConfig(urll, &c, "")
		updateOauthConfigBasedOnEnvironmentVariables(&c, urll)
		handleMissingConfigForGitRepo(c)

		var token *oauth2.Token
		if pairs["oauth_refresh_token"] != "" {
			// Try refresh token (fast, doesn't open browser)
			if verbose {
				fmt.Fprintln(os.Stderr, "refreshing token...")
			}
			token, err = c.TokenSource(context.Background(), &oauth2.Token{RefreshToken: pairs["oauth_refresh_token"]}).Token()
			if err != nil {
				fmt.Fprintln(os.Stderr, "error during OAuth token refresh", err)
			}
		}

		if token == nil {
			// Generate new token (opens browser, may require user input)
			token, err = getToken(c, host)
			if err != nil {
				log.Fatalln(err)
			}
		}
		if verbose {
			fmt.Fprintln(os.Stderr, "token:", token)
		}
		var username string
		if host == "bitbucket.org" {
			// https://support.atlassian.com/bitbucket-cloud/docs/use-oauth-on-bitbucket-cloud/#Cloning-a-repository-with-an-access-token
			username = "x-token-auth"
		} else if host == "dev.azure.com" {
			username = "oauth2"
		} else if looksLikeGitLab {
			// https://docs.gitlab.com/ee/api/oauth2.html#access-git-over-https-with-access-token
			username = "oauth2"
		} else if pairs["username"] == "" {
			username = "oauth2"
		}
		output := map[string]string{
			"password": token.AccessToken,
		}
		if username != "" {
			output["username"] = username
		}
		if !token.Expiry.IsZero() {
			output["password_expiry_utc"] = fmt.Sprintf("%d", token.Expiry.UTC().Unix())
		}
		if token.RefreshToken != "" {
			output["oauth_refresh_token"] = token.RefreshToken
		}
		if verbose {
			fmt.Fprintln(os.Stderr, "output:", output)
		}
		for key, v := range output {
			fmt.Printf("%s=%s\n", key, v)
		}
	case "configure", "unconfigure":
		gitPath, err := exec.LookPath("git")
		if err != nil {
			log.Fatalln(err)
		}
		var commands []*exec.Cmd
		if args[0] == "configure" {
			var storage string
			switch runtime.GOOS {
			case "windows":
				storage = "wincred"
			case "darwin":
				storage = "osxkeychain"
			default:
				storage = "cache --timeout 7200"
			}
			commands = []*exec.Cmd{exec.Command(gitPath, "config", "--global", "--unset-all", "credential.helper"),
				exec.Command(gitPath, "config", "--global", "--add", "credential.helper", storage),
				exec.Command(gitPath, "config", "--global", "--add", "credential.helper", "oauth")}
		} else if args[0] == "unconfigure" {
			commands = []*exec.Cmd{exec.Command(gitPath, "config", "--global", "--unset-all", "credential.helper", "oauth")}
		}
		for _, cmd := range commands {
			cmd.Stderr = os.Stderr
			cmd.Stdout = os.Stdout
			if verbose {
				fmt.Fprintln(os.Stderr, cmd)
			}
			err := cmd.Run()
			// ignore exit status 5 "you try to unset an option which does not exist" https://git-scm.com/docs/git-config#_description
			if err != nil && cmd.ProcessState.ExitCode() != 5 {
				log.Fatalln(err)
			}
		}
		fmt.Fprintf(os.Stderr, "%sd successfully\n", args[0])
	}
}

func handleMissingConfigForGitRepo(c oauth2.Config) {
	if c.ClientID == "" || c.ClientSecret == "" {
		fmt.Fprintln(os.Stderr, "Could not find the correct clientId and clientSecret for the git-credentials-oauth application needed to request oauth credentials")
		os.Exit(1)
	}
	if c.Endpoint.AuthURL == "" || c.Endpoint.TokenURL == "" {
		fmt.Fprintln(os.Stderr, "Could not find the correct clientId and clientSecret for the git-credentials-oauth application needed to request oauth credentials")
		os.Exit(1)
	}
}

func handleUsernamePrefixInCloneUrls(host string, pairs map[string]string) {
	if strings.Contains(host, "bitbucket.org") || strings.Contains(host, "dev.azure.com") {
		username, ok := pairs["username"]
		if ok {
			if username != "" && username != "oauth2" && username != "x-token-auth" {
				fmt.Fprintf(os.Stderr, "make sure to clone repository without specifying a username as otherwise caching of the oauth token will not work. Use git clone https://bitbucket.org/... instead of https://someuser@bitbucket.org/")
				os.Exit(1)
			}
		}
	}
}

func updateOauthConfigBasedOnEnvironmentVariables(c *oauth2.Config, url string) {
	detectGitRepo := getGitRepoFrom(url)
	if detectGitRepo != "" {
		res := os.Getenv(toEnvVariable(detectGitRepo, "CLIENT_ID"))
		if res != "" {
			c.ClientID = res
		}
		res = os.Getenv(toEnvVariable(detectGitRepo, "CLIENT_SECRET"))
		if res != "" {
			c.ClientSecret = res
		}
		res = os.Getenv(toEnvVariable(detectGitRepo, "AUTH_URL"))
		if res != "" {
			authUrl, err := urlResolveReference(url, res)
			if err == nil {
				c.Endpoint.AuthURL = authUrl
			}
			if err != nil {
				log.Fatalln(err)

			}
		}
		res = os.Getenv(toEnvVariable(detectGitRepo, "TOKEN_URL"))
		if res != "" {
			tokenUrl, err := urlResolveReference(url, res)
			if err == nil {
				c.Endpoint.TokenURL = tokenUrl
			}
			if err != nil {
				log.Fatalln(err)

			}
		}
		res = os.Getenv(toEnvVariable(detectGitRepo, "SCOPES"))
		if res != "" {
			c.Scopes = []string{res}
		}
	}
}

func toEnvVariable(detectGitRepo GitRepo, envSuffix string) string {
	return fmt.Sprintf("GC_OAUTH_%s_%s", strings.ToUpper(string(detectGitRepo)), envSuffix)
}

func getGitRepoFrom(host string) GitRepo {
	if strings.Contains(host, "bitbucket") {
		return Bitbucket
	}
	if strings.Contains(host, "gitlab") {
		return Gitlab
	}
	if strings.Contains(host, "github") {
		return Github
	}
	if strings.Contains(host, "dev.azure") {
		return AzureDevops
	}
	fmt.Fprintf(os.Stderr, "Could not detect which git repo based on host %s, will skip environment variables overwrite...", host)
	return ""
}

func updateOauthConfigBasedOnGitConfig(urll string, c *oauth2.Config, file string) {
	gitPath, err := exec.LookPath("git")

	if err == nil {
		output, err := getGitConfigParameter(urll, gitPath, "credential.oauthClientId", file)
		if err == nil {
			c.ClientID = output
		}
		output, err = getGitConfigParameter(urll, gitPath, "credential.oauthClientSecret", file)
		if err == nil {
			c.ClientSecret = output
		}
		output, err = getGitConfigParameter(urll, gitPath, "credential.oauthScopes", file)
		if err == nil {
			c.Scopes = []string{output}
		}
		output, err = getGitConfigParameter(urll, gitPath, "credential.oauthAuthURL", file)
		if err == nil {
			c.Endpoint.AuthURL, err = urlResolveReference(urll, output)
			if err != nil {
				log.Fatalln(err)
			}
		}
		output, err = getGitConfigParameter(urll, gitPath, "credential.oauthTokenURL", file)
		if err == nil {
			c.Endpoint.TokenURL, err = urlResolveReference(urll, output)
			if err != nil {
				log.Fatalln(err)
			}
		}
		output, err = getGitConfigParameter(urll, gitPath, "credential.oauthRedirectURL", file)
		if err == nil {
			c.RedirectURL = strings.TrimSpace(string(output))
		}
	}
}

func getGitConfigParameter(urll string, gitPath string, param string, file string) (string, error) {
	args := []string{"config"}
	//allow to limit the configuration files to look through
	if file != "" {
		args = append(args, fmt.Sprintf("--%s", file))
	}
	args = append(args, "--get-urlmatch", param, urll)
	cmd := exec.Command(gitPath, args...)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func getToken(c oauth2.Config, host string) (*oauth2.Token, error) {
	var state string
	var err error
	queries := make(chan url.Values)
	ideUrl := os.Getenv("CONVEYOR_IDE_URL")
	apiUrl := os.Getenv("CONVEYOR_API_URL")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: consider whether to show errors in browser or command line
		queries <- r.URL.Query()
		w.Write([]byte("Success. You may close this page and return to Git."))
	})
	var server *httptest.Server
	server = httptest.NewServer(handler)
	// When in ide, we should do some magic to make sure the redirect reaches the ide
	if ideUrl != "" {
		c.RedirectURL = fmt.Sprintf("%s/api/v2/ide/callback", apiUrl)
		state, err = constructStateWithIdeAndPortInfo(ideUrl, server.URL)
		if err != nil {
			return nil, err
		}
	} else {
		wihtoutScheme := strings.TrimPrefix(server.URL, "http://")
		c.RedirectURL = fmt.Sprintf("http://127.0.0.1:%s", strings.Split(wihtoutScheme, ":")[1])
		state = randomString(16)
	}
	if verbose {
		oauthConfig, err := json.Marshal(c)
		if err == nil {
			fmt.Fprintln(os.Stderr, fmt.Sprintf("Using oauth config %s", string(oauthConfig)))
		}
	}
	authHandler := func(authCodeURL string) (code string, state string, err error) {
		defer server.Close()
		fmt.Fprintf(os.Stderr, "Please complete authentication in your browser...\n%s\n", authCodeURL)
		var open string
		switch runtime.GOOS {
		case "windows":
			open = "start"
		case "darwin":
			open = "open"
		default:
			open = "www-browser"
		}
		// TODO: wait for server to start before opening browser
		if _, err := exec.LookPath(open); err == nil {
			err = exec.Command(open, authCodeURL).Run()
			if err != nil {
				return "", "", err
			}
		}
		query := <-queries
		if verbose {
			fmt.Fprintln(os.Stderr, "query:", query)
		}
		return query.Get("code"), query.Get("state"), nil
	}
	if host == "dev.azure.com" {
		tokenSource := devops.AzureTokenSource{
			DevopsConfig: c,
			State:        state,
			AuthHandler:  authHandler,
			Verbose:      verbose,
		}
		return oauth2.ReuseTokenSource(nil, tokenSource).Token()
	}

	return authhandler.TokenSourceWithPKCE(context.Background(), &c, state, authHandler, generatePKCEParams()).Token()
}

// We customize the state to contain the necessary info such that our proxy knows where to route the traffic to
// The callback url should be specified statically for an application, so we need to put the dynamic parts in the state field as these are passed along.
func constructStateWithIdeAndPortInfo(ideUrl string, serverUrl string) (string, error) {
	ideId := strings.TrimSuffix(strings.Split(ideUrl, "ide/")[1], "/")
	urlWithoutScheme := strings.TrimPrefix(serverUrl, "http://")
	extractPort := urlWithoutScheme[strings.Index(urlWithoutScheme, ":")+1:]
	stateContent := map[string]string{"ide": ideId, "port": extractPort, "random": randomString(8)}
	stateAsString, err := json.Marshal(stateContent)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(stateAsString), nil
}

func randomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	return string(b)
}

func replaceHost(e oauth2.Endpoint, host string) oauth2.Endpoint {
	url, err := url.Parse(e.AuthURL)
	if err != nil {
		panic(err)
	}
	e.AuthURL = strings.Replace(e.AuthURL, url.Host, host, 1)
	e.TokenURL = strings.Replace(e.TokenURL, url.Host, host, 1)
	return e
}

func generatePKCEParams() *authhandler.PKCEParams {
	verifier := randomString(32)
	sha := sha256.Sum256([]byte(verifier))
	challenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sha[:])

	return &authhandler.PKCEParams{
		Challenge:       challenge,
		ChallengeMethod: "S256",
		Verifier:        verifier,
	}
}

func urlResolveReference(base, ref string) (string, error) {
	base1, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	ref1, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	return base1.ResolveReference(ref1).String(), nil
}
