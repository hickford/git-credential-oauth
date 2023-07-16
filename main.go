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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/authhandler"
	"golang.org/x/oauth2/endpoints"
)

// configByHost lists default config for several public hosts.
var configByHost = map[string]oauth2.Config{
	// https://github.com/settings/applications/2017944
	"github.com": {
		ClientID: "b895675a4e2cf54d5c6c",
		// IMPORTANT: The client "secret" below is non confidential.
		// This is expected for OAuth native apps which (unlike web apps) are public clients
		// "incapable of maintaining the confidentiality of their credentials"
		// "It is assumed that any client authentication credentials included in the application can be extracted"
		// https://datatracker.ietf.org/doc/html/rfc6749#section-2.1
		ClientSecret: "2b746eea028711749c5062b9fe626fed78d03cc0",
		Endpoint:     endpoints.GitHub,
		Scopes:       []string{"repo", "gist", "workflow"}},
	// https://gitlab.com/oauth/applications/232663
	"gitlab.com": {
		ClientID: "10bfbbf46e5b760b55ce772a262d7a0205eacc417816eb84d37d0fb02c89bb97",
		Endpoint: endpoints.GitLab,
		Scopes:   []string{"read_repository", "write_repository"}},
	// https://gitlab.freedesktop.org/oauth/applications/68
	"gitlab.freedesktop.org": {
		ClientID: "ba28f287f465c03c629941bca9de965923c561f8e967ce02673a0cd937a94b6f",
		Endpoint: replaceHost(endpoints.GitLab, "gitlab.freedesktop.org"),
		Scopes:   []string{"read_repository", "write_repository"}},
	// https://gitlab.gnome.org/oauth/applications/112
	"gitlab.gnome.org": {
		ClientID: "9719f147e6117ef0ee9954516bd7fe292176343a7fd24a8bcd5a686e8ef1ec71",
		Endpoint: replaceHost(endpoints.GitLab, "gitlab.gnome.org"),
		Scopes:   []string{"read_repository", "write_repository"}},
	// https://code.videolan.org/oauth/applications/109
	"code.videolan.org": {
		ClientID: "a6d235d8ebc7a7eacc52be6dba0b5bc31a6d013be85e2d15f0fc9006b4c6e9ff",
		Endpoint: replaceHost(endpoints.GitLab, "code.videolan.org"),
		Scopes:   []string{"read_repository", "write_repository"}},
	// https://salsa.debian.org/oauth/applications/95
	"salsa.debian.org": {
		ClientID: "0ae3637439058e4f261db17a001a7ec9235e1fda88b6d9221222a57c14ed830d",
		Endpoint: replaceHost(endpoints.GitLab, "salsa.debian.org"),
		Scopes:   []string{"read_repository", "write_repository"}},
	// https://gitlab.haskell.org/oauth/applications/3
	"gitlab.haskell.org": {
		ClientID: "078baa23982db8d6e179fb7da816b92e6a761268b8b35a7aa1e7ee7a3891a426",
		Endpoint: replaceHost(endpoints.GitLab, "gitlab.haskell.org"),
		Scopes:   []string{"read_repository", "write_repository"}},
	// https://gitlab.alpinelinux.org/oauth/applications/7
	"gitlab.alpinelinux.org": {
		ClientID: "6e1363d5730bd1068bc908d6eda9f4f7e72352147dbe15f441a2f9e2ce5aebee",
		Endpoint: replaceHost(endpoints.GitLab, "gitlab.alpinelinux.org"),
		Scopes:   []string{"read_repository", "write_repository"}},
	// https://gitea.com/user/settings/applications/oauth2/218
	"gitea.com": {
		ClientID: "e13f8ebc-398d-4091-9481-5a37a76b51f6",
		Endpoint: oauth2.Endpoint{AuthURL: "https://gitea.com/login/oauth/authorize", TokenURL: "https://gitea.com/login/oauth/access_token"}},
	// https://codeberg.org/user/settings/applications/oauth2/223
	"codeberg.org": {
		ClientID:     "246ca3e8-e974-430c-b9ec-3d4e2b54ad28",
		ClientSecret: "gto_4stsgpwkgtsvayljdsg3xq33l2v3v245rlc45tnpt4cjp7eyw5gq",
		Endpoint:     oauth2.Endpoint{AuthURL: "https://codeberg.org/login/oauth/authorize", TokenURL: "https://codeberg.org/login/oauth/access_token"}},
	// https://bitbucket.org/hickford/workspace/settings/oauth-consumers/983448/edit
	"bitbucket.org": {
		ClientID:     "abET6ywGmTknNRvAMT",
		ClientSecret: "df8rsnkAxuHCgZrSgu5ykJQjrbGVzT9m",
		Endpoint:     endpoints.Bitbucket,
		Scopes:       []string{"repository", "repository:write"}},
	"android.googlesource.com": {
		ClientID:     "897755559425-di05p489vpt7iv09thbf5a1ombcbs5v0.apps.googleusercontent.com",
		ClientSecret: "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",
		Endpoint:     endpoints.Google,
		Scopes:       []string{"https://www.googleapis.com/auth/gerritcodereview"}},
}

var (
	verbose bool
	// populated by GoReleaser https://goreleaser.com/cookbooks/using-main.version
	version = "dev"
)

func getVersion() string {
	info, ok := debug.ReadBuildInfo()
	if ok && version == "dev" {
		version = info.Main.Version
	}
	return version
}

func printVersion() {
	if verbose {
		fmt.Fprintf(os.Stderr, "git-credential-oauth %s\n", getVersion())
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
		fmt.Fprintln(os.Stderr, "  get            Generate credential [called by Git]")
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
		gitPath, err := exec.LookPath("git")
		if err == nil {
			cmd := exec.Command(gitPath, "config", "--get-urlmatch", "credential.oauthClientId", urll)
			bytes, err := cmd.Output()
			if err == nil {
				c.ClientID = strings.TrimSpace(string(bytes))
			}
			bytes, err = exec.Command(gitPath, "config", "--get-urlmatch", "credential.oauthClientSecret", urll).Output()
			if err == nil {
				c.ClientSecret = strings.TrimSpace(string(bytes))
			}
			bytes, err = exec.Command(gitPath, "config", "--get-urlmatch", "credential.oauthScopes", urll).Output()
			if err == nil {
				c.Scopes = []string{strings.TrimSpace(string(bytes))}
			}
			bytes, err = exec.Command(gitPath, "config", "--get-urlmatch", "credential.oauthAuthURL", urll).Output()
			if err == nil {
				c.Endpoint.AuthURL, err = urlResolveReference(urll, strings.TrimSpace(string(bytes)))
				if err != nil {
					log.Fatalln(err)
				}
			}
			bytes, err = exec.Command(gitPath, "config", "--get-urlmatch", "credential.oauthTokenURL", urll).Output()
			if err == nil {
				c.Endpoint.TokenURL, err = urlResolveReference(urll, strings.TrimSpace(string(bytes)))
				if err != nil {
					log.Fatalln(err)
				}
			}
			bytes, err = exec.Command(gitPath, "config", "--get-urlmatch", "credential.oauthRedirectURL", urll).Output()
			if err == nil {
				c.RedirectURL = strings.TrimSpace(string(bytes))
			}
		}
		if c.ClientID == "" || c.Endpoint.AuthURL == "" || c.Endpoint.TokenURL == "" {
			if looksLikeGitLab {
				fmt.Fprintf(os.Stderr, "It looks like you're authenticating to a GitLab instance! To configure git-credential-oauth for host %s, follow the instructions at https://github.com/hickford/git-credential-oauth/issues/18. You may need to register an OAuth application at https://%s/-/profile/applications\n", host, host)
			}
			return
		}

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
			token, err = getToken(c)
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

var template string = `<!DOCTYPE html>
<html lang="en">
<head>
	<title>Git authentication</title>
</head>
<body>
<p>Success. You may close this page and return to Git.</p>
<p style="font-style: italic">&mdash;<a href="https://github.com/hickford/git-credential-oauth">git-credential-oauth</a> %s</p>
</body>
</html>`

func getToken(c oauth2.Config) (*oauth2.Token, error) {
	state := randomString(16)
	queries := make(chan url.Values)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: consider whether to show errors in browser or command line
		queries <- r.URL.Query()
		w.Header().Add("Content-Type", "text/html")
		html := fmt.Sprintf(template, getVersion())
		w.Write([]byte(html))
	})
	var server *httptest.Server
	if c.RedirectURL == "" {
		server = httptest.NewServer(handler)
		c.RedirectURL = server.URL
	} else {
		server = httptest.NewUnstartedServer(handler)
		url, err := url.Parse(c.RedirectURL)
		if err != nil {
			log.Fatalln(err)
		}
		l, err := net.Listen("tcp", url.Host)
		if err != nil {
			log.Fatalln(err)
		}
		server.Listener = l
		server.Start()
	}
	defer server.Close()
	return authhandler.TokenSourceWithPKCE(context.Background(), &c, state, func(authCodeURL string) (code string, state string, err error) {
		defer server.Close()
		fmt.Fprintf(os.Stderr, "Please complete authentication in your browser...\n%s\n", authCodeURL)
		var open string
		switch runtime.GOOS {
		case "windows":
			open = "start"
		case "darwin":
			open = "open"
		default:
			open = "xdg-open"
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
	}, generatePKCEParams()).Token()
}

func randomString(n int) string {
	data := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(data)
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
