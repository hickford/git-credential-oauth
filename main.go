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
	// https://hifis.net/doc/software/gitlab/getting-started/#use-git-credential-oauth
	"codebase.helmholtz.cloud": {
		ClientID: "e79ac88d46e4f3f79a494166fabb0310e7879d8e4776f316fb57b3100eaec13a",
		Endpoint: replaceHost(endpoints.GitLab, "codebase.helmholtz.cloud"),
		Scopes:   []string{"read_repository", "write_repository"}},
	// https://gitea.com/user/settings/applications/oauth2/218
	"invent.kde.org": {
		ClientID: "36ee2eeb4f179b38db8f066fd4ca9751f4b003653a205fc1422f110ca60181f6",
		Endpoint: replaceHost(endpoints.GitLab, "invent.kde.org"),
		Scopes:   []string{"read_repository", "write_repository"}},
	"gitea.com": {
		ClientID: "e13f8ebc-398d-4091-9481-5a37a76b51f6",
		Endpoint: oauth2.Endpoint{AuthURL: "https://gitea.com/login/oauth/authorize", TokenURL: "https://gitea.com/login/oauth/access_token"}},
	// https://codeberg.org/user/settings/applications/oauth2/223
	"codeberg.org": {
		ClientID: "246ca3e8-e974-430c-b9ec-3d4e2b54ad28",
		Endpoint: oauth2.Endpoint{AuthURL: "https://codeberg.org/login/oauth/authorize", TokenURL: "https://codeberg.org/login/oauth/access_token"}},
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

func printVersion(w io.Writer) {
	fmt.Fprintf(w, "git-credential-oauth %s\n", getVersion())
}

func parse(input string) map[string]string {
	lines := strings.Split(string(input), "\n")
	pairs := map[string]string{}
	for _, line := range lines {
		if key, value, ok := strings.Cut(line, "="); ok {
			_, exists := pairs[key]
			if strings.HasSuffix(key, "[]") && exists {
				pairs[key] += "\n" + value
			} else {
				pairs[key] = value
			}
		}
	}
	return pairs
}

func main() {
	ctx := context.Background()
	flag.BoolVar(&verbose, "verbose", false, "log debug information to stderr")
	var device bool
	flag.BoolVar(&device, "device", false, "instead of opening a web browser locally, print a code to enter on another device")
	var bearer bool
	flag.BoolVar(&bearer, "bearer", false, "Prefer Bearer authentication for supported hosts")
	flag.Usage = func() {
		if verbose {
			printVersion(os.Stderr)
		}
		fmt.Fprintln(os.Stderr, "usage: git credential-oauth [<options>] <action>")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Actions:")
		fmt.Fprintln(os.Stderr, "  get            Generate credential [called by Git]")
		fmt.Fprintln(os.Stderr, "  configure      Configure as Git credential helper")
		fmt.Fprintln(os.Stderr, "  unconfigure    Unconfigure as Git credential helper")
		fmt.Fprintln(os.Stderr, "  version        Print version")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "See also https://github.com/hickford/git-credential-oauth")
	}
	flag.Parse()
	if device {
		c := configByHost["android.googlesource.com"]
		c.ClientID = "897755559425-82ha835rqnprtctvm8shjc2p86bk0eru.apps.googleusercontent.com"
		c.ClientSecret = "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"
		configByHost["android.googlesource.com"] = c
	}
	args := flag.Args()
	if len(args) != 1 {
		flag.Usage()
		os.Exit(2)
	}
	switch args[0] {
	case "get":
		if verbose {
			printVersion(os.Stderr)
		}
		input, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalln(err)
		}
		pairs := parse(string(input))
		if verbose {
			fmt.Fprintln(os.Stderr, "input:", pairs)
		}
		host := pairs["host"]
		looksLikeGitLab := strings.HasPrefix(host, "gitlab.") || strings.Contains(pairs["wwwauth[]"], `realm="GitLab"`)
		looksLikeGitea := strings.Contains(pairs["wwwauth[]"], `realm="Gitea"`)
		looksLikeGitHub := strings.HasPrefix(host, "github.") || strings.Contains(pairs["wwwauth[]"], `realm="GitHub"`)
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
			c.Endpoint = oauth2.Endpoint{
				AuthURL:       fmt.Sprintf("%s/oauth/authorize", urll),
				TokenURL:      fmt.Sprintf("%s/oauth/token", urll),
				DeviceAuthURL: fmt.Sprintf("%s/oauth/authorize_device", urll),
			}
			c.Scopes = configByHost["gitlab.com"].Scopes
		}
		if !found && looksLikeGitea {
			c.ClientID = "a4792ccc-144e-407e-86c9-5e7d8d9c3269"
			c.Endpoint = oauth2.Endpoint{
				AuthURL:  fmt.Sprintf("%s/login/oauth/authorize", urll),
				TokenURL: fmt.Sprintf("%s/login/oauth/access_token", urll),
			}
			c.Scopes = configByHost["gitea.com"].Scopes
		}
		if !found && looksLikeGitHub {
			c.Endpoint = oauth2.Endpoint{
				AuthURL:       fmt.Sprintf("%s/login/oauth/authorize", urll),
				TokenURL:      fmt.Sprintf("%s/login/oauth/access_token", urll),
				DeviceAuthURL: fmt.Sprintf("%s/login/device/code", urll),
			}
			c.Scopes = configByHost["github.com"].Scopes
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
			bytes, err = exec.Command(gitPath, "config", "--get-urlmatch", "credential.oauthDeviceAuthURL", urll).Output()
			if err == nil {
				c.Endpoint.DeviceAuthURL, err = urlResolveReference(urll, strings.TrimSpace(string(bytes)))
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
			} else if looksLikeGitHub {
				fmt.Fprintf(os.Stderr, "It looks like you're authenticating to GitHub Enterprise Server. See issue https://github.com/hickford/git-credential-oauth/issues/39 and workaround https://github.com/hickford/git-credential-oauth/issues/39#issuecomment-1747514543.\n")
			} else if c.ClientID != "" {
				fmt.Fprintf(os.Stderr, "Missing OAuth configuration for host %s. Please set Git config keys credential.%s.oauthAuthURL and credential.%s.oauthTokenURL.", host, urll, urll)
			} else if verbose {
				fmt.Fprintf(os.Stderr, "Missing OAuth configuration for host %s. Please set Git config key credential.%s.oauthClientId.", host, urll)
			}
			return
		}

		var token *oauth2.Token
		if pairs["oauth_refresh_token"] != "" {
			// Try refresh token (fast, doesn't open browser)
			if verbose {
				fmt.Fprintln(os.Stderr, "refreshing token...")
			}
			token, err = c.TokenSource(ctx, &oauth2.Token{RefreshToken: pairs["oauth_refresh_token"]}).Token()
			if err != nil {
				fmt.Fprintln(os.Stderr, "error during OAuth token refresh", err)
			}
		}

		var authURLSuffix string
		if pairs["username"] != "" && pairs["username"] != "oauth2" {
			if looksLikeGitHub {
				// https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#1-request-a-users-github-identity
				authURLSuffix = fmt.Sprintf("&login=%s", pairs["username"])
			}
			if strings.HasSuffix(host, ".googlesource.com") {
				// https://developers.google.com/identity/protocols/oauth2/web-server#creatingclient
				authURLSuffix = fmt.Sprintf("&login_hint=%s", pairs["username"])
			}
		}

		if token == nil {
			// Generate new token (opens browser, may require user input)
			if device {
				token, err = getDeviceToken(ctx, c)
			} else {
				token, err = getToken(ctx, c, authURLSuffix)
			}
			if err != nil {
				log.Fatalln(err)
			}
		}
		if verbose {
			fmt.Fprintln(os.Stderr, "token:", token)
		}
		// "A capability[] directive must precede any value depending on it and these directives should be the first item announced in the protocol." https://git-scm.com/docs/git-credential
		fmt.Println("capability[]=authtype")
		output := map[string]string{}
		hostSupportsBearer := host == "bitbucket.org" || host == "codeberg.org" || host == "gitea.com" || looksLikeGitea || strings.HasSuffix(host, ".googlesource.com")
		authtypeCapable := strings.Contains(pairs["capability[]"], "authtype")
		if bearer && hostSupportsBearer && authtypeCapable {
			output["authtype"] = "Bearer"
			output["credential"] = token.AccessToken
		} else {
			output["password"] = token.AccessToken
			if pairs["username"] == "" {
				if host == "bitbucket.org" {
					// https://support.atlassian.com/bitbucket-cloud/docs/use-oauth-on-bitbucket-cloud/#Cloning-a-repository-with-an-access-token
					output["username"] = "x-token-auth"
				} else {
					// https://docs.gitlab.com/ee/api/oauth2.html#access-git-over-https-with-access-token
					output["username"] = "oauth2"
				}
			}
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
				// six hours
				storage = "cache --timeout 21600"
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
	case "capability":
		// https://git-scm.com/docs/git-credential#CAPA-IOFMT
		fmt.Println("version 0")
		fmt.Println("capability authtype")
	case "version":
		printVersion(os.Stdout)
	}
}

var template string = `<!DOCTYPE html>
<html lang="en">
<head>
	<title>Git authentication</title>
	<meta name="color-scheme" content="light dark" />
</head>
<body>
<p>Success. You may close this page and return to Git.</p>
<p style="font-style: italic">&mdash;<a href="https://github.com/hickford/git-credential-oauth">git-credential-oauth</a> %s</p>
</body>
</html>`

func getToken(ctx context.Context, c oauth2.Config, authURLSuffix string) (*oauth2.Token, error) {
	state := oauth2.GenerateVerifier()
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
		origHostname := url.Hostname()
		if url.Port() == "" {
			url.Host += ":0"
		}
		l, err := net.Listen("tcp", url.Host)
		if err != nil {
			log.Fatalln(err)
		}
		server.Listener = l
		server.Start()
		url.Host = l.Addr().String()
		if verbose {
			fmt.Fprintf(os.Stderr, "listening on %s", url.Host)
		}
		if url.Hostname() != origHostname {
			// restore original hostname such as 'localhost'
			url.Host = fmt.Sprintf("%s:%s", origHostname, url.Port())
		}
		c.RedirectURL = url.String()
	}
	defer server.Close()
	verifier := oauth2.GenerateVerifier()
	authCodeURL := c.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
	authCodeURL += authURLSuffix
	fmt.Fprintf(os.Stderr, "Please complete authentication in your browser...\n%s\n", authCodeURL)
	var open string
	var p []string
	switch runtime.GOOS {
	case "windows":
		open = "rundll32"
		p = append(p, "url.dll,FileProtocolHandler")
	case "darwin":
		open = "open"
	default:
		open = "xdg-open"
	}
	p = append(p, authCodeURL)

	// TODO: wait for server to start before opening browser

	cmd := exec.Command(open, p...)
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr

	if _, err := exec.LookPath(open); err == nil {
		if err := cmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Unable to open browser using '%s': %s\n", open, err)
		}
	}

	query := <-queries

	if err := cmd.Wait(); err != nil {
		fmt.Fprintf(os.Stderr, "Browser '%s' terminates with failure: %s\n", open, err)
	}

	server.Close()

	if verbose {
		fmt.Fprintln(os.Stderr, "query:", query)
	}
	if query.Get("state") != state {
		return nil, fmt.Errorf("state mismatch")
	}
	code := query.Get("code")
	return c.Exchange(ctx, code, oauth2.VerifierOption(verifier))
}

func getDeviceToken(ctx context.Context, c oauth2.Config) (*oauth2.Token, error) {
	deviceAuth, err := c.DeviceAuth(ctx)
	if err != nil {
		log.Fatalln(err)
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "%+v\n", deviceAuth)
	}
	fmt.Fprintf(os.Stderr, "Please enter code %s at %s\n", deviceAuth.UserCode, deviceAuth.VerificationURI)
	return c.DeviceAccessToken(ctx, deviceAuth)
}

func replaceHost(e oauth2.Endpoint, host string) oauth2.Endpoint {
	e.AuthURL = replaceHostInURL(e.AuthURL, host)
	e.TokenURL = replaceHostInURL(e.TokenURL, host)
	e.DeviceAuthURL = replaceHostInURL(e.DeviceAuthURL, host)
	return e
}

func replaceHostInURL(originalURL, host string) string {
	if originalURL == "" {
		return ""
	}
	u, err := url.Parse(originalURL)
	if err != nil {
		panic(err)
	}
	u.Host = host
	return u.String()
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
