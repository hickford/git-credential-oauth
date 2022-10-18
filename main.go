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
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/authhandler"
	"golang.org/x/oauth2/endpoints"
)

var configByHost = map[string]oauth2.Config{
	// https://github.com/settings/applications/2017944
	"github.com": {ClientID: "b895675a4e2cf54d5c6c", ClientSecret: "2b746eea028711749c5062b9fe626fed78d03cc0", Endpoint: endpoints.GitHub, Scopes: []string{"repo", "gist", "workflow"}},
	// https://gitlab.com/oauth/applications/232663
	"gitlab.com": {ClientID: "10bfbbf46e5b760b55ce772a262d7a0205eacc417816eb84d37d0fb02c89bb97", ClientSecret: "e1802e0ac361efc72f8e2024e6fd5855bfdf73524b67740c05e755f55b97eb39", Endpoint: endpoints.GitLab, Scopes: []string{"read_repository", "write_repository"}},
	// https://gitlab.freedesktop.org/oauth/applications/68
	"gitlab.freedesktop.org": {ClientID: "ba28f287f465c03c629941bca9de965923c561f8e967ce02673a0cd937a94b6f", ClientSecret: "e3b4dba6e99a0b25cc3d3d640e418d6cc5dbeb2e2dc4c3ca791d2a22308e951c", Endpoint: replaceHost(endpoints.GitLab, "gitlab.freedesktop.org"), Scopes: []string{"read_repository", "write_repository"}},
	// https://gitlab.gnome.org/oauth/applications/112
	"gitlab.gnome.org": {ClientID: "9719f147e6117ef0ee9954516bd7fe292176343a7fd24a8bcd5a686e8ef1ec71", ClientSecret: "f4e027961928ba9322fd980f5c4ee768dc7b6cb8fd7a81f959feb61b8fdec9f3", Endpoint: replaceHost(endpoints.GitLab, "gitlab.gnome.org"), Scopes: []string{"read_repository", "write_repository"}},
	// https://code.videolan.org/oauth/applications/109
	"code.videolan.org": {ClientID: "a6d235d8ebc7a7eacc52be6dba0b5bc31a6d013be85e2d15f0fc9006b4c6e9ff", ClientSecret: "639bea9d340709eeb4c76522666dbe0bb477e461d7945738e9b6693f1c260f3d", Endpoint: replaceHost(endpoints.GitLab, "code.videolan.org"), Scopes: []string{"read_repository", "write_repository"}},
	// https://salsa.debian.org/oauth/applications/95
	"salsa.debian.org": {ClientID: "0ae3637439058e4f261db17a001a7ec9235e1fda88b6d9221222a57c14ed830d", ClientSecret: "c06b1efadec522dad5b545039d6d601b2808998e755959bf869ba45a382aee7a", Endpoint: replaceHost(endpoints.GitLab, "salsa.debian.org"), Scopes: []string{"read_repository", "write_repository"}},
	// https://gitlab.haskell.org/oauth/applications/3
	"gitlab.haskell.org": {ClientID: "078baa23982db8d6e179fb7da816b92e6a761268b8b35a7aa1e7ee7a3891a426", ClientSecret: "a805ce33fe571390c78dbc90c21f06b95cefa7451ed3e73ced92b67b2bc33583", Endpoint: replaceHost(endpoints.GitLab, "gitlab.haskell.org"), Scopes: []string{"read_repository", "write_repository"}},
	// https://gitea.com/user/settings/applications/oauth2/218
	"gitea.com": {ClientID: "e13f8ebc-398d-4091-9481-5a37a76b51f6", ClientSecret: "gto_gyodepoilwdv4g2nnigosazr2git7kkko3gadqgwqa3f6dxugi6a", Endpoint: oauth2.Endpoint{AuthURL: "https://gitea.com/login/oauth/authorize", TokenURL: "https://gitea.com/login/oauth/access_token"}},
	// https://codeberg.org/user/settings/applications/oauth2/223
	"codeberg.org": {ClientID: "246ca3e8-e974-430c-b9ec-3d4e2b54ad28", ClientSecret: "gto_4stsgpwkgtsvayljdsg3xq33l2v3v245rlc45tnpt4cjp7eyw5gq", Endpoint: oauth2.Endpoint{AuthURL: "https://codeberg.org/login/oauth/authorize", TokenURL: "https://codeberg.org/login/oauth/access_token"}},
	// https://bitbucket.org/hickford/workspace/settings/oauth-consumers/983448/edit
	"bitbucket.org": {ClientID: "abET6ywGmTknNRvAMT", ClientSecret: "df8rsnkAxuHCgZrSgu5ykJQjrbGVzT9m", Endpoint: endpoints.Bitbucket, Scopes: []string{"repository", "repository:write"}},
}

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
		fmt.Fprintln(os.Stderr, "usage: git credential-cache [<options>] <action>")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "See also https://git-scm.com/docs/gitcredentials#_custom_helpers")
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
			fmt.Fprintln(os.Stderr, "input: ", pairs)
		}
		c, ok := configByHost[pairs["host"]]
		if !ok {
			return
		}
		state := randomString(16)
		queries := make(chan url.Values)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// TODO: consider whether to show errors in browser or command line
			queries <- r.URL.Query()
			w.Write([]byte("Success. You may close this page and return to Git."))
		}))
		defer server.Close()
		c.RedirectURL = server.URL
		tokenSource := authhandler.TokenSourceWithPKCE(context.Background(), &c, state, func(authCodeURL string) (code string, state string, err error) {
			defer server.Close()
			fmt.Fprintln(os.Stderr, "Please complete authentication in your browser")
			if verbose {
				fmt.Fprintln(os.Stderr, authCodeURL)
			}
			err = exec.Command("open", authCodeURL).Run()
			if err != nil {
				return "", "", err
			}
			query := <-queries
			if verbose {
				fmt.Fprintln(os.Stderr, "query:", query)
			}
			return query.Get("code"), query.Get("state"), nil
		}, generatePKCEParams())
		token, err := tokenSource.Token()
		if err != nil {
			log.Fatalln(err)
		}
		if verbose {
			fmt.Fprintln(os.Stderr, "token:", token)
		}
		fmt.Printf("username=%s\n", "oauth2")
		fmt.Printf("password=%s\n", token.AccessToken)
	}
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
