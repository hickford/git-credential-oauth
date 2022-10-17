package main

import (
	"context"
	"crypto/rand"
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
	"strings"

	"go.pinniped.dev/pkg/oidcclient/pkce"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

var configByHost = map[string]oauth2.Config{
	// https://github.com/settings/applications/2017944 owned by hickford
	"github.com": {ClientID: "b895675a4e2cf54d5c6c", ClientSecret: "2b746eea028711749c5062b9fe626fed78d03cc0", Endpoint: endpoints.GitHub, Scopes: []string{"repo", "gist", "workflow"}},
	// https://gitlab.com/oauth/applications/232663 owned by hickford
	"gitlab.com":             {ClientID: "10bfbbf46e5b760b55ce772a262d7a0205eacc417816eb84d37d0fb02c89bb97", ClientSecret: "e1802e0ac361efc72f8e2024e6fd5855bfdf73524b67740c05e755f55b97eb39", Endpoint: endpoints.GitLab, Scopes: []string{"read_repository", "write_repository"}},
	"gitlab.freedesktop.org": {ClientID: "ba28f287f465c03c629941bca9de965923c561f8e967ce02673a0cd937a94b6f", ClientSecret: "e3b4dba6e99a0b25cc3d3d640e418d6cc5dbeb2e2dc4c3ca791d2a22308e951c", Endpoint: replaceHost(endpoints.GitLab, "gitlab.freedesktop.org"), Scopes: []string{"read_repository", "write_repository"}},
	"gitea.com":              {ClientID: "e13f8ebc-398d-4091-9481-5a37a76b51f6", ClientSecret: "gto_gyodepoilwdv4g2nnigosazr2git7kkko3gadqgwqa3f6dxugi6a", Endpoint: oauth2.Endpoint{AuthURL: "https://gitea.com/login/oauth/authorize", TokenURL: "https://gitea.com/login/oauth/access_token"}},
	"bitbucket.org":          {ClientID: "abET6ywGmTknNRvAMT", ClientSecret: "df8rsnkAxuHCgZrSgu5ykJQjrbGVzT9m", Endpoint: endpoints.Bitbucket, Scopes: []string{"repository", "repository:write"}},
}

var (
	verbose bool
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func printVersion() {
	if verbose {
		fmt.Fprintf(os.Stderr, "git-credential-oauth %s, commit %s, built at %s\n", version, commit, date)
	}
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
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalln(err)
		}
		lines := strings.Split(string(raw), "\n")
		pairs := map[string]string{}
		for _, line := range lines {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) >= 2 {
				pairs[parts[0]] = parts[1]
			}
		}
		if verbose {
			fmt.Fprintln(os.Stderr, "input: ", pairs)
		}
		c, ok := configByHost[pairs["host"]]
		if !ok {
			return
		}
		state, err := randomString(32)
		if err != nil {
			log.Fatalln(err)
		}
		queries := make(chan url.Values)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// TODO: consider whether to show errors in browser or command line
			queries <- r.URL.Query()
			w.Write([]byte("Success. You may close this page and return to Git."))
		}))
		defer server.Close()
		c.RedirectURL = server.URL
		pcode, err := pkce.Generate()
		if err != nil {
			log.Fatalln(err)
		}
		// TODO: use refresh token without opening browser
		url := c.AuthCodeURL(state, pcode.Challenge(), pcode.Method())
		fmt.Fprintln(os.Stderr, "Please complete authentication in your browser")
		if verbose {
			fmt.Fprintln(os.Stderr, url)
		}
		err = exec.Command("open", url).Run()
		if err != nil {
			log.Fatalln(err)
		}
		query := <-queries
		if verbose {
			fmt.Fprintln(os.Stderr, "query:", query)
		}
		server.Close()
		var code string
		if query.Get("state") == state {
			code = query.Get("code")
		} else {
			log.Fatalln(query)
		}
		token, err := c.Exchange(context.Background(), code, pcode.Verifier())
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

func randomString(n int) (string, error) {
	data := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
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
