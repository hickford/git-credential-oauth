// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
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

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/authhandler"
	"golang.org/x/oauth2/endpoints"
)

var configByHost = map[string]oauth2.Config{
	// https://github.com/settings/applications/2017944
	"github.com": {ClientID: "b895675a4e2cf54d5c6c", ClientSecret: "2b746eea028711749c5062b9fe626fed78d03cc0", Endpoint: endpoints.GitHub, Scopes: []string{"repo", "gist", "workflow"}},
	// https://gitlab.com/oauth/applications/232663
	"gitlab.com": {ClientID: "10bfbbf46e5b760b55ce772a262d7a0205eacc417816eb84d37d0fb02c89bb97", ClientSecret: "e1802e0ac361efc72f8e2024e6fd5855bfdf73524b67740c05e755f55b97eb39", Endpoint: endpoints.GitLab, Scopes: []string{"read_repository", "write_repository"}},
}

var (
	verbose bool
)

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
		tokenSource := authhandler.TokenSource(context.Background(), &c, state, func(authCodeURL string) (code string, state string, err error) {
			defer server.Close()
			fmt.Fprintf(os.Stderr, "Please complete authentication in your browser...\n%s\n", authCodeURL)
			// TODO: wait for server to start before opening browser
			err = exec.Command("open", authCodeURL).Run()
			if err != nil {
				return "", "", err
			}
			query := <-queries
			if verbose {
				fmt.Fprintln(os.Stderr, "query:", query)
			}
			return query.Get("code"), query.Get("state"), nil
		})
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
