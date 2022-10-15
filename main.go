package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/gitlab"
)

var configByHost = map[string]oauth2.Config{
	// borrowed from GCM
	// TODO: create own
	"github.com": {ClientID: "0120e057bd645470c1ed", ClientSecret: "18867509d956965542b521a529a79bb883344c90", Endpoint: github.Endpoint},
	"gitlab.com": {ClientID: "172b9f227872b5dde33f4d9b1db06a6a5515ae79508e7a00c973c85ce490671e", ClientSecret: "f7b0fe4d82bc3c770b22b55cff60528fe52a859b", Endpoint: gitlab.Endpoint},
}

func main() {
	flag.Parse()
	if len(os.Args) <= 1 {
		fmt.Printf("usage: git-credential-oauth <action>")
		fmt.Printf("https://git-scm.com/docs/gitcredentials")
		os.Exit(1)
	}
	switch os.Args[1] {
	case "erase":
	case "store":
		// simply forward
		cmd := exec.Command("git", "credential-cache", os.Args[1])
		cmd.Stdin = os.Stdin
		if err := cmd.Run(); err != nil {
			log.Fatal(err)
		}
	case "get":
		raw, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			log.Fatal(err)
		}
		lines := strings.Split(string(raw), "\n")
		pairs := map[string]string{}
		for _, line := range lines {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) >= 2 {
				pairs[parts[0]] = parts[1]
			}
		}
		log.Print(pairs)
		cmd := exec.Command("git", "credential-cache", "get")
		cmd.Stdin = bytes.NewReader(raw)
		output, err := cmd.Output()
		if err != nil {
			log.Fatal(err)
		}
		if len(output) > 0 {
			log.Print("found existing credentials")
			os.Stdout.Write(output)
			return
		}
		state := "xyzzy" // TODO: random string
		codes := make(chan string)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			query := r.URL.Query()
			if query.Get("state") == state {
				codes <- query.Get("code")
				w.Write([]byte("Success. You may close this page and return to Git."))
			}
		}))
		defer server.Close()
		c, ok := configByHost[pairs["host"]]
		if !ok {
			return
		}
		c.RedirectURL = server.URL
		// workaround for GCM app
		c.RedirectURL = strings.ReplaceAll(server.URL, "127.0.0.1", "localhost")
		url := c.AuthCodeURL(state)
		fmt.Fprintf(os.Stderr, "Please complete authentication in your browser %s\n", url)
		err = exec.Command("open", url).Run()
		if err != nil {
			log.Fatal(err)
		}
		code := <-codes
		server.Close()
		token, err := c.Exchange(context.Background(), code)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("username=%s\n", "oauth2")
		fmt.Printf("password=%s\n", token.AccessToken)
	}
}
