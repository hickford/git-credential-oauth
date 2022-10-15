git-credential-oauth
====================

[![Go Reference](https://pkg.go.dev/badge/github.com/hickford/git-credential-oauth.svg)](https://pkg.go.dev/github.com/hickford/git-credential-oauth)

*No more passwords! No more personal access tokens! No more SSH keys!*

A Git credential helper that securely authenticates to GitHub, GitLab and other forges using [OAuth](https://oauth.net/).

## Motivation

Two-factor authentication changed how users authenticate to websites, but Git still assumes users can type a password from memory. Personal access tokens are easy enough to copy and paste but awkward to store securely. While [git-credential-cache](https://git-scm.com/docs/git-credential-cache) works well for passwords, the user has to generate a new token whenever the cache expires. All in all, the usability is so poor that the [most popular advice on StackOverflow](https://stackoverflow.com/a/35942890/284795) is to insecurely save credentials in plaintext.

## Philosophy

* Do one thing well, namely OAuth authentication.
* Interoperate with [other git credential helpers](https://git-scm.com/docs/gitcredentials). Defer storage to the user's choice.
* Contribute upstream to improve the ecosystem.

## Comparison with Git Credential Manager

[Git Credential Manager](https://github.com/GitCredentialManager/git-credential-manager) has broader functionality including its own implementations of platform-specific storage. GCM ships with Git for Windows, but because it's developed in .NET, it is harder to build and install on Linux. Disclaimer: I also contribute to GCM.

## Roadmap

* Install instructions for Go users
* Binaries
* Package for Linux distributions
* Upstream to Git?
