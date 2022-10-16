git-credential-oauth
====================

[![Go Reference](https://pkg.go.dev/badge/github.com/hickford/git-credential-oauth.svg)](https://pkg.go.dev/github.com/hickford/git-credential-oauth)

*No more passwords! No more personal access tokens! No more SSH keys!*

A Git credential helper that securely authenticates to GitHub, GitLab and other forges using [OAuth](https://oauth.net/).

The first time you push, the helper will open a browser window to authenticate. Subsequent pushes within the cache timeout require no interaction.

## Motivation

Two-factor authentication changed how users authenticate to websites, but Git still assumes users can type a password from memory. Personal access tokens are easy enough to copy and paste but awkward to store securely. While [git-credential-cache](https://git-scm.com/docs/git-credential-cache) works well for passwords, the impossible-to-memorise token is lost when the cache expires, so user has to generate a new token daily. All in all, the usability is so poor that the [most popular advice on StackOverflow](https://stackoverflow.com/a/35942890/284795) is to insecurely save credentials in plaintext.

## Philosophy

* Do one thing well, namely OAuth authentication.
* Interoperate with [other git credential helpers](https://git-scm.com/docs/gitcredentials). Defer storage to the user's choice.
* Contribute upstream to improve the ecosystem.

## Installation and configuration

Download from https://github.com/hickford/git-credential-oauth/releases

Alternatively, Go users can install with:

    go install github.com/hickford/git-credential-oauth@latest

Test the binary:

	./git-credential-oauth

Then edit your `~/.gitconfig` to include the following lines, making sure to adjust the username:

```ini
[credential]
	helper = 
	helper = cache --timeout 7200	# two hours
	helper = /home/YOURUSERNAMEHERE/bin/git-credential-oauth
```

NB. The path must be an absolute path.

## Comparison with Git Credential Manager

[Git Credential Manager](https://github.com/GitCredentialManager/git-credential-manager) has broader functionality including its own implementations of platform-specific storage. However because it's developed in .NET, GCM is harder to build and install on Linux. In particular, GCM is awkward for Linux distributions to package.

|                | Git Credential Manager | git-credential-oauth |
|----------------|------------------------|----------------------|
| Cross platform | ✓                      | ✓                     |
| Linux arm64 support            | 🗙               | ✓                            |
| Installation size | 150 MB              | 7 MB                 |
| GUI            | ✓              | 🗙                            |
| Storage        | Implements storage     | Interoperates with other helpers |
| Development    | .NET                   | Go                   |
| Packaged in Linux distributions               | [Challenging](https://github.com/dotnet/source-build/discussions/2960)            | Ready to package?       |

Disclaimer: I also contribute to GCM.
