git-credential-oauth
====================

[![Go Reference](https://pkg.go.dev/badge/github.com/hickford/git-credential-oauth.svg)](https://pkg.go.dev/github.com/hickford/git-credential-oauth)

*No more passwords! No more personal access tokens! No more SSH keys!*

A Git credential helper that securely authenticates to GitHub, GitLab, BitBucket and other forges using [OAuth](https://oauth.net/).

The first time you push, the helper will open a browser window to authenticate. Subsequent pushes within the cache timeout require no interaction.

## Motivation

Two-factor authentication changed how users authenticate to websites, but Git still assumes users can type a password from memory. Personal access tokens are easy enough to copy and paste but awkward to store securely. [git-credential-cache](https://git-scm.com/docs/git-credential-cache) works well for passwords but not personal access tokens because the token is lost when the cache expires. All in all, the usability is so poor that the [most popular advice on StackOverflow](https://stackoverflow.com/a/35942890/284795) is to insecurely save credentials in plaintext.

## Installation

Download from https://github.com/hickford/git-credential-oauth/releases

Alternatively, Go users can install to `~/go/bin` with:

	go install github.com/hickford/git-credential-oauth@latest

Test that Git can find the binary:

	git credential-oauth

If you have problems, make sure that the binary is [located in the path](https://superuser.com/a/284351/62691) and executable.

## Configuration

Git is cleverly designed to [support multiple credential helpers](https://git-scm.com/docs/gitcredentials#_custom_helpers). To fill credentials, Git calls each helper in turn until it has the information it needs. git-credential-oauth is a read-only credential-generating helper, designed to be used in combination with a storage helper.  

To use together with [git-credential-cache](https://git-scm.com/docs/git-credential-cache):

```sh
git config --global --unset-all credential.helper
git config --global --add credential.helper "cache --timeout 7200" # two hours
git config --global --add credential.helper oauth
```

You may choose a different storage helper such as `osxkeychain` or `wincred`, but git-credential-oauth must be configured last. This ensures Git checks for *stored* credentials before generating *new* credentials.

### Manual config

Edit your [global git config](https://git-scm.com/docs/git-config#FILES) `~/.gitconfig` to include the following lines:

```ini
[credential]
	helper = cache --timeout 7200	# two hours
	helper = oauth
```

### Unconfiguration

Edit `~/.gitconfig` manually, or:

	git config --global --unset-all credential.helper oauth

## Philosophy

* Do one thing well, namely OAuth authentication.
* Interoperate with other credential helpers.
* Contribute upstream to improve the ecosystem.

## Comparison with Git Credential Manager

[Git Credential Manager](https://github.com/GitCredentialManager/git-credential-manager) has broader functionality including storage. However because it's developed in .NET, GCM is harder to build and install on Linux. In particular, GCM is awkward for Linux distributions to package.

|                | Git Credential Manager | git-credential-oauth |
|----------------|------------------------|----------------------|
| Cross platform | ✓                      | ✓                     |
| Linux arm64 support            | 🗙               | ✓                            |
| Installation size | 150 MB              | 5 MB                 |
| Storage        | ✓     | Used in conjuction with other helpers |
| Development    | .NET                   | Go                   |
| Packaged in Linux distributions               | [Challenging to package](https://github.com/dotnet/source-build/discussions/2960)            | Ready to package       |

Disclaimer: I also contribute to GCM.

## Development

Install locally with `go install .`.

### Debugging

Use the `-verbose` flag to print more details:

```sh
git config --global --unset-all credential.helper oauth
git config --global --add credential.helper "oauth -verbose"
```

You can also test git-credential-oauth in isolation:

```
echo host=gitlab.com\nprotocol=https | git-credential-oauth -verbose get
```

You can test configured helpers in combination with `git credential fill`, eg.

```
echo url=https://gitlab.com | git credential fill
```

To see which helpers Git calls, set `export GIT_TRACE=1`.

## Disclaimer

This is not an officially supported Google product.
