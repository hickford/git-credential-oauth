git-credential-oauth
====================

[![Go Reference](https://pkg.go.dev/badge/github.com/hickford/git-credential-oauth.svg)](https://pkg.go.dev/github.com/hickford/git-credential-oauth)

*No more passwords! No more personal access tokens! No more SSH keys!*

A Git credential helper that securely authenticates to GitHub, GitLab, BitBucket and other forges using [OAuth](https://oauth.net/).

The first time you push, the helper will open a browser window to authenticate. Subsequent pushes within storage lifetime require no interaction.

## Motivation

Two-factor authentication changed how users authenticate to websites, but Git still assumes users can type a password from memory. Personal access tokens are easy enough to copy and paste but awkward to store securely. [git-credential-cache](https://git-scm.com/docs/git-credential-cache) works well for passwords but not personal access tokens because the token is lost when the cache expires. All in all, the usability is so poor that the [most popular advice on StackOverflow](https://stackoverflow.com/a/35942890/284795) is to insecurely save credentials in plaintext.

## Installation

Download from https://github.com/hickford/git-credential-oauth/releases.

Alternatively, Go users can install to `~/go/bin` with:

	go install github.com/hickford/git-credential-oauth@latest

Test that Git can find the binary:

	git credential-oauth

If you have problems, make sure that the binary is [located in the path](https://superuser.com/a/284351/62691) and is executable.

## Configuration

As a convenience, you can run:

```sh
git credential-oauth configure
```

This uses the recommended config below.

### How it works

Git is cleverly designed to [support multiple credential helpers](https://git-scm.com/docs/gitcredentials#_custom_helpers). To fill credentials, Git calls each helper in turn until it has the information it needs. git-credential-oauth is a read-only credential-generating helper, designed to be configured in combination with a storage helper.

To configure together with [git-credential-cache](https://git-scm.com/docs/git-credential-cache):

```sh
git config --global --unset-all credential.helper
git config --global --add credential.helper "cache --timeout 7200" # two hours
git config --global --add credential.helper oauth
```

You may choose a different storage helper such as `osxkeychain`, `wincred` or `libsecret`, but git-credential-oauth must be configured last. This ensures Git checks for *stored* credentials before generating *new* credentials.

**Windows users** must use storage helper `wincred` because [git-credential-cache isn't available on Windows](https://github.com/git-for-windows/git/issues/3892).

### Manual config

Edit your [global git config](https://git-scm.com/docs/git-config#FILES) `~/.gitconfig` to include the following lines:

```ini
[credential]
	helper = cache --timeout 7200	# two hours
	helper = oauth
```

### Unconfiguration

Edit `~/.gitconfig` manually, or run:

	git config --global --unset-all credential.helper oauth

## Custom hosts

To use with a custom host, eg. `gitlab.example.com`:

1. Register an OAuth application on the host. How to do this depends on the host, but the [GitLab instructions](https://docs.gitlab.com/ee/integration/oauth_provider.html#user-owned-applications) are typical.
	* Specify name `git-credential-oauth`
	* Specify redirect URI `http://127.0.0.1`.
	* Select scopes for read and write Git operations.
2. Adjust the config commands below with the generated client id, client secret and *space-separated* scopes.
3. Share the config commands with colleagues so they can skip the registration step.

```sh
git config --global credential.https://gitlab.example.com.oauthClientId <CLIENTID>
git config --global credential.https://gitlab.example.com.oauthClientSecret <CLIENTSECRET>
git config --global credential.https://gitlab.example.com.oauthScopes read_repository write_repository
git config --global credential.https://gitlab.example.com.oauthAuthURL /oauth/authorize
git config --global credential.https://gitlab.example.com.oauthTokenURL /oauth/token
```

Note: Some non-conforming servers are confused by native apps that listen on a random port. If you see an error about the redirect URI, try removing the port including prefix `%3A` from the auth URL. To workaround permanently, set an explicit port in the app redirect URI *and* Git config variable `credential.oauthRedirectURL`. Please report a bug to the server operators, citing OAuth [RFC 8252](https://datatracker.ietf.org/doc/html/rfc8252#section-7.3) "The authorization server MUST allow any port to be specified at the time of the request for loopback IP redirect URIs".

## Philosophy

* Do one thing well, namely OAuth authentication.
* Interoperate with other credential helpers.
* [Contribute upstream](https://lore.kernel.org/git/?q=f%3Ahickford+s%3Acredential) to improve the ecosystem.

## Comparison with Git Credential Manager

[Git Credential Manager](https://github.com/GitCredentialManager/git-credential-manager) has broader functionality including storage. However because it's developed in .NET, GCM is [challenging for Linux distributions to package](https://github.com/dotnet/source-build/discussions/2960).

|                | Git Credential Manager | git-credential-oauth |
|----------------|------------------------|----------------------|
| Cross platform | ✓                      | ✓                     |
| Linux arm64 support            | 🗙               | ✓                            |
| Installation size (Linux) | 150 MB              | 5 MB                 |
| Storage        | ✓     | Used in conjuction with other helpers |
| Development    | .NET                   | Go                   |
| Packaged in Linux distributions               | None            | [Multiple distros](https://repology.org/project/git-credential-oauth/versions) including [Fedora](https://packages.fedoraproject.org/pkgs/git-credential-oauth/git-credential-oauth/) and [Debian](https://tracker.debian.org/pkg/git-credential-oauth)       |

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
