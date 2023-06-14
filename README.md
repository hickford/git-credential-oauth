git-credential-oauth
====================

[![Go Reference](https://pkg.go.dev/badge/github.com/hickford/git-credential-oauth.svg)](https://pkg.go.dev/github.com/hickford/git-credential-oauth)

*No more passwords! No more personal access tokens! No more SSH keys!*

git-credential-oauth is a Git credential helper that securely authenticates to GitHub, GitLab, BitBucket and Gerrit using [OAuth](https://datatracker.ietf.org/wg/oauth/about/).

The first time you authenticate, the helper opens a browser window to the host.
Subsequent authentication within storage lifetime is non interactive.

## Why fork the original project
This is a fork of the [git-credential-oauth](https://github.com/hickford/git-credential-oauth) to make it work with ide's in our product [Conveyor](https://conveyordata.com). 
We want to support the following git repositories:
- azure devops (created a custom implementation: we will contribute this back to the main project if they want it)
- gitlab
- github
- bitbucket

Additionally, we made a couple of changes to make it easier to work for us:
- We want the redirect URL's to go to our control plane API such that we can forward them to the correct ide.
- We want to support overwriting the config through environment variables instead of only git config (easier to manage with kubernetes pods)
- 

## Motivation

Git assumes users can type a password from memory, but hosts such as GitHub no longer accept passwords without two-factor authentication.
Personal access tokens are easy enough to copy and paste but awkward to store securely.
[git-credential-cache](https://git-scm.com/docs/git-credential-cache) works well for passwords but not personal access tokens because the token is lost when the cache expires.
All in all, the usability is so poor that the [most popular advice on StackOverflow](https://stackoverflow.com/a/35942890/284795) is to insecurely save credentials in plaintext!

OAuth has multiple advantages over personal access tokens or SSH:

| Advantage                                  | OAuth | Personal access token | SSH |
|--------------------------------------------|-------|-----------------------|-----|
| Clone public repo without setup            | ✓     | ✓                     | 🗙   |
| Authenticate to popular hosts without setup| ✓     | 🗙                     | 🗙   |
| Server authenticity verified automatically | ✓     | ✓                     | 🗙   |
| Protections against token theft[^1] | [✓](https://www.ietf.org/archive/id/draft-ietf-oauth-security-topics-22.html#name-refresh-token-protection)     | 🗙                     | *only if key has passphrase*   |

[^1]: Scenario: an old disk backup is leaked.

## Installation

**Download** binary from https://github.com/hickford/git-credential-oauth/releases.

Then test that Git can find the application:

	git credential-oauth

If you have problems, make sure that the binary is [located in the path](https://superuser.com/a/284351/62691) and [is executable](https://askubuntu.com/a/229592/18504).

### Linux

[Several Linux distributions](https://repology.org/project/git-credential-oauth/versions) include a git-credential-oauth package including [Fedora](https://packages.fedoraproject.org/pkgs/git-credential-oauth/git-credential-oauth/), [Debian](https://tracker.debian.org/pkg/git-credential-oauth) and [Ubuntu](https://packages.ubuntu.com/lunar/git-credential-oauth).

[![Packaging status](https://repology.org/badge/vertical-allrepos/git-credential-oauth.svg?exclude_unsupported=1&header=)](https://repology.org/project/git-credential-oauth/versions)

### macOS

#### Homebrew

macOS users can install from [Homebrew](https://formulae.brew.sh/formula/git-credential-oauth#default):

	brew install git-credential-oauth
	
#### MacPorts

macOS users can alternatively install via [MacPorts](https://ports.macports.org/port/git-credential-oauth/):

	sudo port install git-credential-oauth

### Go users

Go users can install the latest release to `~/go/bin` with:

	go install github.com/hickford/git-credential-oauth@latest

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

## Conveyor oauth application setup
Register an Oauth application on the git repository:
    * specify name: conveyor ide <tenant>
    * specify redirect url: https://app.conveyordata.com/api/v2/ide/callback (or another cp-tenant when working on stg)
    * Define the scopes: read, write permissions to git repo and potentially email address of the user

Go to the following urls to create these applications:
- https://dev.azure.com/datamindedbe/_usersSettings/authorizations 
  - Normally everyone has access to the azure devops organization 
- https://github.com/settings/developers
  - I will transfer the oauth application to the datamindedbe organisation, so only admins of the organisation will be able to edit this

Put the credentials in ssm as a secure string.

### Use the configuration in Conveyor
The git-credential oauth tool supports 2 way to overwrite default Oauth configuration, namely:
- git config (as described in next section)
- environment variables

To specify the Oauth config for ides, you can use the following env variables:
```sh
export GC_OAUTH_<gitRepoName>_CLIENT_ID=<some-client-id>
export GC_OAUTH_<gitRepoName>_CLIENT_SECRET=<some-client-id>
export GC_OAUTH_<gitRepoName>_CLIENT_AUTH_URL=/oauth/authorize
export GC_OAUTH_<gitRepoName>_CLIENT_TOKEN_URL=/oauth/token
export GC_OAUTH_<gitRepoName>_SCOPES=<1 or more scopes separated by spaces>
```

where gitRepoName is one of: `GITLAB, GITHUB, BITBUCKET, DEVOPS` at the moment 
Note:
For the cloud based git repositories `gitlab, github, bitbucket, azure devops`, we included the auth and token urls.
When specifying them as environment variables, you only need to add the suffix (e.g. `oauth/authorize`) as this will be appended after the base url in your git clone command.

Additionally, the tool relies on the `CONVEYOR_IDE_URL` and the `CONVEYOR_API_URL` env variables to detect it is running in an ide to construct the correct callback url.
This is important because the callback-/redirectUrl defined by the git-credential-oauth tool should match exactly with the url defined when creating your oauth application.

## Custom hosts

To use with a custom host, eg. `gitlab.example.com`:

1. Register an OAuth application on the host. The [GitLab instructions](https://docs.gitlab.com/ee/integration/oauth_provider.html#user-owned-applications) are typical.
	* Specify name `git-credential-oauth`
	* Specify redirect URI `http://127.0.0.1`.
	* Select scopes for read and write Git operations.
2. Adjust the config commands below with the generated client id and *space-separated* scopes.
3. Share the config commands with colleagues so they can skip the registration step.

```sh
git config --global credential.https://gitlab.example.com.oauthClientId <CLIENTID>
git config --global credential.https://gitlab.example.com.oauthScopes read_repository write_repository
git config --global credential.https://gitlab.example.com.oauthAuthURL /oauth/authorize
git config --global credential.https://gitlab.example.com.oauthTokenURL /oauth/token
```

Would you like to see universal GitLab support? *Vote for [GitLab issue #374172](https://gitlab.com/gitlab-org/gitlab/-/issues/374172).

## Philosophy

* Do one thing well, namely OAuth authentication.
* Interoperate with other credential helpers.
* [Contribute upstream](https://lore.kernel.org/git/?q=f%3Ahickford+s%3Acredential) to improve the ecosystem.

## Comparison with Git Credential Manager

[Git Credential Manager](https://github.com/GitCredentialManager/git-credential-manager) (GCM) is an excellent credential helper with broader functionality. However because it's developed in .NET, GCM is [prohibitively difficult for Linux distributions to package](https://github.com/dotnet/source-build/discussions/2960).

|                | Git Credential Manager | git-credential-oauth |
|----------------|------------------------|----------------------|
| Cross platform | ✓                      | ✓                     |
| Linux arm64 support            | 🗙               | ✓                            |
| Packaged in Linux distributions               | 🗙            | ✓ [Many](https://repology.org/project/git-credential-oauth/versions) |
| Installation size (Linux) | [82 MB](https://github.com/git-ecosystem/git-credential-manager/issues/1212#issuecomment-1530304873) | 5 MB                 |
| Installation size (Windows) | 4 MB | 5 MB                 |
| Ships with Git for Windows | ✓ | 🗙 |
| Credential storage | In built | Used together with any storage helper |
| Development    | .NET                   | Go                   |
| Lines of code | 40,000 | 400 |
| Minimum HTTP requests | 1 | 0 |
| Authentication to Azure DevOps | ✓ | 🗙 |
| Hosts with default config | 4 | 12 |

The maintainer personally uses GCM on Windows and git-credential-oauth on Linux.

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
