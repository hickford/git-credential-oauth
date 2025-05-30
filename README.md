git-credential-oauth
====================

*No more passwords! No more personal access tokens! No more SSH keys!*

git-credential-oauth is a Git credential helper that securely authenticates to GitHub, GitLab, BitBucket and Gerrit using [OAuth](https://datatracker.ietf.org/wg/oauth/about/).

The first time you authenticate, the helper opens a browser window to the host.
Subsequent authentication within storage lifetime is non interactive.

## Motivation

Git assumes users can type a password from memory, but hosts such as GitHub no longer accept passwords without two-factor authentication.
Personal access tokens are easy enough to copy and paste but awkward to store securely.
[git-credential-cache](https://git-scm.com/docs/git-credential-cache) works well for passwords but not personal access tokens because the token is lost when the cache expires.
All in all, the usability is so poor that the [most popular advice on StackOverflow](https://stackoverflow.com/a/35942890/284795) is to insecurely save credentials in plaintext!

OAuth has multiple advantages over personal access tokens or SSH:

| Advantage                                  | OAuth | Personal access token | SSH |
|--------------------------------------------|-------|-----------------------|-----|
| Clone public repo without setup            | ✔     | ✔                     | 🗙   |
| Authenticate to popular hosts without setup| ✔     | 🗙                     | 🗙   |
| Server authenticity verified automatically | ✔     | ✔                     | 🗙   |
| Protections against token theft[^1] | [✔](https://www.ietf.org/archive/id/draft-ietf-oauth-security-topics-22.html#name-refresh-token-protection)     | 🗙                     | *only if key has passphrase*   |

[^1]: Scenario: an old disk backup is leaked.

## Features by host

| Host                | Preconfigured | OAuth             | OAuth device flow |
|---------------------|---------------|-------------------|-------------------|
| github.com          | ✔             | ✔                 | ✔                 |
| GitHub Enterprise Server | 🗙        | ✔                 | ✔                 |
| gitlab.com          | ✔             | ✔                 | ✔                 |
| gitlab.example.com  | [🗙](https://gitlab.com/gitlab-org/gitlab/-/issues/374172)            | ✔                 | ✔                 |
| gitea.example.com   | ✔             | ✔                 | [🗙](https://github.com/go-gitea/gitea/issues/27309)                 |
| forgejo.example.com | ✔             | ✔                 | [🗙](https://codeberg.org/forgejo/forgejo/issues/4830) |
| bitbucket.org       | ✔             | ✔                 | 🗙                 |
| googlesource.com    | ✔             | ✔                 | [🗙](https://github.com/hickford/git-credential-oauth/issues/38) |

OAuth device flow is useful for browserless systems.

## Installation

### All platforms

**Download** binary from <https://github.com/hickford/git-credential-oauth/releases>.

Then test that Git can find the application:

	git credential-oauth

If you have problems, make sure that the binary is [located in the path](https://superuser.com/a/284351/62691) and [is executable](https://askubuntu.com/a/229592/18504).

### Linux

[Several Linux distributions](https://repology.org/project/git-credential-oauth/versions) include a git-credential-oauth package including [Fedora](https://packages.fedoraproject.org/pkgs/git-credential-oauth/git-credential-oauth/), [Debian](https://tracker.debian.org/pkg/git-credential-oauth) and [Ubuntu](https://packages.ubuntu.com/noble/git-credential-oauth). Ubuntu users can also use PPA [hickford/git-credential-oauth](https://launchpad.net/~hickford/+archive/ubuntu/git-credential-oauth) to install the latest release. 

[![Packaging status](https://repology.org/badge/vertical-allrepos/git-credential-oauth.svg?exclude_unsupported=1&header=)](https://repology.org/project/git-credential-oauth/versions)

### macOS

#### Homebrew

macOS users can install from [Homebrew](https://formulae.brew.sh/formula/git-credential-oauth#default):

	brew install git-credential-oauth
	
#### MacPorts

macOS users can alternatively install via [MacPorts](https://ports.macports.org/port/git-credential-oauth/):

	sudo port install git-credential-oauth

### Windows

Install with [winget](https://learn.microsoft.com/en-us/windows/package-manager/winget/):

    winget install hickford.git-credential-oauth

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
git config --global --add credential.helper "cache --timeout 21600" # six hours
git config --global --add credential.helper oauth
```

You may choose a different storage helper such as `osxkeychain`, `wincred` or `libsecret`, but git-credential-oauth must be configured last. This ensures Git checks for *stored* credentials before generating *new* credentials.

**Windows users** are recommended to use storage helper `wincred`.

### Manual config

Edit your [global git config](https://git-scm.com/docs/git-config#FILES) `~/.gitconfig` to include the following lines:

```ini
[credential]
	helper = cache --timeout 21600	# six hours
	helper = oauth
```

### Browserless systems

On systems without a web browser, set the `-device` flag to authenticate on another device using [OAuth device flow](https://www.rfc-editor.org/rfc/rfc8628). 

```ini
[credential]
	helper = cache --timeout 21600	# six hours
	helper = oauth -device
```

Currently only GitHub and [GitLab](https://docs.gitlab.com/ee/api/oauth2.html#device-authorization-grant-flow) support this flow. See Gitea feature request [#27309](https://github.com/go-gitea/gitea/issues/27309).

### Unconfiguration

Edit `~/.gitconfig` manually, or run:

	git config --global --unset-all credential.helper oauth

## Custom hosts

### GitLab

> [!TIP]
> Would you like universal GitLab support without configuration? Vote for [GitLab issue #374172](https://gitlab.com/gitlab-org/gitlab/-/issues/374172)!

To use with a custom host, eg. `gitlab.example.com`:

1. [Register an OAuth application](https://docs.gitlab.com/ee/integration/oauth_provider.html#user-owned-applications) on the host.
    * Browse to eg. https://gitlab.example.com/-/profile/applications.
	* "Add new application"
	* Specify name `git-credential-oauth`.
	* Specify redirect URI `http://127.0.0.1`.
	* Uncheck "confidential"
	* Select scopes "read_repository" and "write_repository".
	* "Save application".
2. Adjust the config command below with the generated client id.
3. Share the config command with colleagues so they can skip the registration step.

```sh
git config --global credential.https://gitlab.example.com.oauthClientId <CLIENTID>
git config --global credential.https://gitlab.example.com.oauthScopes "read_repository write_repository"
git config --global credential.https://gitlab.example.com.oauthAuthURL /oauth/authorize
git config --global credential.https://gitlab.example.com.oauthTokenURL /oauth/token
git config --global credential.https://gitlab.example.com.oauthDeviceAuthURL /oauth/authorize_device
```

### Other

1. Register an OAuth application.
	* Specify name `git-credential-oauth`
	* Specify redirect URI `http://127.0.0.1`.
	* Select scopes for read and write Git operations.
2. Consult the documentation for OAuth scopes and URLs.
2. Adjust the config commands below with the generated client id, OAuth scopes and relative URLs.
3. Share the config commands with colleagues so they can skip the registration step.

```sh
git config --global credential.https://code.example.com.oauthClientId <CLIENTID>
git config --global credential.https://code.example.com.oauthScopes "read_repository write_repository"
git config --global credential.https://code.example.com.oauthAuthURL /oauth/authorize
git config --global credential.https://code.example.com.oauthTokenURL /oauth/token
git config --global credential.https://code.example.com.oauthDeviceAuthURL /oauth/authorize_device
```

## Philosophy

* Do one thing well, namely OAuth authentication.
* Interoperate with other credential helpers.
* [Contribute upstream](https://lore.kernel.org/git/?q=f%3Ahickford+s%3Acredential) to improve the ecosystem.

## Comparison with Git Credential Manager

[Git Credential Manager](https://github.com/GitCredentialManager/git-credential-manager) (GCM) is an excellent credential helper with broader functionality. However because it's developed in .NET, GCM is [prohibitively difficult for Linux distributions to package](https://github.com/dotnet/source-build/discussions/2960).

|                | Git Credential Manager | git-credential-oauth |
|----------------|------------------------|----------------------|
| Cross platform | ✔                      | ✔                     |
| Linux arm64 support            | 🗙               | ✔                            |
| Packaged in Linux distributions               | 🗙            | ✔ ([many](https://repology.org/project/git-credential-oauth/versions)) |
| Installation size (Linux) | [82 MB](https://github.com/git-ecosystem/git-credential-manager/issues/1212#issuecomment-1530304873) | 5 MB                 |
| Installation size (Windows) | 4 MB | 5 MB                 |
| Ships with Git for Windows | ✔ | 🗙 |
| Credential storage | In built | Used together with any storage helper |
| Development    | .NET                   | Go                   |
| Lines of code | 40,000 | 500 |
| Minimum HTTP requests | 1 | 0 |
| Authentication to Azure DevOps | ✔ | 🗙 (try [git-credential-azure](https://github.com/hickford/git-credential-azure)) |
| Hosts with default config | 4 | 14 |

The maintainer personally uses GCM on Windows and git-credential-oauth on Linux.

## Troubleshooting

1. List Git credential helpers `git config --get-all credential.helper`. At least one storage helper should preceed `oauth`.
2. Check Git version `git --version` is at least 2.45. Older Git versions have [limited support for storing OAuth refresh tokens](https://github.com/hickford/git-credential-oauth/issues/20).
3. Check git-credential-oauth version is [recent](https://github.com/hickford/git-credential-oauth/releases/).
4. Check Git remote URL `git remote -v` does not contain a username.
5. Test git-credential-oauth in verbose mode for *your specific host* `printf host=example.com\nprotocol=https\n | git-credential-oauth -verbose get`. Set any config keys suggested.

### GitHub organizations

Some GitHub organizations require users to manually request approval for the app:

1. <https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-personal-account-on-github/managing-your-membership-in-organizations/requesting-organization-approval-for-oauth-apps>
2. <https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data/approving-oauth-apps-for-your-organization>

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

## See also

* [git-credential-azure](https://github.com/hickford/git-credential-azure): a Git credential manager that authenticates to Azure Repos
* [Git Credential Manager](https://github.com/git-ecosystem/git-credential-manager)
