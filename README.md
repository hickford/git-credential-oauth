git-credential-oauth
====================

*No more passwords! No more personal access tokens! No more SSH keys!*

A Git credential helper that securely authenticates to GitHub, GitLab and other forges using [OAuth](https://oauth.net/).

The first time you push, the helper will open a browser window to authenticate. Subsequent pushes within the cache timeout require no interaction.

## Motivation

Two-factor authentication changed how users authenticate to websites, but Git still assumes users can type a password from memory. Personal access tokens are easy enough to copy and paste but awkward to store securely. [git-credential-cache](https://git-scm.com/docs/git-credential-cache) works well for passwords but not personal access tokens because the token is lost when the cache expires. All in all, the usability is so poor that the [most popular advice on StackOverflow](https://stackoverflow.com/a/35942890/284795) is to insecurely save credentials in plaintext.

## Installation and configuration

Confirm the binary is in the path:

	git-credential-oauth

Test that Git can find the binary:

	git credential-oauth

Then edit your `~/.gitconfig` to include the following lines, adjusting the path to wherever you saved the binary:

```ini
[credential]
	helper = 
	helper = cache --timeout 7200	# two hours
	helper = oauth
```

You may use a different storage helper, but git-credential-oauth must be configured last.

### Uninstallation

Edit `~/.gitconfig` manually, or:

	git config --global --unset-all credential.helper oauth

## Development

Install locally with `go install .`.

### Debugging

Use the `-verbose` flag to print more details:

```ini
	helper = oauth -verbose
```

You can also test git-credential-oauth in isolation:

```
echo host=gitlab.com\nprotocol=https | git-credential-oauth -verbose get
```

You can test your Git config with `git credential fill`, eg.

```
echo host=gitlab.com\nprotocol=https | git credential fill
```

To see which helpers Git calls, set `export GIT_TRACE=1`.

## Disclaimer

This is not an officially supported Google product.
