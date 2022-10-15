git-credential-oauth
====================

*No more passwords! No more personal access tokens! No more SSH keys!*

A Git credential helper that securely authenticates to GitHub, GitLab and other forges using OAuth.

## Motivation

Two-factor authentication

## Comparison with Git Credential Manager

[Git Credential Manager](https://github.com/GitCredentialManager/git-credential-manager) has broader functionality including platform-specific storage. However because it's developed in .NET, it is harder to build and install on Linux.

Philosophy wise, this project is intentionally minimal, deferring other operations to other helpers.

## Roadmap

* Install instructions for Go users
* Binaries
* Package for Linux distributions
