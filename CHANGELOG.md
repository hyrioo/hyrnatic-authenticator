# Changelog

All notable changes to `hyrnatic-authenticator` will be documented in this file.

## Unreleased

### Changed

- Replaced the permission and permission-group API with registered, typed scopes and persisted custom scopes.
- Replaced `assignScope()`, `modelCan()`, `tokenCan()`, and `modelAndTokenCan()` with `scope()`, `modelHasScope()`, `tokenHasScope()`, and `hasScope()`.
- Tokens inherit the owner's effective scopes when `setScopes()` is omitted; `setScopes([])` now explicitly issues a token without scopes.
