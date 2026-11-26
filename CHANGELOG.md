# Changelog

All notable changes to `hyrnatic-authenticator` will be documented in this file.

## Unreleased

### Changed

- Replaced the permission and permission-group API with registered, typed scopes and persisted custom scopes.
- Replaced `assignScope()`, `modelCan()`, `tokenCan()`, and `modelAndTokenCan()` with `scope()`, `modelHasScope()`, `tokenHasScope()`, and `hasScope()`.
- Tokens follow the owner's current scopes when `setScopes()` is omitted. Calling `setScopes([])` explicitly denies all scope checks for the token.
- Restricted access and refresh tokens bind to their write-once family scope restrictions with a SHA-256 digest. Existing access tokens with matching scope lists remain valid. Restricted families with older refresh tokens require reissuance.
