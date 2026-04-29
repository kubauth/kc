# v0.2.1

- token subcommand: Refactoring of the 'Authorization successful' page to display tokens in decoded form. 
- Add --userInfo option, to request also on userinfo endpoint.
- In default scopes, replace offline per offline_access (The standard value)
- Add `--ttl` and `--renewAt` parameters on `client` and `client-nui` subcommand to exercise token renewal.
- Introspection endpoint is now fetched from discovery mechanism.