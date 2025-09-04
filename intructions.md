

In the 'noui' subcommand, we do 'token, err := oauth2Config.PasswordCredentialsToken(ctx, login, password)'
The problem is there is no way with this function to retrieve also an OIDC id_token

Replace by a more appropriate function which will fetch also a JWT id token, if provided by the server.

Also, check this id_token, using go-oidc verifier


