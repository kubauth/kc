

In the 'noui' subcommand, we do 'token, err := oauth2Config.PasswordCredentialsToken(ctx, login, password)'
The problem is there is no way with this function to retrieve also an OIDC id_token

Replace by a more appropriate function which will fetch also a JWT id token, if provided by the server.

Also, check this id_token, using go-oidc verifier

--

Write a subcommand 'jwtd', which take a jwt token as only parameter or from stdin and display its content in a pretty json.

In jwtd display, some claims, such as auth_time, exp, iat, rat seems to be timestamp. Patch the resulting json with a human readable string for these values.

--

Complete the ui.go subcommand to handle fetching of tokens using authorisation code flow. 
This will need to spawn a local browser to a local webserver, build with internal.httpserver