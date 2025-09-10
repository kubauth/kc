

In the 'noui' subcommand, we do 'token, err := oauth2Config.PasswordCredentialsToken(ctx, login, password)'
The problem is there is no way with this function to retrieve also an OIDC id_token

Replace by a more appropriate function which will fetch also a JWT id token, if provided by the server.

Also, check this id_token, using go-oidc verifier

--

Write a subcommand 'jwtd', which take a jwt token as only parameter or from stdin and display its content in a pretty json.

In jwtd display, some claims, such as auth_time, exp, iat, rat seems to be timestamp. Patch the resulting json with a human readable string for these values.

--

Complete the ui.go subcommand to handle fetching of tokens using authorisation code flow. 
This will need to spawn a local browser to a local webserver, build with internal.httpserver.
Resulting Token will be displayed both in the resulting web page and to the command prompt, as already implemented.


Make PKCE as an option, triggered by a new CLI flag 'pkce', false by default

Add a small icon on top right corner of each token box to copy the value in the clipboard.


The problem is the copy buttons does not react at all. Clicking in do nothing

Add a --browser option for following values:
- "": Default. Use default browser
- "chrome": launch google chrome
- firefox: launch firefox
- safari: launch safari (Mac only)


Create a logout command which will
- find the 'end_session_endpoint' by fetching the server configuration (.well-known/openid-configuration)
- Launch a browser on this endpoint.
Use the 'openBrowser()' function of ui.go by moving it in common.go
Use the same code pattern than others commands.

for logout function, do not use oidcParams but duplicate only the needed flags

write a README.md for this 'kc' command line interface

In this README, add download from https://github.com/kubauth/kc/releases/tag/0.1.0 in the installation part
