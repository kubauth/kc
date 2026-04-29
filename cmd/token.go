/*
Copyright 2025 Kubotal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"kc/internal/httpclient"
	"kc/internal/httpsrv"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

var tokenParams struct {
	httpSrvConfig httpsrv.Config
	usePKCE       bool
	browser       string
}

func init() {
	initOidcParams(tokenCmd)
	tokenCmd.PersistentFlags().IntVar(&tokenParams.httpSrvConfig.DumpExchanges, "dumpServerExchanges", 0, "Dump http server req/resp (0, 1, 2 or 3)")
	tokenCmd.PersistentFlags().IntVarP(&tokenParams.httpSrvConfig.BindPort, "bindPort", "p", 9921, "Local server Bind port")
	tokenCmd.PersistentFlags().BoolVar(&tokenParams.usePKCE, "pkce", false, "Use PKCE (Proof Key for Code Exchange) for enhanced security")
	tokenCmd.PersistentFlags().StringVar(&tokenParams.browser, "browser", "", "Browser to use (default: system default, options: chrome, firefox, safari)")
	tokenCmd.PersistentFlags().DurationVarP(&oidcParams.ttl, "ttl", "t", time.Duration(0), "Time to live (default: 0)")
	tokenCmd.PersistentFlags().IntVar(&oidcParams.renewAt, "renewAt", 60, "Percentage of the ticket duration to Trigger renewal ")

}

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "token: Get token using authorisation code flow (Using browser)",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {

		logger, err := setupOidc(cmd)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		tokenParams.httpSrvConfig.BindAddr = "127.0.0.1"
		tokenParams.httpSrvConfig.Tls = false

		if oidcParams.ttl != 0 {
			ensureOfflineAccessScope(logger)
		}

		logger.Debug("Start with UI processing", "issuer", oidcParams.httpClientConfig.BaseURL)

		httpClient, err := httpclient.New(&oidcParams.httpClientConfig)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		ctx := oidc.ClientContext(context.Background(), httpClient)
		ctx = logr.NewContextWithSlogLogger(ctx, logger)

		provider, err := oidc.NewProvider(ctx, oidcParams.httpClientConfig.BaseURL)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		endpoints := provider.Endpoint()
		logger.Debug("OIDC provider initialized", "AuthURL", endpoints.AuthURL, "tokenURL", endpoints.TokenURL, "UserInfoURL", provider.UserInfoEndpoint())

		// Perform OAuth2 authorization code flow
		tokenResponse, err := performAuthorizationCodeFlow(ctx, provider, logger)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		verifyTokens(ctx, provider, tokenResponse, httpClient, logger)

		// Output tokens based on requested format
		outputTokens(tokenResponse, logger)

		if oidcParams.userInfo {
			dumpUserInfo(ctx, provider, httpClient, tokenResponse, logger)
		}

		if oidcParams.ttl != 0 {
			renewalLoop(ctx, provider, tokenResponse, httpClient, logger)
		}

		// Give some time to server
		time.Sleep(time.Millisecond * 2000)
	},
}

// performAuthorizationCodeFlow performs the complete OAuth2 authorization code flow
func performAuthorizationCodeFlow(ctx context.Context, provider *oidc.Provider, logger *slog.Logger) (*TokenResponse, error) {
	// Generate state parameter for CSRF protection
	state, err := generateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	// Generate PKCE parameters if enabled
	var codeVerifier, codeChallenge string
	if tokenParams.usePKCE {
		codeVerifier, err = generateRandomString(43)
		if err != nil {
			return nil, fmt.Errorf("failed to generate code verifier: %w", err)
		}
		// Generate code challenge using SHA256 hash of the verifier (RFC 7636)
		hash := sha256.Sum256([]byte(codeVerifier))
		codeChallenge = base64.RawURLEncoding.EncodeToString(hash[:])
		logger.Debug("PKCE enabled", "codeChallenge", codeChallenge[:10]+"...")
	} else {
		logger.Debug("PKCE disabled")
	}

	// Build redirect URI
	redirectURI := fmt.Sprintf("http://%s:%d/callback", tokenParams.httpSrvConfig.BindAddr, tokenParams.httpSrvConfig.BindPort)

	logger.Debug("Setting redirect URI", "redirectURI", redirectURI)

	// Configure OAuth2
	oauth2Config := oauth2.Config{
		ClientID:     oidcParams.clientId,
		ClientSecret: oidcParams.clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURI,
		Scopes:       oidcParams.scopes,
	}

	// Build authorization URL, conditionally with PKCE
	var authURL string
	if tokenParams.usePKCE {
		authURL = oauth2Config.AuthCodeURL(state,
			oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
	} else {
		authURL = oauth2Config.AuthCodeURL(state)
	}

	logger.Debug("Authorization URL generated", "redirectURI", redirectURI, "authURL", authURL)

	// Create HTTP server for callback
	var tokenResponse *TokenResponse
	var serverError error
	var wg sync.WaitGroup
	wg.Add(1)

	// Create HTTP router
	mux := http.NewServeMux()

	// Handle authorization callback
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		defer wg.Done()

		logger.Debug("Received authorization callback", "query", r.URL.RawQuery)

		// Check for errors
		if errorParam := r.URL.Query().Get("error"); errorParam != "" {
			errorDesc := r.URL.Query().Get("error_description")
			serverError = fmt.Errorf("authorization error: %s - %s", errorParam, errorDesc)
			http.Error(w, fmt.Sprintf("Authorization failed: %s", errorDesc), http.StatusBadRequest)
			return
		}

		// Verify state parameter
		receivedState := r.URL.Query().Get("state")
		if receivedState != state {
			serverError = fmt.Errorf("invalid state parameter")
			http.Error(w, "Invalid state parameter", http.StatusBadRequest)
			return
		}

		// Get authorization code
		code := r.URL.Query().Get("code")
		if code == "" {
			serverError = fmt.Errorf("missing authorization code")
			http.Error(w, "Missing authorization code", http.StatusBadRequest)
			return
		}

		logger.Debug("Authorization code received", "code", code[:10]+"...")

		// Exchange code for tokens
		tokenResponse, serverError = exchangeCodeForTokens(ctx, oauth2Config, code, codeVerifier, tokenParams.usePKCE, logger)
		if serverError != nil {
			http.Error(w, fmt.Sprintf("Token exchange failed: %v", serverError), http.StatusInternalServerError)
			return
		}

		httpCli, cliErr := httpclient.New(&oidcParams.httpClientConfig)
		if cliErr != nil {
			serverError = fmt.Errorf("failed to create HTTP client: %w", cliErr)
			http.Error(w, serverError.Error(), http.StatusInternalServerError)
			return
		}
		if oidcParams.userInfo {
			res := fetchUserInfoJSON(ctx, provider, httpCli, tokenResponse, logger)
			tokenResponse.userInfoFetched = true
			tokenResponse.userInfoCachedJSON = res.JSON
			tokenResponse.userInfoCachedWarn = res.Warning
		}
		view := buildSuccessPageView(tokenResponse)
		displaySuccessPage(w, &view)
	})

	// Handle root path with instructions
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		html := `<!DOCTYPE html>
<html>
<head>
    <title>OAuth2 Authorization</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        .container { text-align: center; }
        .auth-link { display: inline-block; padding: 10px 20px; background: #007cba; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
        .auth-link:hover { background: #005a87; }
    </style>
</head>
<body>
    <div class="container">
        <h1>OAuth2 Authorization</h1>
        <p>Click the link below to authorize the application:</p>
        <a href="` + authURL + `" class="auth-link">Authorize Application</a>
        <p><small>Or copy this URL to your browser:<br>` + authURL + `</small></p>
    </div>
</body>
</html>`

		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(html))
	})

	// Start HTTP server
	httpServer := httpsrv.New("oauth-callback", &tokenParams.httpSrvConfig, mux)

	// Start server in goroutine
	serverCtx, serverCancel := context.WithCancel(ctx)
	defer serverCancel()

	go func() {
		if err := httpServer.Start(serverCtx); err != nil {
			logger.Error("HTTP server error", "error", err)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Open browser
	//fmt.Printf("Opening browser to: %s\n", authURL)
	_, _ = fmt.Fprintf(os.Stderr, "If browser doesn't open automatically, visit: http://%s:%d\n",
		tokenParams.httpSrvConfig.BindAddr, tokenParams.httpSrvConfig.BindPort)

	if err := openBrowser(authURL, tokenParams.browser); err != nil {
		logger.Debug("Failed to open browser automatically", "error", err)
	}

	// Wait for callback or timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		if serverError != nil {
			return nil, serverError
		}
		return tokenResponse, nil
	case <-time.After(5 * time.Minute):
		return nil, fmt.Errorf("authorization timeout after 5 minutes")
	}
}

// exchangeCodeForTokens exchanges authorization code for access and ID tokens
func exchangeCodeForTokens(ctx context.Context, oauth2Config oauth2.Config, code, codeVerifier string, usePKCE bool, logger *slog.Logger) (*TokenResponse, error) {
	// Prepare token exchange request
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", oauth2Config.RedirectURL)
	data.Set("client_id", oauth2Config.ClientID)
	if oauth2Config.ClientSecret != "" {
		data.Set("client_secret", oauth2Config.ClientSecret)
	}
	if usePKCE && codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
		logger.Debug("Including PKCE code verifier in token exchange")
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", oauth2Config.Endpoint.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	logger.Debug("Exchanging authorization code for tokens", "tokenURL", oauth2Config.Endpoint.TokenURL)

	// Get HTTP client from context (with custom CA settings if any)
	httpClient, err := httpclient.New(&oidcParams.httpClientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Perform request
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform token request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse JSON response
	var tokenResponse TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	logger.Debug("Token exchange successful", "hasAccessToken", tokenResponse.AccessToken != "", "hasIDToken", tokenResponse.IDToken != "")

	return &tokenResponse, nil
}

// successPageView drives the OAuth callback HTML success page.
type successPageView struct {
	MetadataJSON      string
	IDTokenJSON       string
	AccessTokenJSON   string
	RefreshTokenJSON  string
	UserInfoRequested bool
	UserInfoJSON      string
	UserInfoWarning   string
}

func combineJWTPartsJSON(token string) string {
	headerStr, payloadStr, err := decodeJWT(token)
	if err != nil {
		fallback := map[string]string{
			"decode_error": err.Error(),
			"jwt":          token,
		}
		b, _ := json.MarshalIndent(fallback, "", "  ")
		return string(b)
	}
	var headerObj, payloadObj interface{}
	if err := json.Unmarshal([]byte(headerStr), &headerObj); err != nil {
		b, _ := json.MarshalIndent(map[string]string{"decode_error": err.Error(), "jwt": token}, "", "  ")
		return string(b)
	}
	if err := json.Unmarshal([]byte(payloadStr), &payloadObj); err != nil {
		b, _ := json.MarshalIndent(map[string]string{"decode_error": err.Error(), "jwt": token}, "", "  ")
		return string(b)
	}
	combined := map[string]interface{}{
		"header":  headerObj,
		"payload": payloadObj,
	}
	b, err := json.MarshalIndent(combined, "", "  ")
	if err != nil {
		b, _ := json.MarshalIndent(map[string]string{"decode_error": err.Error(), "jwt": token}, "", "  ")
		return string(b)
	}
	return string(b)
}

func formatAccessTokenForSuccessPage(token string) string {
	if isJWT(token) {
		return combineJWTPartsJSON(token)
	}
	type opaqueView struct {
		Format   string `json:"format"`
		Encoding string `json:"encoding"`
		Value    string `json:"value"`
	}
	b, err := json.MarshalIndent(opaqueView{
		Format:   "opaque",
		Encoding: "base64",
		Value:    base64.StdEncoding.EncodeToString([]byte(token)),
	}, "", "  ")
	if err != nil {
		return `{"error":"failed to encode opaque access token"}`
	}
	return string(b)
}

func buildSuccessPageView(token *TokenResponse) successPageView {
	v := successPageView{}
	meta := map[string]interface{}{}
	if token.TokenType != "" {
		meta["token_type"] = token.TokenType
	}
	if token.ExpiresIn > 0 {
		meta["expires_in"] = token.ExpiresIn
		meta["expires_in_human"] = (time.Duration(token.ExpiresIn) * time.Second).String()
	}
	if token.Scope != "" {
		meta["scope"] = token.Scope
	}
	if len(meta) > 0 {
		b, _ := json.MarshalIndent(meta, "", "  ")
		v.MetadataJSON = string(b)
	}
	if token.IDToken != "" {
		v.IDTokenJSON = combineJWTPartsJSON(token.IDToken)
	}
	if token.AccessToken != "" {
		v.AccessTokenJSON = formatAccessTokenForSuccessPage(token.AccessToken)
	}
	if token.RefreshToken != "" {
		wrapped := map[string]string{"refresh_token": token.RefreshToken}
		b, _ := json.MarshalIndent(wrapped, "", "  ")
		v.RefreshTokenJSON = string(b)
	}
	if oidcParams.userInfo {
		v.UserInfoRequested = true
		v.UserInfoJSON = token.userInfoCachedJSON
		v.UserInfoWarning = token.userInfoCachedWarn
	}
	return v
}

// displaySuccessPage shows a success page with token information as JSON.
func displaySuccessPage(w http.ResponseWriter, view *successPageView) {
	const tmplStr = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Authorization successful</title>
    <style>
        :root { color-scheme: light dark; }
        body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; max-width: 52rem; margin: 2rem auto; padding: 0 1.25rem; line-height: 1.45; }
        h1 { font-size: 1.5rem; margin-bottom: 0.25rem; }
        .lead { color: #555; margin-top: 0; }
        section { margin: 1.5rem 0; }
        h2 { font-size: 1.05rem; margin: 0 0 0.5rem; font-weight: 600; }
        .row { display: flex; align-items: flex-start; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 0.35rem; }
        pre.json {
            flex: 1 1 100%;
            margin: 0;
            padding: 0.75rem 1rem;
            overflow-x: auto;
            font-size: 0.8rem;
            border-radius: 6px;
            background: #f0f2f5;
            border: 1px solid #d8dde3;
        }
        @media (prefers-color-scheme: dark) {
            pre.json { background: #1e222a; border-color: #3a4250; }
            .lead { color: #aaa; }
        }
        button.copy {
            font: inherit;
            font-size: 0.8rem;
            padding: 0.35rem 0.75rem;
            border-radius: 6px;
            border: 1px solid #007cba;
            background: #007cba;
            color: #fff;
            cursor: pointer;
        }
        button.copy:hover { filter: brightness(1.08); }
        button.copy:active { filter: brightness(0.92); }
        .warn {
            padding: 0.65rem 0.85rem;
            border-radius: 6px;
            background: #fff8e6;
            border: 1px solid #e6c200;
            color: #5c4a00;
            font-size: 0.9rem;
        }
        @media (prefers-color-scheme: dark) {
            .warn { background: #3d3500; border-color: #8a7500; color: #f5e9a8; }
        }
        footer { margin-top: 2rem; font-style: italic; color: #666; font-size: 0.9rem; }
    </style>
</head>
<body>
    <h1>Authorization successful</h1>
    <p class="lead">Tokens were retrieved. Details below as JSON. You can close this window and return to the terminal.</p>

    {{if .MetadataJSON}}
    <section>
        <h2>Token response metadata</h2>
        <div class="row"><button type="button" class="copy" data-target="pre-meta">Copy</button></div>
        <pre class="json" id="pre-meta">{{.MetadataJSON}}</pre>
    </section>
    {{end}}

    {{if .IDTokenJSON}}
    <section>
        <h2>ID token (JWT as JSON)</h2>
        <div class="row"><button type="button" class="copy" data-target="pre-id">Copy</button></div>
        <pre class="json" id="pre-id">{{.IDTokenJSON}}</pre>
    </section>
    {{end}}

    {{if .AccessTokenJSON}}
    <section>
        <h2>Access token</h2>
        <div class="row"><button type="button" class="copy" data-target="pre-access">Copy</button></div>
        <pre class="json" id="pre-access">{{.AccessTokenJSON}}</pre>
    </section>
    {{end}}

    {{if .RefreshTokenJSON}}
    <section>
        <h2>Refresh token</h2>
        <div class="row"><button type="button" class="copy" data-target="pre-refresh">Copy</button></div>
        <pre class="json" id="pre-refresh">{{.RefreshTokenJSON}}</pre>
    </section>
    {{end}}

    {{if .UserInfoRequested}}
    <section>
        <h2>UserInfo</h2>
        {{if .UserInfoWarning}}
        <p class="warn"><strong>Warning:</strong> {{.UserInfoWarning}}</p>
        {{end}}
        {{if .UserInfoJSON}}
        <div class="row"><button type="button" class="copy" data-target="pre-userinfo">Copy</button></div>
        <pre class="json" id="pre-userinfo">{{.UserInfoJSON}}</pre>
        {{end}}
    </section>
    {{end}}

    <footer>You can close this browser window and return to the command line.</footer>

    <script>
        function copyText(text, btn) {
            function done() {
                var t = btn.textContent;
                btn.textContent = 'Copied';
                setTimeout(function () { btn.textContent = t; }, 1200);
            }
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(done).catch(function () { fallback(); });
            } else { fallback(); }
            function fallback() {
                var ta = document.createElement('textarea');
                ta.value = text;
                ta.style.cssText = 'position:fixed;left:-9999px;top:0';
                document.body.appendChild(ta);
                ta.select();
                try { if (document.execCommand('copy')) done(); } catch (e) {}
                document.body.removeChild(ta);
            }
        }
        document.querySelectorAll('button.copy').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var id = btn.getAttribute('data-target');
                var el = id && document.getElementById(id);
                if (el) copyText(el.textContent, btn);
            });
        });
    </script>
</body>
</html>`

	tmpl, err := template.New("success").Parse(tmplStr)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = tmpl.Execute(w, view)
}

// generateRandomString generates a cryptographically secure random string
func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes)[:length], nil
}
