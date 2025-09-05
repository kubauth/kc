package cmd

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"getok/internal/httpclient"
	"getok/internal/httpsrv"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

var uiParams struct {
	httpSrvConfig httpsrv.Config
	usePKCE       bool
}

func init() {
	initOidcParams(uiCmd)
	uiCmd.PersistentFlags().BoolVar(&uiParams.httpSrvConfig.DumpExchanges, "dumpServerExchanges", false, "Dump http server req/resp")
	uiCmd.PersistentFlags().IntVarP(&uiParams.httpSrvConfig.BindPort, "bindPort", "p", 9921, "Local server Bind port")
	uiCmd.PersistentFlags().BoolVar(&uiParams.usePKCE, "pkce", false, "Use PKCE (Proof Key for Code Exchange) for enhanced security")
}

var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "UI: Get token using authorisation code flow",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {

		logger, err := setupOidc(cmd)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		uiParams.httpSrvConfig.BindAddr = "127.0.0.1"
		uiParams.httpSrvConfig.Tls = false

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

		// Verify ID token if present
		if tokenResponse.IDToken != "" {
			err = verifyIDToken(ctx, provider, tokenResponse.IDToken, oidcParams.clientId)
			if err != nil {
				logger.Debug("ID token verification failed", "error", err)
				_, _ = fmt.Fprintf(os.Stderr, "Warning: ID token verification failed: %v\n", err)
			} else {
				logger.Debug("ID token verified successfully")
			}
		}

		// Output tokens based on requested format
		outputTokens(tokenResponse)
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
	if uiParams.usePKCE {
		codeVerifier, err = generateRandomString(43)
		if err != nil {
			return nil, fmt.Errorf("failed to generate code verifier: %w", err)
		}
		codeChallenge = base64.RawURLEncoding.EncodeToString([]byte(codeVerifier))
		logger.Debug("PKCE enabled", "codeChallenge", codeChallenge[:10]+"...")
	} else {
		logger.Debug("PKCE disabled")
	}

	// Build redirect URI
	redirectURI := fmt.Sprintf("http://%s:%d/callback", uiParams.httpSrvConfig.BindAddr, uiParams.httpSrvConfig.BindPort)

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
	if uiParams.usePKCE {
		authURL = oauth2Config.AuthCodeURL(state,
			oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
	} else {
		authURL = oauth2Config.AuthCodeURL(state)
	}

	logger.Info("Authorization URL generated", "redirectURI", redirectURI, "authURL", authURL)

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
		tokenResponse, serverError = exchangeCodeForTokens(ctx, oauth2Config, code, codeVerifier, uiParams.usePKCE, logger)
		if serverError != nil {
			http.Error(w, fmt.Sprintf("Token exchange failed: %v", serverError), http.StatusInternalServerError)
			return
		}

		// Display success page with tokens
		displaySuccessPage(w, tokenResponse)
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
	httpServer := httpsrv.New("oauth-callback", &uiParams.httpSrvConfig, mux)

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
	fmt.Printf("Opening browser to: %s\n", authURL)
	fmt.Printf("If browser doesn't open automatically, visit: http://%s:%d\n",
		uiParams.httpSrvConfig.BindAddr, uiParams.httpSrvConfig.BindPort)

	if err := openBrowser(authURL); err != nil {
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

// displaySuccessPage shows a success page with token information
func displaySuccessPage(w http.ResponseWriter, tokenResponse *TokenResponse) {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>Authorization Successful</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .container { text-align: center; }
        .success { color: #4CAF50; }
        .token-info { background: #f5f5f5; padding: 20px; margin: 20px 0; text-align: left; border-radius: 5px; }
        .token-field { margin: 10px 0; word-break: break-all; }
        .token-label { font-weight: bold; color: #333; }
        .token-value { font-family: monospace; background: #e8e8e8; padding: 5px; border-radius: 3px; }
        .close-message { margin-top: 30px; font-style: italic; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="success">✅ Authorization Successful!</h1>
        <p>Tokens have been retrieved successfully.</p>
        
        <div class="token-info">
            <h3>Token Information:</h3>`

	if tokenResponse.AccessToken != "" {
		html += fmt.Sprintf(`
            <div class="token-field">
                <div class="token-label">Access Token:</div>
                <div class="token-value">%s</div>
            </div>`, tokenResponse.AccessToken)
	}

	if tokenResponse.IDToken != "" {
		html += fmt.Sprintf(`
            <div class="token-field">
                <div class="token-label">ID Token:</div>
                <div class="token-value">%s</div>
            </div>`, tokenResponse.IDToken)
	}

	if tokenResponse.RefreshToken != "" {
		html += fmt.Sprintf(`
            <div class="token-field">
                <div class="token-label">Refresh Token:</div>
                <div class="token-value">%s</div>
            </div>`, tokenResponse.RefreshToken)
	}

	if tokenResponse.ExpiresIn > 0 {
		html += fmt.Sprintf(`
            <div class="token-field">
                <div class="token-label">Expires In:</div>
                <div class="token-value">%d seconds (%s)</div>
            </div>`, tokenResponse.ExpiresIn, time.Duration(tokenResponse.ExpiresIn)*time.Second)
	}

	html += `
        </div>
        
        <p class="close-message">You can close this browser window and return to the command line.</p>
    </div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// outputTokens outputs tokens in the requested format to command line
func outputTokens(tokenResponse *TokenResponse) {
	if oidcParams.onlyIDToken {
		if tokenResponse.IDToken == "" {
			_, _ = fmt.Fprintf(os.Stderr, "No ID token\n")
		} else {
			fmt.Println(tokenResponse.IDToken)
		}
	} else if oidcParams.onlyAccessToken {
		if tokenResponse.AccessToken == "" {
			_, _ = fmt.Fprintf(os.Stderr, "No access token\n")
		} else {
			fmt.Println(tokenResponse.AccessToken)
		}
	} else {
		if tokenResponse.AccessToken != "" {
			fmt.Printf("Access token: %s\n", tokenResponse.AccessToken)
		} else {
			fmt.Printf("Access token: null\n")
		}
		if tokenResponse.RefreshToken != "" {
			fmt.Printf("Refresh token: %s\n", tokenResponse.RefreshToken)
		} else {
			fmt.Printf("Refresh token: null\n")
		}
		if tokenResponse.IDToken != "" {
			fmt.Printf("ID token: %s\n", tokenResponse.IDToken)
		} else {
			fmt.Printf("ID token: null\n")
		}
		fmt.Printf("Expire in: %s\n", time.Duration(tokenResponse.ExpiresIn)*time.Second)
	}
}

// generateRandomString generates a cryptographically secure random string
func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes)[:length], nil
}

// openBrowser attempts to open the default browser with the given URL
func openBrowser(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start", url}
	case "darwin":
		cmd = "open"
		args = []string{url}
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
		args = []string{url}
	}

	return exec.Command(cmd, args...).Start()
}
