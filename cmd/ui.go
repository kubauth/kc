package cmd

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"getok/internal/httpclient"
	"getok/internal/httpsrv"
	"html/template"
	"io"
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

var uiParams struct {
	httpSrvConfig httpsrv.Config
	usePKCE       bool
	browser       string
}

func init() {
	initOidcParams(uiCmd)
	uiCmd.PersistentFlags().BoolVar(&uiParams.httpSrvConfig.DumpExchanges, "dumpServerExchanges", false, "Dump http server req/resp")
	uiCmd.PersistentFlags().IntVarP(&uiParams.httpSrvConfig.BindPort, "bindPort", "p", 9921, "Local server Bind port")
	uiCmd.PersistentFlags().BoolVar(&uiParams.usePKCE, "pkce", false, "Use PKCE (Proof Key for Code Exchange) for enhanced security")
	uiCmd.PersistentFlags().StringVar(&uiParams.browser, "browser", "", "Browser to use (default: system default, options: chrome, firefox, safari)")
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
	//fmt.Printf("Opening browser to: %s\n", authURL)
	_, _ = fmt.Fprintf(os.Stderr, "If browser doesn't open automatically, visit: http://%s:%d\n",
		uiParams.httpSrvConfig.BindAddr, uiParams.httpSrvConfig.BindPort)

	if err := openBrowser(authURL, uiParams.browser); err != nil {
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
	tmplStr := `<!DOCTYPE html>
<html>
<head>
    <title>Authorization Successful</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .container { text-align: center; }
        .success { color: #4CAF50; }
        .token-info { background: #f5f5f5; padding: 20px; margin: 20px 0; text-align: left; border-radius: 5px; }
        .token-field { margin: 10px 0; word-break: break-all; position: relative; }
        .token-label { font-weight: bold; color: #333; }
        .token-value { 
            font-family: monospace; 
            background: #e8e8e8; 
            padding: 10px; 
            border-radius: 3px; 
            position: relative;
            padding-right: 65px;
        }
        .copy-icon {
            position: absolute;
            top: 8px;
            right: 8px;
            cursor: pointer;
            background: #007cba;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 6px 10px;
            font-size: 10px;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
            font-weight: 600;
            letter-spacing: 0.5px;
            transition: all 0.2s ease;
            min-width: 50px;
            height: 26px;
            text-align: center;
            line-height: 14px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.2);
            z-index: 10;
        }
        .copy-icon:hover {
            background: #005a87;
            transform: translateY(-1px);
            box-shadow: 0 2px 6px rgba(0,0,0,0.3);
        }
        .copy-icon:active {
            background: #004466;
            transform: translateY(0);
            box-shadow: 0 1px 2px rgba(0,0,0,0.2);
        }
        .copy-feedback {
            position: absolute;
            top: 8px;
            right: 8px;
            background: #4CAF50;
            color: white;
            padding: 6px 10px;
            border-radius: 4px;
            font-size: 10px;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
            font-weight: 600;
            letter-spacing: 0.5px;
            opacity: 0;
            transition: opacity 0.3s ease;
            min-width: 50px;
            height: 26px;
            text-align: center;
            line-height: 14px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.3);
            z-index: 5;
            pointer-events: none;
        }
        .copy-feedback.show {
            opacity: 1;
        }
        .close-message { margin-top: 30px; font-style: italic; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="success">Authorization Successful!</h1>
        <p>Tokens have been retrieved successfully.</p>
        
        <div class="token-info">
            <h3>Token Information:</h3>
            {{if .AccessToken}}
            <div class="token-field">
                <div class="token-label">Access Token:</div>
                <div class="token-value">{{.AccessToken}}
                    <button class="copy-icon" data-token-type="access" title="Copy to clipboard">COPY</button>
                    <div class="copy-feedback">Copied!</div>
                </div>
            </div>
            {{end}}
            {{if .IDToken}}
            <div class="token-field">
                <div class="token-label">ID Token:</div>
                <div class="token-value">{{.IDToken}}
                    <button class="copy-icon" data-token-type="id" title="Copy to clipboard">COPY</button>
                    <div class="copy-feedback">Copied!</div>
                </div>
            </div>
            {{end}}
            {{if .RefreshToken}}
            <div class="token-field">
                <div class="token-label">Refresh Token:</div>
                <div class="token-value">{{.RefreshToken}}
                    <button class="copy-icon" data-token-type="refresh" title="Copy to clipboard">COPY</button>
                    <div class="copy-feedback">Copied!</div>
                </div>
            </div>
            {{end}}
            {{if gt .ExpiresIn 0}}
            <div class="token-field">
                <div class="token-label">Expires In:</div>
                <div class="token-value">{{.ExpiresIn}} seconds ({{.ExpiresInDuration}})</div>
            </div>
            {{end}}
        </div>
        
        <p class="close-message">You can close this browser window and return to the command line.</p>
    </div>
    
    <script>
        function copyTokenToClipboard(buttonElement) {
            // Find the token text by looking at the parent token-value div
            const tokenValueDiv = buttonElement.parentNode;
            const tokenText = tokenValueDiv.childNodes[0].textContent.trim();
            
            // Try modern clipboard API first
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(tokenText).then(function() {
                    showFeedback(buttonElement);
                }).catch(function(err) {
                    fallbackCopy(tokenText, buttonElement);
                });
            } else {
                fallbackCopy(tokenText, buttonElement);
            }
        }
        
        function fallbackCopy(text, buttonElement) {
            const textArea = document.createElement('textarea');
            textArea.value = text;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            textArea.style.top = '-999999px';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            
            try {
                const successful = document.execCommand('copy');
                if (successful) {
                    showFeedback(buttonElement);
                }
            } catch (err) {
                // Silent fallback failure
            } finally {
                document.body.removeChild(textArea);
            }
        }
        
        function showFeedback(buttonElement) {
            const feedback = buttonElement.nextElementSibling;
            if (feedback && feedback.classList) {
                feedback.classList.add('show');
                setTimeout(function() {
                    feedback.classList.remove('show');
                }, 2000);
            }
        }
        
        // Use event delegation - attach to document
        document.addEventListener('click', function(event) {
            // Check if the clicked element or its parent is a copy button
            let target = event.target;
            let copyButton = null;
            
            // Look for copy-icon class in the clicked element or its parents
            while (target && target !== document) {
                if (target.classList && target.classList.contains('copy-icon')) {
                    copyButton = target;
                    break;
                }
                target = target.parentNode;
            }
            
            if (copyButton) {
                event.preventDefault();
                event.stopPropagation();
                copyTokenToClipboard(copyButton);
            }
        });
        
        // Also add direct event listeners when DOM is ready
        document.addEventListener('DOMContentLoaded', function() {
            const copyButtons = document.querySelectorAll('.copy-icon');
            
            copyButtons.forEach(function(button) {
                button.addEventListener('click', function(event) {
                    event.preventDefault();
                    copyTokenToClipboard(this);
                });
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

	data := struct {
		*TokenResponse
		ExpiresInDuration string
	}{
		TokenResponse:     tokenResponse,
		ExpiresInDuration: time.Duration(tokenResponse.ExpiresIn * int(time.Second)).String(),
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	tmpl.Execute(w, data)
}

// generateRandomString generates a cryptographically secure random string
func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes)[:length], nil
}
