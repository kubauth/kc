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
	"encoding/json"
	"fmt"
	"io"
	"kc/internal/httpclient"
	"kc/internal/misc"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"
)

// TokenResponse represents the OAuth2/OIDC token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`

	// Set during browser callback when --userInfo; reused by CLI dump to avoid a second request.
	userInfoFetched    bool   `json:"-"`
	userInfoCachedJSON string `json:"-"`
	userInfoCachedWarn string `json:"-"`
}

var oidcParams struct {
	logConfig         misc.LogConfig
	httpClientConfig  httpclient.Config
	scopes            []string
	clientId          string
	clientSecret      string
	onlyIdToken       bool
	onlyAccessToken   bool
	kubeconfig        string
	context           string
	detailIdToken     bool
	detailAccessToken bool
	// Used only by token and token-nui. (Not by client flow command)
	ttl      time.Duration
	renewAt  int // % of the token duration
	userInfo bool
}

func initOidcParams(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&oidcParams.logConfig.Mode, "logMode", "text", "Log mode ('text' or 'json')")
	cmd.PersistentFlags().StringVarP(&oidcParams.logConfig.Level, "logLevel", "l", "INFO", "Log level(DEBUG, INFO, WARN, ERROR)")

	cmd.PersistentFlags().BoolVar(&oidcParams.httpClientConfig.DumpExchanges, "dumpClientExchanges", false, "Dump http client req/resp")
	cmd.PersistentFlags().BoolVar(&oidcParams.httpClientConfig.InsecureSkipVerify, "insecureSkipVerify", false, "Don't validate issuer certificate")
	cmd.PersistentFlags().StringArrayVar(&oidcParams.httpClientConfig.RootCaPaths, "caFile", []string{}, "Root CA path(s) for validation of issuer URL.")
	cmd.PersistentFlags().StringArrayVar(&oidcParams.scopes, "scope", []string{"openid", "profile", "offline_access", "groups"}, "Requested scopes.")
	cmd.PersistentFlags().StringVarP(&oidcParams.httpClientConfig.BaseURL, "issuerURL", "i", "", "issuer URL (Env:KC_ISSUER_URL)")
	cmd.PersistentFlags().StringVar(&oidcParams.kubeconfig, "kubeconfig", "", "kubeconfig file to fetch issuerURL and CA (default env:KUBECONFIG or $HOME/.kube/config)")
	cmd.PersistentFlags().StringVar(&oidcParams.context, "context", "", "Context in kubeconfig file to fetch issuerURL and CA (Override kubeconfig default context")

	cmd.PersistentFlags().StringVarP(&oidcParams.clientId, "clientId", "c", "", "Client ID (Env:KC_CLIENT_ID)")
	cmd.PersistentFlags().StringVarP(&oidcParams.clientSecret, "clientSecret", "s", "", "Client Secret (Env:KC_CLIENT_SECRET)")
	cmd.PersistentFlags().BoolVar(&oidcParams.onlyIdToken, "onlyIdToken", false, "Output only ID token")
	cmd.PersistentFlags().BoolVar(&oidcParams.onlyAccessToken, "onlyAccessToken", false, "Output only Access token")
	cmd.PersistentFlags().BoolVarP(&oidcParams.detailIdToken, "detailIdToken", "d", false, "Print decoded ID token (JWT) to the terminal only; the browser success page always shows token details")
	cmd.PersistentFlags().BoolVarP(&oidcParams.detailAccessToken, "detailAccessToken", "a", false, "Print decoded access token or opaque notice to the terminal only; the browser success page always shows token details")
	cmd.PersistentFlags().BoolVar(&oidcParams.userInfo, "userInfo", false, "Request userinfo endpoint and dump result")

}

func setupOidc(cmd *cobra.Command) (*slog.Logger, error) {
	var err error
	logger, err := misc.NewLogger(&oidcParams.logConfig)
	if err != nil {
		return nil, fmt.Errorf("could not create logger: %w", err)
	}
	adjustStringParam(cmd.PersistentFlags(), "issuerURL", "KC_ISSUER_URL", &oidcParams.httpClientConfig.BaseURL)
	adjustStringParam(cmd.PersistentFlags(), "clientId", "KC_CLIENT_ID", &oidcParams.clientId)
	adjustStringParam(cmd.PersistentFlags(), "clientSecret", "KC_CLIENT_SECRET", &oidcParams.clientSecret)

	// If some parameters are missing, try to fetch from current kubeconfig
	if oidcParams.httpClientConfig.BaseURL == "" || len(oidcParams.httpClientConfig.RootCaPaths) == 0 {
		configInfo, err := getConfigInfo(oidcParams.kubeconfig, oidcParams.context, logger)
		if err != nil {
			return nil, err
		}
		if configInfo != nil {
			logger.Debug("Completing OIDC configuration from kubeconfig")
			if oidcParams.httpClientConfig.BaseURL == "" {
				oidcParams.httpClientConfig.BaseURL = configInfo.issuerURL
			}
			if len(oidcParams.httpClientConfig.RootCaPaths) == 0 {
				oidcParams.httpClientConfig.RootCaDatas = []string{configInfo.caData}
			}
			if !oidcParams.httpClientConfig.InsecureSkipVerify {
				oidcParams.httpClientConfig.InsecureSkipVerify = configInfo.insecureSkipTlsVerify
			}
		}
	}

	if oidcParams.httpClientConfig.BaseURL == "" {
		return logger, fmt.Errorf("issuer URL cannot be empty")
	}
	if oidcParams.clientId == "" {
		return logger, fmt.Errorf("client ID cannot be empty")
	}
	// clientSecret can be null (public client)
	return logger, nil
}

// outputTokens prints tokens according to the configured output mode
func outputTokens(tokenResponse *TokenResponse, logger *slog.Logger) {
	if oidcParams.onlyIdToken {
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
		if tokenResponse.IDToken != "" && oidcParams.detailIdToken {
			err := decodeAndDisplayJWT("IdToken", tokenResponse.IDToken, true)
			if err != nil {
				logger.Warn("Failed to display detailed ID token")
			}
		}
		if tokenResponse.AccessToken != "" && oidcParams.detailAccessToken {
			if isJWT(tokenResponse.AccessToken) {
				err := decodeAndDisplayJWT("AccessToken", tokenResponse.AccessToken, true)
				if err != nil {
					logger.Warn("Failed to display detailed Access token")
				}
			} else {
				fmt.Printf("Server is configured to generate opaque access token\n")
			}
		}
	}
}

// As the server may issue AccessToken as JWT or as opaque form, depends on its configuration, we need a clean test to find the token type.
func isJWT(token string) bool {
	// JWT tokens have exactly 3 parts separated by dots
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	// Each part should be non-empty and contain valid base64url characters
	for _, part := range parts {
		if len(part) == 0 {
			return false
		}
		// Check if the part contains only valid base64url characters
		// Base64url uses: A-Z, a-z, 0-9, -, _
		for _, char := range part {
			if !((char >= 'A' && char <= 'Z') ||
				(char >= 'a' && char <= 'z') ||
				(char >= '0' && char <= '9') ||
				char == '-' || char == '_') {
				return false
			}
		}
	}

	return true
}

// openBrowser attempts to open a browser with the given URL and browser preference
func openBrowser(url, browser string) error {
	var cmd string
	var args []string

	// Handle specific browser requests
	if browser != "" {
		switch browser {
		case "chrome":
			switch runtime.GOOS {
			case "windows":
				cmd = "cmd"
				args = []string{"/c", "start", "chrome", url}
			case "darwin":
				cmd = "open"
				args = []string{"-a", "Google Chrome", url}
			default: // Linux and others
				cmd = "google-chrome"
				args = []string{url}
			}
		case "firefox":
			switch runtime.GOOS {
			case "windows":
				cmd = "cmd"
				args = []string{"/c", "start", "firefox", url}
			case "darwin":
				cmd = "open"
				args = []string{"-a", "Firefox", url}
			default: // Linux and others
				cmd = "firefox"
				args = []string{url}
			}
		case "safari":
			if runtime.GOOS == "darwin" {
				cmd = "open"
				args = []string{"-a", "Safari", url}
			} else {
				return fmt.Errorf("safari is only available on macOS")
			}
		default:
			return fmt.Errorf("unsupported browser: %s (supported: chrome, firefox, safari)", browser)
		}
	} else {
		// Default system browser
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
	}

	return exec.Command(cmd, args...).Start()
}

func ensureOfflineAccessScope(logger *slog.Logger) {
	for _, s := range oidcParams.scopes {
		if s == "offline_access" {
			return
		}
	}
	logger.Info("Adding 'offline_access' scope (required for token renewal)")
	oidcParams.scopes = append(oidcParams.scopes, "offline_access")
}

// refreshTokenFlow uses a refresh token to obtain new access/ID tokens
func refreshTokenFlow(ctx context.Context, tokenURL, clientID, clientSecret, refreshToken string, logger *slog.Logger) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", clientID)
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	logger.Debug("Refreshing token", "tokenURL", tokenURL)

	httpClient, err := httpclient.New(&oidcParams.httpClientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform refresh request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refresh request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResponse TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return nil, fmt.Errorf("failed to parse refresh response: %w", err)
	}

	logger.Debug("Token refresh successful",
		"hasAccessToken", tokenResponse.AccessToken != "",
		"hasIDToken", tokenResponse.IDToken != "",
		"hasNewRefreshToken", tokenResponse.RefreshToken != "",
		"expiresIn", tokenResponse.ExpiresIn)

	return &tokenResponse, nil
}

// userInfoJSONResult is the outcome of a userinfo request for CLI or HTML output.
type userInfoJSONResult struct {
	JSON    string // pretty-printed JSON, empty on failure
	Warning string // set when userinfo was requested but could not be retrieved
}

// fetchUserInfoJSON calls the OIDC userinfo endpoint and returns pretty JSON, or a warning reason.
func fetchUserInfoJSON(ctx context.Context, provider *oidc.Provider, httpClient *http.Client, tokenResponse *TokenResponse, logger *slog.Logger) userInfoJSONResult {
	userInfoURL := provider.UserInfoEndpoint()
	if userInfoURL == "" {
		return userInfoJSONResult{Warning: "provider does not expose a userinfo endpoint"}
	}

	if tokenResponse.AccessToken == "" {
		return userInfoJSONResult{Warning: "cannot fetch userinfo without an access token"}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
	if err != nil {
		return userInfoJSONResult{Warning: fmt.Sprintf("failed to build userinfo request: %v", err)}
	}
	req.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)
	req.Header.Set("Accept", "application/json")

	logger.Debug("Requesting userinfo", "userInfoURL", userInfoURL)

	resp, err := httpClient.Do(req)
	if err != nil {
		return userInfoJSONResult{Warning: fmt.Sprintf("userinfo request failed: %v", err)}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return userInfoJSONResult{Warning: fmt.Sprintf("failed to read userinfo response: %v", err)}
	}

	if resp.StatusCode != http.StatusOK {
		return userInfoJSONResult{Warning: fmt.Sprintf("userinfo request returned status %d: %s", resp.StatusCode, string(body))}
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(body, &claims); err != nil {
		// Not JSON (e.g. signed JWT response): wrap raw body
		wrapped := map[string]string{"raw": string(body)}
		pretty, err := json.MarshalIndent(wrapped, "", "  ")
		if err != nil {
			return userInfoJSONResult{JSON: string(body)}
		}
		return userInfoJSONResult{JSON: string(pretty)}
	}
	pretty, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		return userInfoJSONResult{JSON: string(body)}
	}
	return userInfoJSONResult{JSON: string(pretty)}
}

// dumpUserInfo requests the OIDC userinfo endpoint using the access token and
// prints the response as pretty JSON. If the provider does not advertise a
// userinfo endpoint, it emits a warning instead.
func dumpUserInfo(ctx context.Context, provider *oidc.Provider, httpClient *http.Client, tokenResponse *TokenResponse, logger *slog.Logger) {
	if tokenResponse.userInfoFetched {
		if tokenResponse.userInfoCachedWarn != "" {
			_, _ = fmt.Fprintf(os.Stderr, "Warning: %s\n", tokenResponse.userInfoCachedWarn)
		}
		if tokenResponse.userInfoCachedJSON != "" {
			fmt.Printf("UserInfo:\n%s\n", tokenResponse.userInfoCachedJSON)
		}
		return
	}

	res := fetchUserInfoJSON(ctx, provider, httpClient, tokenResponse, logger)
	if res.Warning != "" {
		_, _ = fmt.Fprintf(os.Stderr, "Warning: %s\n", res.Warning)
	}
	if res.JSON != "" {
		fmt.Printf("UserInfo:\n%s\n", res.JSON)
	}
}

// renewalLoop continuously renews the token until the TTL deadline is reached.
// Exits with error if the token expires without a successful renewal.
func renewalLoop(ctx context.Context, provider *oidc.Provider, initialToken *TokenResponse, httpClient *http.Client, logger *slog.Logger) {
	deadline := time.Now().Add(oidcParams.ttl)
	tokenURL := provider.Endpoint().TokenURL
	refreshToken := initialToken.RefreshToken
	expiresIn := initialToken.ExpiresIn
	renewalCount := 0

	_, _ = fmt.Fprintf(os.Stderr, "\nRenewal loop started (ttl: %s, renewAt: %d%%, deadline: %s)\n",
		oidcParams.ttl, oidcParams.renewAt, deadline.Format(time.RFC3339))

	if refreshToken == "" {
		_, _ = fmt.Fprintf(os.Stderr, "Error: no refresh token received (is 'offline_access' scope granted by the server?)\n")
		os.Exit(1)
	}

	for {
		if expiresIn <= 0 {
			_, _ = fmt.Fprintf(os.Stderr, "Error: token has no expiration info, cannot schedule renewal\n")
			os.Exit(1)
		}

		tokenLifetime := time.Duration(expiresIn) * time.Second
		renewAfter := time.Duration(float64(tokenLifetime) * float64(oidcParams.renewAt) / 100.0)
		tokenExpiresAt := time.Now().Add(tokenLifetime)

		_, _ = fmt.Fprintf(os.Stderr, "Token lifetime: %s, renewal in: %s (at %s), expires at: %s\n",
			tokenLifetime, renewAfter.Truncate(time.Second),
			time.Now().Add(renewAfter).Format(time.TimeOnly),
			tokenExpiresAt.Format(time.TimeOnly))

		if time.Now().Add(renewAfter).After(deadline) {
			remaining := time.Until(deadline)
			if remaining > 0 {
				_, _ = fmt.Fprintf(os.Stderr, "Next renewal would be past deadline, waiting %s for TTL to expire...\n", remaining.Truncate(time.Second))
				time.Sleep(remaining)
			}
			_, _ = fmt.Fprintf(os.Stderr, "TTL reached, exiting renewal loop\n")
			return
		}

		_, _ = fmt.Fprintf(os.Stderr, "Waiting %s before next renewal...\n", renewAfter.Truncate(time.Second))
		time.Sleep(renewAfter)

		renewalCount++
		_, _ = fmt.Fprintf(os.Stderr, "\n--- Renewal #%d at %s ---\n", renewalCount, time.Now().Format(time.RFC3339))

		newToken, err := refreshTokenFlow(ctx, tokenURL, oidcParams.clientId, oidcParams.clientSecret, refreshToken, logger)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Renewal failed: %v\n", err)
			if time.Now().After(tokenExpiresAt) {
				_, _ = fmt.Fprintf(os.Stderr, "Error: token expired without successful renewal\n")
				os.Exit(1)
			}
			_, _ = fmt.Fprintf(os.Stderr, "Token still valid until %s, will retry\n", tokenExpiresAt.Format(time.TimeOnly))
			expiresIn = int(time.Until(tokenExpiresAt).Seconds())
			continue
		}

		_, _ = fmt.Fprintf(os.Stderr, "Renewal #%d successful\n", renewalCount)

		if newToken.RefreshToken != "" {
			refreshToken = newToken.RefreshToken
		}
		expiresIn = newToken.ExpiresIn

		verifyTokens(ctx, provider, newToken, httpClient, logger)
		outputTokens(newToken, logger)
		if oidcParams.userInfo {
			dumpUserInfo(ctx, provider, httpClient, newToken, logger)
		}
	}
}
