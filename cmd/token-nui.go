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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"kc/internal/httpclient"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/go-logr/logr"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
)

var tokenNuiParams struct {
	login    string
	password string
}

func init() {
	initOidcParams(tokenNuiCmd)
	tokenNuiCmd.PersistentFlags().StringVarP(&tokenNuiParams.login, "login", "u", "", "User login (Env:KC_USER_LOGIN)")
	tokenNuiCmd.PersistentFlags().StringVarP(&tokenNuiParams.password, "password", "p", "", "User password (Env:KC_USER_PASSWORD)")
}

var tokenNuiCmd = &cobra.Command{
	Use:   "token-nui",
	Short: "No UI: Get token using Resource Owner Password Credentials (ROPC)",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {

		logger, err := setupOidc(cmd)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		logger.Debug("Start No UI processing", "issuer", oidcParams.httpClientConfig.BaseURL)

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
		login := tokenNuiParams.login
		password := tokenNuiParams.password
		for login == "" || password == "" {
			login, password = inputCredentials(login, password)
		}

		// Perform password credentials flow with direct HTTP request to get both access and ID tokens
		tokenResponse, err := passwordCredentialsFlow(ctx, httpClient, provider.Endpoint().TokenURL, oidcParams.clientId, oidcParams.clientSecret, login, password, oidcParams.scopes)
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
		if tokenResponse.AccessToken != "" {
			if isJWT(tokenResponse.AccessToken) {
				// Verify a JWT access token
				err = verifyJWTAccessToken(ctx, provider, tokenResponse.AccessToken, oidcParams.clientId)
				if err != nil {
					logger.Debug("JWT access token verification failed", "error", err)
					_, _ = fmt.Fprintf(os.Stderr, "Warning: JWT access token verification failed: %v\n", err)
				} else {
					logger.Debug("JWT access token verified successfully")
				}
			} else {
				// Verify an opaque access token using introspection
				err = verifyOpaqueAccessToken(ctx, httpClient, provider, tokenResponse.AccessToken, oidcParams.clientId, oidcParams.clientSecret)
				if err != nil {
					logger.Debug("Opaque access token verification failed", "error", err)
					_, _ = fmt.Fprintf(os.Stderr, "Warning: Opaque access token verification failed: %v\n", err)
				} else {
					logger.Debug("Opaque access token verified successfully")
				}
			}
		}

		// Output tokens using shared function
		outputTokens(tokenResponse, logger)

	},
}

func inputCredentials(login, password string) (string, string) {
	if login == "" {
		login = os.Getenv("KC_USER_LOGIN")
		if login == "" {
			_, err := fmt.Fprint(os.Stderr, "Login:")
			if err != nil {
				panic(err)
			}
			r := bufio.NewReader(os.Stdin)
			login, err = r.ReadString('\n')
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "\nUnable to access stdin to input login. Try login with '--login' and '--password' options.\n\n")
				os.Exit(18)
			}
			login = strings.TrimSpace(login)
		}
	}
	if password == "" {
		password = os.Getenv("KC_USER_PASSWORD")
		if password == "" {
			password = inputPassword("Password:")
		}
	}
	return login, password
}

func inputPassword(prompt string) string {
	_, err := fmt.Fprint(os.Stderr, prompt)
	if err != nil {
		panic(err)
	}
	bytePassword, err2 := terminal.ReadPassword(int(syscall.Stdin)) // cast to int is redundant, except for windows target
	if err2 != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Unable to access stdin to input password. Try login with '--login' and '--password' options.\n\n")
		os.Exit(18)
	}
	_, _ = fmt.Fprintf(os.Stderr, "\n")
	return strings.TrimSpace(string(bytePassword))
}

// passwordCredentialsFlow performs the OAuth2 Resource Owner Password Credentials flow
// with a direct HTTP request to retrieve both access_token and id_token
func passwordCredentialsFlow(ctx context.Context, httpClient *http.Client, tokenURL, clientID, clientSecret, username, password string, scopes []string) (*TokenResponse, error) {
	logger := logr.FromContextAsSlogLogger(ctx)
	// Prepare form data
	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("username", username)
	data.Set("password", password)
	data.Set("client_id", clientID)
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}
	if len(scopes) > 0 {
		data.Set("scope", strings.Join(scopes, " "))
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	logger.Debug("Making password credentials request", "tokenURL", tokenURL, "clientID", clientID, "scopes", scopes)

	// Perform request
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform token request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
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

	logger.Debug("Token response received", "hasAccessToken", tokenResponse.AccessToken != "", "hasIDToken", tokenResponse.IDToken != "")

	return &tokenResponse, nil
}

// verifyJWTAccessToken verifies a JWT access token
func verifyJWTAccessToken(ctx context.Context, provider *oidc.Provider, accessToken, clientID string) error {
	logger := logr.FromContextAsSlogLogger(ctx)

	// For JWT access tokens, we can decode and validate the structure
	// Note: Access tokens typically don't have the same verification requirements as ID tokens
	// They might not be intended for the client (audience check might fail)
	// So we'll do basic JWT validation and check expiration

	// First, try to decode the JWT to validate its structure and check expiration
	header, payload, err := decodeJWT(accessToken)
	if err != nil {
		return fmt.Errorf("failed to decode JWT access token: %w", err)
	}

	// Parse the payload to check expiration
	var claims map[string]interface{}
	if err := json.Unmarshal([]byte(payload), &claims); err != nil {
		return fmt.Errorf("failed to parse JWT access token payload: %w", err)
	}

	// Check expiration if present
	if exp, ok := claims["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		if time.Now().After(expTime) {
			return fmt.Errorf("JWT access token has expired at %v", expTime)
		}
		logger.Debug("JWT access token expiration checked", "expires", expTime)
	}

	// Check not before if present
	if nbf, ok := claims["nbf"].(float64); ok {
		nbfTime := time.Unix(int64(nbf), 0)
		if time.Now().Before(nbfTime) {
			return fmt.Errorf("JWT access token not valid before %v", nbfTime)
		}
	}

	// Log some basic info about the token
	if sub, ok := claims["sub"].(string); ok {
		logger.Debug("JWT access token validated", "subject", sub)
	}
	if iss, ok := claims["iss"].(string); ok {
		logger.Debug("JWT access token issuer", "issuer", iss)
	}

	// Note: We don't verify the signature here as access tokens might not be intended for this client
	// and the go-oidc verifier is specifically for ID tokens
	logger.Debug("JWT access token structure and timing validated", "header", header[:50]+"...")

	return nil
}

// verifyOpaqueAccessToken verifies an opaque access token using OAuth2 introspection
func verifyOpaqueAccessToken(ctx context.Context, httpClient *http.Client, provider *oidc.Provider, accessToken, clientID, clientSecret string) error {
	logger := logr.FromContextAsSlogLogger(ctx)

	// Debug client configuration
	logger.Debug("Starting opaque token verification",
		"clientID", clientID,
		"clientSecretLength", len(clientSecret),
		"hasClientSecret", clientSecret != "")

	// Try to find the introspection endpoint
	// First, try the standard RFC 7662 introspection endpoint
	introspectionURL := strings.TrimSuffix(provider.Endpoint().TokenURL, "/token") + "/introspect"

	// Alternatively, we could try to get it from the provider's discovery document
	// but for now, we'll use the standard endpoint pattern

	// Prepare introspection request
	data := url.Values{}
	data.Set("token", accessToken)
	data.Set("token_type_hint", "access_token")

	// Add client authentication - handle both confidential and public clients
	if clientSecret != "" {
		// Confidential client: use HTTP Basic authentication
		logger.Debug("Using HTTP Basic auth for introspection (confidential client)")
	} else {
		// Public client: include client_id in the form data
		data.Set("client_id", clientID)
		logger.Debug("Using client_id in form data for introspection (public client)")
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", introspectionURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create introspection request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Set authentication header for confidential clients
	if clientSecret != "" {
		req.SetBasicAuth(clientID, clientSecret)
	}

	logger.Debug("Introspecting opaque access token",
		"introspectionURL", introspectionURL,
		"clientID", clientID,
		"hasClientSecret", clientSecret != "",
		"authMethod", func() string {
			if clientSecret != "" {
				return "HTTP Basic Auth"
			}
			return "client_id in form data"
		}())

	// Debug: Log request details
	logger.Debug("Sending introspection request",
		"method", req.Method,
		"url", req.URL.String(),
		"headers", req.Header,
		"hasBasicAuth", req.Header.Get("Authorization") != "")

	// Perform request
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to perform introspection request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read introspection response: %w", err)
	}

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("introspection request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse introspection response
	var introspectionResponse struct {
		Active    bool   `json:"active"`
		Scope     string `json:"scope,omitempty"`
		ClientID  string `json:"client_id,omitempty"`
		Username  string `json:"username,omitempty"`
		TokenType string `json:"token_type,omitempty"`
		Exp       int64  `json:"exp,omitempty"`
		Iat       int64  `json:"iat,omitempty"`
		Nbf       int64  `json:"nbf,omitempty"`
		Sub       string `json:"sub,omitempty"`
		Aud       string `json:"aud,omitempty"`
		Iss       string `json:"iss,omitempty"`
	}

	if err := json.Unmarshal(body, &introspectionResponse); err != nil {
		return fmt.Errorf("failed to parse introspection response: %w", err)
	}

	// Check if token is active
	if !introspectionResponse.Active {
		return fmt.Errorf("access token is not active")
	}

	// Check expiration if present
	if introspectionResponse.Exp > 0 {
		expTime := time.Unix(introspectionResponse.Exp, 0)
		if time.Now().After(expTime) {
			return fmt.Errorf("access token has expired at %v", expTime)
		}
		logger.Debug("Opaque access token expiration checked", "expires", expTime)
	}

	// Check not before if present
	if introspectionResponse.Nbf > 0 {
		nbfTime := time.Unix(introspectionResponse.Nbf, 0)
		if time.Now().Before(nbfTime) {
			return fmt.Errorf("access token not valid before %v", nbfTime)
		}
	}

	logger.Debug("Opaque access token introspection successful",
		"active", introspectionResponse.Active,
		"scope", introspectionResponse.Scope,
		"subject", introspectionResponse.Sub,
		"client_id", introspectionResponse.ClientID)

	return nil
}
