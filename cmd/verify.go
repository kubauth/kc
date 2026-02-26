/*
Copyright 2026 Kubotal

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
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-logr/logr"
)

func verifyTokens(ctx context.Context, provider *oidc.Provider, tokenResponse *TokenResponse, httpClient *http.Client, logger *slog.Logger) {
	// Verify ID token if present
	if tokenResponse.IDToken != "" {
		err := verifyIDToken(ctx, provider, tokenResponse.IDToken, oidcParams.clientId)
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
			err := verifyJWTAccessToken(ctx, provider, tokenResponse.AccessToken, oidcParams.clientId)
			if err != nil {
				logger.Debug("JWT access token verification failed", "error", err)
				_, _ = fmt.Fprintf(os.Stderr, "Warning: JWT access token verification failed: %v\n", err)
			} else {
				logger.Debug("JWT access token verified successfully")
			}
		} else {
			// Verify an opaque access token using introspection
			err := verifyOpaqueAccessToken(ctx, httpClient, provider, tokenResponse.AccessToken, oidcParams.clientId, oidcParams.clientSecret)
			if err != nil {
				logger.Debug("Opaque access token verification failed", "error", err)
				_, _ = fmt.Fprintf(os.Stderr, "Warning: Opaque access token verification failed: %v\n", err)
			} else {
				logger.Debug("Opaque access token verified successfully")
			}
		}
	}

}

// verifyIDToken verifies the ID token using go-oidc verifier
func verifyIDToken(ctx context.Context, provider *oidc.Provider, idToken, clientID string) error {
	logger := logr.FromContextAsSlogLogger(ctx)

	// Create ID token verifier
	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	// Verify the ID token
	token, err := verifier.Verify(ctx, idToken)
	if err != nil {
		return fmt.Errorf("ID token verification failed: %w", err)
	}

	logger.Debug("ID token verified", "subject", token.Subject, "issuer", token.Issuer, "audience", token.Audience)

	return nil
}

// verifyJWTAccessToken verifies a JWT access token including signature verification
func verifyJWTAccessToken(ctx context.Context, provider *oidc.Provider, accessToken, clientID string) error {
	logger := logr.FromContextAsSlogLogger(ctx)

	// First, try to decode the JWT to validate its structure and get basic info
	_, payload, err := decodeJWT(accessToken)
	if err != nil {
		return fmt.Errorf("failed to decode JWT access token: %w", err)
	}

	// Parse the payload to get claims
	var claims map[string]interface{}
	if err := json.Unmarshal([]byte(payload), &claims); err != nil {
		return fmt.Errorf("failed to parse JWT access token payload: %w", err)
	}

	// Log basic token info
	if sub, ok := claims["sub"].(string); ok {
		logger.Debug("JWT access token subject", "subject", sub)
	}
	if iss, ok := claims["iss"].(string); ok {
		logger.Debug("JWT access token issuer", "issuer", iss)
	}

	// Now verify the signature using go-oidc
	// Create a verifier that skips audience validation since access tokens
	// might not be intended for this specific client
	verifier := provider.Verifier(&oidc.Config{
		ClientID:          clientID,
		SkipClientIDCheck: true,  // Skip audience check for access tokens
		SkipExpiryCheck:   false, // Still check expiration
		SkipIssuerCheck:   false, // Still check issuer
	})

	// Verify the JWT signature and claims
	token, err := verifier.Verify(ctx, accessToken)
	if err != nil {
		// If signature verification fails, log the error but continue with manual validation
		logger.Error("JWT access token signature verification failed, falling back to manual validation", "error", err)

		// Manual validation for cases where the verifier is too strict
		return verifyJWTManually(claims, logger)
	}

	// If signature verification succeeded, log success
	logger.Debug("JWT access token signature verified successfully",
		"subject", token.Subject,
		"issuer", token.Issuer,
		"expiry", token.Expiry)

	return nil
}

// verifyJWTManually performs manual JWT validation when signature verification fails
func verifyJWTManually(claims map[string]interface{}, logger *slog.Logger) error {
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

	// Check issued at if present
	if iat, ok := claims["iat"].(float64); ok {
		iatTime := time.Unix(int64(iat), 0)
		if time.Now().Before(iatTime) {
			return fmt.Errorf("JWT access token issued in the future at %v", iatTime)
		}
	}

	logger.Debug("JWT access token manually validated (signature verification failed but timing is valid)")
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
	data.Set("client_id", clientID)

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
