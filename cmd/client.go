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
	"kc/internal/httpclient"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
)

func init() {
	initOidcParams(clientCmd)
}

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "No UI: Exercise Client credential flow",
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

		tokenResponse, err := clientCredentialsFlow(ctx, httpClient, provider.Endpoint().TokenURL, oidcParams.clientId, oidcParams.clientSecret, oidcParams.scopes)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		verifyTokens(ctx, provider, tokenResponse, httpClient, logger)

		// Output tokens using shared function
		outputTokens(tokenResponse, logger)

	},
}

// clientCredentialsFlow performs the OAuth2 Client Credentials flow
// with a direct HTTP request to retrieve access_token
func clientCredentialsFlow(ctx context.Context, httpClient *http.Client, tokenURL string, clientId string, clientSecret string, scopes []string) (*TokenResponse, error) {
	logger := logr.FromContextAsSlogLogger(ctx)
	// Prepare form data
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", clientId)
	data.Set("client_secret", clientSecret)
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

	logger.Debug("Making client credentials request", "tokenURL", tokenURL, "clientID", clientId, "scopes", scopes)

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
	tokenResponse := &TokenResponse{}
	err = json.Unmarshal(body, tokenResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	logger.Debug("Token response received", "hasAccessToken", tokenResponse.AccessToken != "", "hasIDToken", tokenResponse.IDToken != "")

	return tokenResponse, nil
}
