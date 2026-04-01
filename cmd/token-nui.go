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
	tokenNuiCmd.PersistentFlags().DurationVarP(&oidcParams.ttl, "ttl", "t", time.Duration(0), "Time to live (default: 0)")
	tokenNuiCmd.PersistentFlags().IntVar(&oidcParams.renewAt, "renewAt", 60, "Percentage of the ticket duration to Trigger renewal ")
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

		if oidcParams.ttl != 0 {
			ensureOfflineAccessScope(logger)
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
		verifyTokens(ctx, provider, tokenResponse, httpClient, logger)

		// Output tokens using shared function
		outputTokens(tokenResponse, logger)

		if oidcParams.ttl != 0 {
			renewalLoop(ctx, provider, tokenResponse, httpClient, logger)
		}

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
