package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"getok/internal/httpclient"
	"io"
	"net/http"
	"os"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
)

var logoutParams struct {
	browser string
}

func init() {
	initOidcParams(logoutCmd)
	logoutCmd.PersistentFlags().StringVar(&logoutParams.browser, "browser", "", "Browser to use (default: system default, options: chrome, firefox, safari)")
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout: Open browser to end_session_endpoint for logout",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		logger, err := setupOidc(cmd)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		logger.Debug("Start logout processing", "issuer", oidcParams.httpClientConfig.BaseURL)

		httpClient, err := httpclient.New(&oidcParams.httpClientConfig)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		ctx := context.Background()
		ctx = logr.NewContextWithSlogLogger(ctx, logger)

		// Fetch OIDC configuration to get end_session_endpoint
		endSessionEndpoint, err := getEndSessionEndpoint(ctx, httpClient, oidcParams.httpClientConfig.BaseURL)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		if endSessionEndpoint == "" {
			_, _ = fmt.Fprintln(os.Stderr, "Error: end_session_endpoint not found in OIDC configuration")
			os.Exit(1)
		}

		logger.Debug("Found end_session_endpoint", "endpoint", endSessionEndpoint)

		// Open browser to end_session_endpoint
		_, _ = fmt.Fprintf(os.Stderr, "Opening browser to logout endpoint: %s\n", endSessionEndpoint)

		if err := openBrowser(endSessionEndpoint, logoutParams.browser); err != nil {
			logger.Debug("Failed to open browser automatically", "error", err)
			_, _ = fmt.Fprintf(os.Stderr, "Failed to open browser automatically. Please visit: %s\n", endSessionEndpoint)
		}
	},
}

// OIDCConfiguration represents the OIDC provider configuration
type OIDCConfiguration struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSUri               string `json:"jwks_uri"`
}

// getEndSessionEndpoint fetches the OIDC configuration and returns the end_session_endpoint
func getEndSessionEndpoint(ctx context.Context, httpClient *http.Client, issuerURL string) (string, error) {
	logger := logr.FromContextAsSlogLogger(ctx)

	// Construct the well-known configuration URL
	configURL := issuerURL + "/.well-known/openid-configuration"
	logger.Debug("Fetching OIDC configuration", "configURL", configURL)

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", configURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	// Perform request
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch OIDC configuration: %w", err)
	}
	defer resp.Body.Close()

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("OIDC configuration request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read OIDC configuration response: %w", err)
	}

	// Parse JSON response
	var config OIDCConfiguration
	if err := json.Unmarshal(body, &config); err != nil {
		return "", fmt.Errorf("failed to parse OIDC configuration: %w", err)
	}

	logger.Debug("OIDC configuration retrieved",
		"issuer", config.Issuer,
		"authEndpoint", config.AuthorizationEndpoint,
		"tokenEndpoint", config.TokenEndpoint,
		"endSessionEndpoint", config.EndSessionEndpoint)

	return config.EndSessionEndpoint, nil
}
