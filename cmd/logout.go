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
	"os"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
)

var logoutParams struct {
	browser             string
	issuerURL           string
	logLevel            string
	logMode             string
	dumpClientExchanges bool
	insecureSkipVerify  bool
	rootCaPaths         []string
}

func init() {
	logoutCmd.PersistentFlags().StringVar(&logoutParams.browser, "browser", "", "Browser to use (default: system default, options: chrome, firefox, safari)")
	logoutCmd.PersistentFlags().StringVarP(&logoutParams.issuerURL, "issuerURL", "i", "", "issuer URL (Env:KC_ISSUER_URL)")
	logoutCmd.PersistentFlags().StringVarP(&logoutParams.logLevel, "logLevel", "l", "INFO", "Log level(DEBUG, INFO, WARN, ERROR)")
	logoutCmd.PersistentFlags().StringVar(&logoutParams.logMode, "logMode", "text", "Log mode ('text' or 'json')")
	logoutCmd.PersistentFlags().BoolVar(&logoutParams.dumpClientExchanges, "dumpClientExchanges", false, "Dump http client req/resp")
	logoutCmd.PersistentFlags().BoolVar(&logoutParams.insecureSkipVerify, "insecureSkipVerify", false, "Don't validate issuer certificate")
	logoutCmd.PersistentFlags().StringArrayVar(&logoutParams.rootCaPaths, "caFile", []string{}, "Root CA path(s) for validation of issuer URL.")
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout: Open browser to end_session_endpoint for logout",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		logger, httpClientConfig, err := setupLogout(cmd)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		logger.Debug("Start logout processing", "issuer", httpClientConfig.BaseURL)

		httpClient, err := httpclient.New(httpClientConfig)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		ctx := context.Background()
		ctx = logr.NewContextWithSlogLogger(ctx, logger)

		// Fetch OIDC configuration to get end_session_endpoint
		endSessionEndpoint, err := getEndSessionEndpoint(ctx, httpClient, httpClientConfig.BaseURL)
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

// setupLogout sets up the logger and HTTP client configuration for logout command
func setupLogout(cmd *cobra.Command) (*slog.Logger, *httpclient.Config, error) {
	// Setup logging
	logConfig := misc.LogConfig{
		Level: logoutParams.logLevel,
		Mode:  logoutParams.logMode,
	}
	logger, err := misc.NewLogger(&logConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create logger: %w", err)
	}

	// Handle environment variables
	adjustStringParam(cmd.PersistentFlags(), "issuerURL", "KC_ISSUER_URL", &logoutParams.issuerURL)

	if logoutParams.issuerURL == "" {
		return logger, nil, fmt.Errorf("issuer URL cannot be empty")
	}

	// Setup HTTP client configuration
	httpClientConfig := &httpclient.Config{
		BaseURL:            logoutParams.issuerURL,
		DumpExchanges:      logoutParams.dumpClientExchanges,
		InsecureSkipVerify: logoutParams.insecureSkipVerify,
		RootCaPaths:        logoutParams.rootCaPaths,
	}

	return logger, httpClientConfig, nil
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
