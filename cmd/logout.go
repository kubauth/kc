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
	"k8s.io/client-go/tools/clientcmd"
	"kc/internal/httpclient"
	"kc/internal/misc"
	"net/http"
	"os"
	"os/exec"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
)

var logoutParams struct {
	logConfig           misc.LogConfig
	browser             string
	issuerURL           string
	dumpClientExchanges bool
	insecureSkipVerify  bool
	rootCaPaths         []string
	kubeconfig          string
	context             string
}

func init() {
	logoutCmd.PersistentFlags().StringVar(&logoutParams.browser, "browser", "", "Browser to use (default: system default, options: chrome, firefox, safari)")
	logoutCmd.PersistentFlags().StringVarP(&logoutParams.issuerURL, "issuerURL", "i", "", "issuer URL (Env:KC_ISSUER_URL)")
	logoutCmd.PersistentFlags().StringVarP(&logoutParams.logConfig.Level, "logLevel", "l", "INFO", "Log level(DEBUG, INFO, WARN, ERROR)")
	logoutCmd.PersistentFlags().StringVar(&logoutParams.logConfig.Mode, "logMode", "text", "Log mode ('text' or 'json')")
	logoutCmd.PersistentFlags().BoolVar(&logoutParams.dumpClientExchanges, "dumpClientExchanges", false, "Dump http client req/resp")
	logoutCmd.PersistentFlags().BoolVar(&logoutParams.insecureSkipVerify, "insecureSkipVerify", false, "Don't validate issuer certificate")
	logoutCmd.PersistentFlags().StringArrayVar(&logoutParams.rootCaPaths, "caFile", []string{}, "Root CA path(s) for validation of issuer URL.")
	logoutCmd.PersistentFlags().StringVar(&logoutParams.kubeconfig, "kubeconfig", "", "kubeconfig file to fetch issuerURL and CA (default env:KUBECONFIG or $HOME/.kube/config)")
	logoutCmd.PersistentFlags().StringVar(&logoutParams.context, "context", "", "Context in kubeconfig file to fetch issuerURL and CA (Override kubeconfig default context")

}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout: Open browser to end_session_endpoint for logout",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		err := func() error {
			logger, err := misc.NewLogger(&logoutParams.logConfig)
			if err != nil {
				return fmt.Errorf("could not create logger: %w", err)
			}

			// Handle environment variables
			adjustStringParam(cmd.PersistentFlags(), "issuerURL", "KC_ISSUER_URL", &logoutParams.issuerURL)

			configInfo, err := getConfigInfo(logoutParams.kubeconfig, logoutParams.context, logger)
			if err != nil {
				return err
			}
			var rootCaDatas []string = nil
			if configInfo != nil {
				logger.Debug("Completing OIDC configuration from kubeconfig")
				if logoutParams.issuerURL == "" {
					logoutParams.issuerURL = configInfo.issuerURL
				}
				if len(logoutParams.rootCaPaths) == 0 {
					rootCaDatas = []string{configInfo.caData}
				}
				if !logoutParams.insecureSkipVerify {
					logoutParams.insecureSkipVerify = configInfo.insecureSkipTlsVerify
				}
				if configInfo.standalone {
					fmt.Printf("Cleaning oidc auth provider token in kubeconfig if any\n")
					err = standaloneLogout(logoutParams.kubeconfig, logoutParams.context)
					if err != nil {
						logger.Error("Error on standalone mode logout", "error", err)
					}
				} else {
					fmt.Printf("CLeaning kubelogin OIDC configuration if any\n")
					err := exec.Command("kubectl", "oidc-login", "clean").Start()
					if err != nil {
						logger.Error("Could not clean kubelogin OIDC configuration", "error", err)
					}
				}
			}

			if logoutParams.issuerURL == "" {
				return fmt.Errorf("issuer URL cannot be empty")
			}

			// Setup HTTP client configuration
			httpClientConfig := &httpclient.Config{
				BaseURL:            logoutParams.issuerURL,
				DumpExchanges:      logoutParams.dumpClientExchanges,
				InsecureSkipVerify: logoutParams.insecureSkipVerify,
				RootCaPaths:        logoutParams.rootCaPaths,
				RootCaDatas:        rootCaDatas,
			}

			logger.Debug("Start logout processing", "issuer", httpClientConfig.BaseURL)

			httpClient, err := httpclient.New(httpClientConfig)
			if err != nil {
				return err
			}

			ctx := context.Background()
			ctx = logr.NewContextWithSlogLogger(ctx, logger)

			// Fetch OIDC configuration to get end_session_endpoint
			endSessionEndpoint, err := getEndSessionEndpoint(ctx, httpClient, httpClientConfig.BaseURL)
			if err != nil {
				return err
			}

			if endSessionEndpoint == "" {
				return fmt.Errorf("end_session_endpoint not found in OIDC configuration")
			}

			logger.Debug("Found end_session_endpoint", "endpoint", endSessionEndpoint)

			// Open browser to end_session_endpoint
			_, _ = fmt.Fprintf(os.Stderr, "Opening browser to logout endpoint: %s\n", endSessionEndpoint)

			err = openBrowser(endSessionEndpoint, logoutParams.browser)
			if err != nil {
				logger.Debug("Failed to open browser automatically", "error", err)
				_, _ = fmt.Fprintf(os.Stderr, "Failed to open browser automatically. Please visit: %s\n", endSessionEndpoint)
			}
			return nil
		}()
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
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

// NB: Most of errors should no occurs, as this function is called only when standalone mode has been detected
func standaloneLogout(kubeconfig string, context string) error {
	// ----------------------------------------------- Load the current kubeconfig
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.ExplicitPath = kubeconfig // From the command line. Must take precedence
	loadingRules.WarnIfAllMissing = false
	configOverrides := &clientcmd.ConfigOverrides{}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	rawConfig, err := kubeConfig.RawConfig()
	if err != nil {
		return err
	}
	configAccess := kubeConfig.ConfigAccess()

	contextName := rawConfig.CurrentContext
	if context != "" {
		contextName = context
	}
	currentContext := rawConfig.Contexts[contextName]
	if currentContext == nil {
		return fmt.Errorf("current context not found in kubeconfig")
	}
	authInfo := rawConfig.AuthInfos[currentContext.AuthInfo]
	if authInfo == nil {
		return fmt.Errorf("no authInfo for user %s found in kubeconfig", currentContext.AuthInfo)
	}
	authProvider := authInfo.AuthProvider
	if authProvider == nil {
		return fmt.Errorf("no authProvider for user %s found in kubeconfig", currentContext.AuthInfo)
	}
	if authProvider.Name != "oidc" {
		return fmt.Errorf("authProvider %s for user %s is not 'oidc'", authProvider.Name, currentContext.AuthInfo)
	}
	config := authProvider.Config
	if config == nil {
		return fmt.Errorf("no config found for user %s in kubeconfig", currentContext.AuthInfo)
	}
	delete(config, "id-token")
	delete(config, "refresh-token")

	return clientcmd.ModifyConfig(configAccess, rawConfig, false)
}
