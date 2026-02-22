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
	"fmt"
	"kc/internal/httpclient"
	"kc/internal/misc"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

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
}

func initOidcParams(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&oidcParams.logConfig.Mode, "logMode", "text", "Log mode ('text' or 'json')")
	cmd.PersistentFlags().StringVarP(&oidcParams.logConfig.Level, "logLevel", "l", "INFO", "Log level(DEBUG, INFO, WARN, ERROR)")

	cmd.PersistentFlags().BoolVar(&oidcParams.httpClientConfig.DumpExchanges, "dumpClientExchanges", false, "Dump http client req/resp")
	cmd.PersistentFlags().BoolVar(&oidcParams.httpClientConfig.InsecureSkipVerify, "insecureSkipVerify", false, "Don't validate issuer certificate")
	cmd.PersistentFlags().StringArrayVar(&oidcParams.httpClientConfig.RootCaPaths, "caFile", []string{}, "Root CA path(s) for validation of issuer URL.")
	cmd.PersistentFlags().StringArrayVar(&oidcParams.scopes, "scope", []string{"openid", "profile", "offline", "groups"}, "Requested scopes.")
	cmd.PersistentFlags().StringVarP(&oidcParams.httpClientConfig.BaseURL, "issuerURL", "i", "", "issuer URL (Env:KC_ISSUER_URL)")
	cmd.PersistentFlags().StringVar(&oidcParams.kubeconfig, "kubeconfig", "", "kubeconfig file to fetch issuerURL and CA (default env:KUBECONFIG or $HOME/.kube/config)")
	cmd.PersistentFlags().StringVar(&oidcParams.context, "context", "", "Context in kubeconfig file to fetch issuerURL and CA (Override kubeconfig default context")

	cmd.PersistentFlags().StringVarP(&oidcParams.clientId, "clientId", "c", "", "Client ID (Env:KC_CLIENT_ID)")
	cmd.PersistentFlags().StringVarP(&oidcParams.clientSecret, "clientSecret", "s", "", "Client Secret (Env:KC_CLIENT_SECRET)")
	cmd.PersistentFlags().BoolVar(&oidcParams.onlyIdToken, "onlyIdToken", false, "Output only ID token")
	cmd.PersistentFlags().BoolVar(&oidcParams.onlyAccessToken, "onlyAccessToken", false, "Output only Access token")
	cmd.PersistentFlags().BoolVarP(&oidcParams.detailIdToken, "detailIdToken", "d", false, "Detail ID token")
	cmd.PersistentFlags().BoolVarP(&oidcParams.detailAccessToken, "detailAccessToken", "a", false, "Detail Access token")

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

// As the server may issue AccessToken as JWT or as opaque form, depending of its configuration, we need a clean test to find the token type.
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
