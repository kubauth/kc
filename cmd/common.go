package cmd

import (
	"fmt"
	"kc/internal/httpclient"
	"kc/internal/misc"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
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
	logConfig        misc.LogConfig
	httpClientConfig httpclient.Config
	scopes           []string
	clientId         string
	clientSecret     string
	onlyIDToken      bool
	onlyAccessToken  bool
}

func initOidcParams(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&oidcParams.logConfig.Mode, "logMode", "text", "Log mode ('text' or 'json')")
	cmd.PersistentFlags().StringVarP(&oidcParams.logConfig.Level, "logLevel", "l", "INFO", "Log level(DEBUG, INFO, WARN, ERROR)")

	cmd.PersistentFlags().BoolVar(&oidcParams.httpClientConfig.DumpExchanges, "dumpClientExchanges", false, "Dump http client req/resp")
	cmd.PersistentFlags().BoolVar(&oidcParams.httpClientConfig.InsecureSkipVerify, "insecureSkipVerify", false, "Don't validate issuer certificate")
	cmd.PersistentFlags().StringArrayVar(&oidcParams.httpClientConfig.RootCaPaths, "caFile", []string{}, "Root CA path(s) for validation of issuer URL.")
	cmd.PersistentFlags().StringArrayVar(&oidcParams.scopes, "scope", []string{"openid", "profile"}, "Requested scopes.")

	cmd.PersistentFlags().StringVarP(&oidcParams.httpClientConfig.BaseURL, "issuerURL", "i", "", "issuer URL (Env:KC_ISSUER_URL)")
	cmd.PersistentFlags().StringVarP(&oidcParams.clientId, "clientId", "c", "", "Client ID (Env:KC_CLIENT_ID)")
	cmd.PersistentFlags().StringVarP(&oidcParams.clientSecret, "clientSecret", "s", "", "Client Secret (Env:KC_CLIENT_SECRET)")
	cmd.PersistentFlags().BoolVar(&oidcParams.onlyIDToken, "onlyIDToken", false, "Output only ID token")
	cmd.PersistentFlags().BoolVar(&oidcParams.onlyAccessToken, "onlyAccessToken", false, "Output only Access token")

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
func outputTokens(tokenResponse *TokenResponse) {
	if oidcParams.onlyIDToken {
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
	}
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
