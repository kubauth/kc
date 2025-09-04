package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"getok/global"
	"getok/internal/httpclient"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
)

var noUiParams struct {
	login           string
	password        string
	onlyIDToken     bool
	onlyAccessToken bool
}

// TokenResponse represents the OAuth2/OIDC token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func init() {
	noUiCmd.PersistentFlags().StringVarP(&noUiParams.login, "login", "u", "", "User login")
	noUiCmd.PersistentFlags().StringVarP(&noUiParams.password, "password", "p", "", "User password")
	noUiCmd.PersistentFlags().BoolVar(&noUiParams.onlyIDToken, "onlyIDToken", false, "Output only ID token")
	noUiCmd.PersistentFlags().BoolVar(&noUiParams.onlyAccessToken, "onlyAccessToken", false, "Output only Access token")
}

var noUiCmd = &cobra.Command{
	Use:   "noui",
	Short: "No UI: Get token using Resource Owner Password Credentials (ROPC)",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {

		err := setup()
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		global.Logger.Debug("Start No UI processing", "issuer", rootParams.httpConfig.BaseURL)

		httpClient, err := httpclient.New(&rootParams.httpConfig)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		ctx := oidc.ClientContext(context.Background(), httpClient)
		provider, err := oidc.NewProvider(ctx, rootParams.httpConfig.BaseURL)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
		}
		endpoints := provider.Endpoint()
		global.Logger.Debug("OIDC provider initialized", "AuthURL", endpoints.AuthURL, "tokenURL", endpoints.TokenURL, "UserInfoURL", provider.UserInfoEndpoint())
		login := noUiParams.login
		password := noUiParams.password
		for login == "" || password == "" {
			login, password = inputCredentials(login, password)
		}

		// Perform password credentials flow with direct HTTP request to get both access and ID tokens
		tokenResponse, err := passwordCredentialsFlow(ctx, httpClient, provider.Endpoint().TokenURL, rootParams.clientId, rootParams.clientSecret, login, password, rootParams.scopes)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		// Verify ID token if present
		if tokenResponse.IDToken != "" {
			err = verifyIDToken(ctx, provider, tokenResponse.IDToken, rootParams.clientId)
			if err != nil {
				global.Logger.Debug("ID token verification failed", "error", err)
				_, _ = fmt.Fprintf(os.Stderr, "Warning: ID token verification failed: %v\n", err)
			} else {
				global.Logger.Debug("ID token verified successfully")
			}
		}

		// Optionally output ID token if requested and present
		if noUiParams.onlyIDToken {
			if tokenResponse.IDToken == "" {
				_, _ = fmt.Fprintf(os.Stderr, "No ID token\n")
			} else {
				fmt.Println(tokenResponse.IDToken)
			}
		} else if noUiParams.onlyAccessToken {
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
			fmt.Printf("Expire in :%s sec\n", time.Duration(tokenResponse.ExpiresIn)*time.Second)

		}
		//if tokenResponse.IDToken != "" {
		//	global.Logger.Debug("ID token received", "length", len(tokenResponse.IDToken))
		//	if noUiParams.showIDToken {
		//		fmt.Fprintf(os.Stderr, "ID Token: %s\n", tokenResponse.IDToken)
		//	}
		//}

	},
}

func inputCredentials(login, password string) (string, string) {
	if login == "" {
		login = os.Getenv("GETOK_USER_LOGIN")
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
		password = os.Getenv("GETOK_USER_PASSWORD")
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
	bytePassword, err2 := terminal.ReadPassword(int(syscall.Stdin))
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

	global.Logger.Debug("Making password credentials request", "tokenURL", tokenURL, "clientID", clientID, "scopes", scopes)

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

	global.Logger.Debug("Token response received", "hasAccessToken", tokenResponse.AccessToken != "", "hasIDToken", tokenResponse.IDToken != "")

	return &tokenResponse, nil
}

// verifyIDToken verifies the ID token using go-oidc verifier
func verifyIDToken(ctx context.Context, provider *oidc.Provider, idToken, clientID string) error {
	// Create ID token verifier
	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	// Verify the ID token
	token, err := verifier.Verify(ctx, idToken)
	if err != nil {
		return fmt.Errorf("ID token verification failed: %w", err)
	}

	global.Logger.Debug("ID token verified", "subject", token.Subject, "issuer", token.Issuer, "audience", token.Audience)

	return nil
}
