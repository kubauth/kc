package cmd

import (
	"fmt"
	"getok/internal/httpclient"
	"getok/internal/misc"
	"github.com/spf13/cobra"
	"log/slog"
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

	cmd.PersistentFlags().StringVarP(&oidcParams.httpClientConfig.BaseURL, "issuerURL", "i", "", "issuer URL (Env:GETOK_ISSUER_URL)")
	cmd.PersistentFlags().StringVarP(&oidcParams.clientId, "clientId", "c", "", "Client ID (Env:GETOK_CLIENT_ID)")
	cmd.PersistentFlags().StringVarP(&oidcParams.clientSecret, "clientSecret", "s", "", "Client Secret (Env:GETOK_CLIENT_SECRET)")
	cmd.PersistentFlags().BoolVar(&oidcParams.onlyIDToken, "onlyIDToken", false, "Output only ID token")
	cmd.PersistentFlags().BoolVar(&oidcParams.onlyAccessToken, "onlyAccessToken", false, "Output only Access token")

}

func setupOidc(cmd *cobra.Command) (*slog.Logger, error) {
	var err error
	logger, err := misc.NewLogger(&oidcParams.logConfig)
	if err != nil {
		return nil, fmt.Errorf("could not create logger: %w", err)
	}
	adjustStringParam(cmd.PersistentFlags(), "issuerURL", "GETOK_ISSUER_URL", &oidcParams.httpClientConfig.BaseURL)
	adjustStringParam(cmd.PersistentFlags(), "clientId", "GETOK_CLIENT_ID", &oidcParams.clientId)
	adjustStringParam(cmd.PersistentFlags(), "clientSecret", "GETOK_CLIENT_SECRET", &oidcParams.clientSecret)

	if oidcParams.httpClientConfig.BaseURL == "" {
		return logger, fmt.Errorf("issuer URL cannot be empty")
	}
	if oidcParams.clientId == "" {
		return logger, fmt.Errorf("client ID cannot be empty")
	}
	// clientSecret can be null (public client)
	return logger, nil
}
