package cmd

import (
	"context"
	"fmt"
	"getok/internal/httpclient"
	"getok/internal/httpsrv"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"
)

var uiParams struct {
	httpSrvConfig httpsrv.Config
}

func init() {
	initOidcParams(uiCmd)
	uiCmd.PersistentFlags().BoolVar(&uiParams.httpSrvConfig.DumpExchanges, "dumpServerExchanges", false, "Dump http server req/resp")
	uiCmd.PersistentFlags().IntVarP(&uiParams.httpSrvConfig.BindPort, "bindPort", "p", 9921, "Local server Bind port")
}

var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "UI: Get token using authorisation code flow",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {

		logger, err := setupOidc(cmd)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		uiParams.httpSrvConfig.BindAddr = "127.0.0.1"
		uiParams.httpSrvConfig.Tls = false

		logger.Debug("Start with UI processing", "issuer", oidcParams.httpClientConfig.BaseURL)

		httpClient, err := httpclient.New(&oidcParams.httpClientConfig)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		ctx := oidc.ClientContext(context.Background(), httpClient)
		provider, err := oidc.NewProvider(ctx, oidcParams.httpClientConfig.BaseURL)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		endpoints := provider.Endpoint()
		logger.Debug("OIDC provider initialized", "AuthURL", endpoints.AuthURL, "tokenURL", endpoints.TokenURL, "UserInfoURL", provider.UserInfoEndpoint())
		login := noUiParams.login
		password := noUiParams.password
		for login == "" || password == "" {
			login, password = inputCredentials(login, password)
		}

		// Implements authorization code flow here
		tokenResponse := TokenResponse{}

		// Verify ID token if present
		if tokenResponse.IDToken != "" {
			err = verifyIDToken(ctx, provider, tokenResponse.IDToken, oidcParams.clientId)
			if err != nil {
				logger.Debug("ID token verification failed", "error", err)
				_, _ = fmt.Fprintf(os.Stderr, "Warning: ID token verification failed: %v\n", err)
			} else {
				logger.Debug("ID token verified successfully")
			}
		}

		// Optionally output ID token if requested and present
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
