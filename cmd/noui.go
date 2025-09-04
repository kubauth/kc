package cmd

import (
	"bufio"
	"context"
	"fmt"
	"getok/global"
	"getok/internal/httpclient"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/oauth2"
	"os"
	"strings"
	"syscall"
)

var noUiParams struct {
	login    string
	password string
}

func init() {
	noUiCmd.PersistentFlags().StringVarP(&noUiParams.login, "login", "u", "", "User login")
	noUiCmd.PersistentFlags().StringVarP(&noUiParams.password, "password", "p", "", "User password")
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

		oauth2Config := oauth2.Config{
			ClientID:     rootParams.clientId,
			ClientSecret: rootParams.clientSecret,
			Endpoint:     provider.Endpoint(),
			Scopes:       rootParams.scopes,
		}
		token, err := oauth2Config.PasswordCredentialsToken(ctx, login, password)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(token.AccessToken)

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
