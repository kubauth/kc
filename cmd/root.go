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
	"getok/global"
	"getok/internal/httpclient"
	"getok/internal/misc"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"os"
)

func init() {

}

var rootParams struct {
	logConfig  misc.LogConfig
	httpConfig httpclient.Config
	scopes     []string

	clientId     string
	clientSecret string
}

func init() {
	rootCmd.PersistentFlags().StringVar(&rootParams.logConfig.Mode, "logMode", "text", "Log mode ('text' or 'json')")
	rootCmd.PersistentFlags().StringVarP(&rootParams.logConfig.Level, "logLevel", "l", "INFO", "Log level(DEBUG, INFO, WARN, ERROR)")
	rootCmd.PersistentFlags().BoolVar(&rootParams.httpConfig.DumpExchanges, "dumpExchanges", false, "Dump http client req/resp")
	rootCmd.PersistentFlags().BoolVar(&rootParams.httpConfig.InsecureSkipVerify, "insecureSkipVerify", false, "Don't validate server certificate")
	rootCmd.PersistentFlags().StringArrayVar(&rootParams.httpConfig.RootCaPaths, "caFile", []string{}, "Root CA path(s) for validation of issuer URL.")
	rootCmd.PersistentFlags().StringArrayVar(&rootParams.scopes, "scope", []string{"openid", "profile"}, "Requested scopes.")

	rootCmd.PersistentFlags().StringVarP(&rootParams.httpConfig.BaseURL, "issuerURL", "i", "", "issuer URL")
	rootCmd.PersistentFlags().StringVarP(&rootParams.clientId, "clientId", "c", "", "Client ID")
	rootCmd.PersistentFlags().StringVarP(&rootParams.clientSecret, "clientSecret", "s", "", "Client Secret")

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(noUiCmd)

}

func setup() error {

	var err error
	global.Logger, err = misc.NewLogger(&rootParams.logConfig)
	if err != nil {
		return fmt.Errorf("could not create logger: %w", err)
	}
	adjustStringParam(rootCmd.PersistentFlags(), "issuerURL", "GETOK_ISSUER_URL", &rootParams.httpConfig.BaseURL)
	adjustStringParam(rootCmd.PersistentFlags(), "clientId", "GETOK_CLIENT_ID", &rootParams.clientId)
	adjustStringParam(rootCmd.PersistentFlags(), "clientSecret", "GETOK_CLIENT_SECRET", &rootParams.clientSecret)

	if rootParams.httpConfig.BaseURL == "" {
		return fmt.Errorf("issuer URL cannot be empty")
	}
	if rootParams.clientId == "" {
		return fmt.Errorf("client ID cannot be empty")
	}
	// clientSecret can be null (public client)
	return nil
}

var rootCmd = &cobra.Command{
	Use:   "getok",
	Short: "Get Token tool",
}

var debug = true

func Execute() {
	defer func() {
		if !debug {
			if r := recover(); r != nil {
				fmt.Printf("ERROR:%v\n", r)
				os.Exit(1)
			}
		}
	}()
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
}

func adjustStringParam(flagSet *pflag.FlagSet, paramName string, envVar string, value *string) {
	if !flagSet.Lookup(paramName).Changed {
		// Lookup in env
		v := os.Getenv(envVar)
		if v != "" {
			*value = v
		}
	}
}
