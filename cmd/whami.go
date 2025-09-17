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
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"kc/internal/misc"
	"os"
	"path/filepath"
	"time"
)

var whoamiParams struct {
	logConfig  misc.LogConfig
	detailed   bool
	kubeconfig string
	context    string
}

func init() {
	whoamiCmd.PersistentFlags().StringVar(&whoamiParams.logConfig.Mode, "logMode", "text", "Log mode ('text' or 'json')")
	whoamiCmd.PersistentFlags().StringVarP(&whoamiParams.logConfig.Level, "logLevel", "l", "INFO", "Log level(DEBUG, INFO, WARN, ERROR)")
	whoamiCmd.PersistentFlags().BoolVarP(&whoamiParams.detailed, "detailed", "d", false, "Detail ID token")

	whoamiCmd.PersistentFlags().StringVar(&whoamiParams.kubeconfig, "kubeconfig", "", "kubeconfig file to fetch issuerURL and CA (default env:KUBECONFIG or $HOME/.kube/config)")
	whoamiCmd.PersistentFlags().StringVar(&whoamiParams.context, "context", "", "Context in kubeconfig file to fetch issuerURL and CA (Override kubeconfig default context")
}

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Display information about the current user, from jwt token",
	Run: func(cmd *cobra.Command, args []string) {
		err := func() error {
			logger, err := misc.NewLogger(&whoamiParams.logConfig)
			if err != nil {
				return fmt.Errorf("could not create logger: %w", err)
			}
			configInfo, err := getConfigInfo(whoamiParams.kubeconfig, whoamiParams.context, logger)
			if err != nil {
				return err
			}
			if configInfo == nil {
				logger.Debug("no kubelogin configuration found in kubeconfig file")
				fmt.Printf("unknown\n")
				return nil
			}
			if configInfo.standalone {
				if configInfo.idToken == "" {
					logger.Debug("no id-token found in standalone configuration in kubeconfig file")
					fmt.Printf("unknown\n")
					return nil
				}
				_, payload, err := decodeJWT(configInfo.idToken)
				if err != nil {
					return err
				}
				err = displayWhoami(payload)
				if err != nil {
					return err
				}
				return nil
			} else {
				content := lookupInOidcLoginCache()
				if content == "" {
					logger.Debug("no kubelogin configuration found in cache")
					fmt.Printf("unknown\n")
					return nil
				}
				var kubeloginCacheInfo struct {
					IdToken      string `json:"id_token"`
					RefreshToken string `json:"refresh_token"`
				}
				err := json.Unmarshal([]byte(content), &kubeloginCacheInfo)
				if err != nil {
					return err
				}
				_, payload, err := decodeJWT(kubeloginCacheInfo.IdToken)
				if err != nil {
					return err
				}
				err = displayWhoami(payload)
				if err != nil {
					return err
				}
			}
			// Lookup in kubconfig cache
			return nil
		}()
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

	},
}

func displayWhoami(payload string) error {
	var jwtDataMin struct {
		Sub string `json:"sub"`
		Exp int64  `json:"exp"`
	}
	err := json.Unmarshal([]byte(payload), &jwtDataMin)
	if err != nil {
		return err
	}
	expired := ""
	if jwtDataMin.Exp < time.Now().Unix() {
		expired = "  (expired)"
	}
	fmt.Printf("%s%s\n", jwtDataMin.Sub, expired)
	if whoamiParams.detailed {
		fmt.Printf("JWT Payload:\n%s\n", payload)
	}
	return nil
}

func lookupInOidcLoginCache() string {
	//homedir.HomeDir()
	dir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	cacheDir := filepath.Join(dir, ".kube/cache", "oidc-login")
	_, err = os.Stat(cacheDir)
	if err != nil {
		return ""
	}
	readDir, err := os.ReadDir(cacheDir)
	if err != nil {
		return ""
	}
	for _, entry := range readDir {
		//fmt.Printf("%v  %v   %v\n", entry.Name(), entry.IsDir(), entry.Type())
		info, err := entry.Info()
		if err != nil {
			return ""
		}
		//fmt.Printf("  %v   %v\n", info.Name(), info.Size())
		if info.Size() > 10 {
			fileContent, err := os.ReadFile(filepath.Join(cacheDir, entry.Name()))
			if err != nil {
				return ""
			}
			return string(fileContent)
		}
	}
	return ""
}
