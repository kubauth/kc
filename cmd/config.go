package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/go-logr/logr"
	"github.com/kubauth/okit/pkg/proto"
	"github.com/spf13/cobra"
	"io"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
	"kc/internal/httpclient"
	"kc/internal/misc"
	"net/http"
	"os"
	"strconv"
	"strings"
)

var configParams struct {
	logConfig            misc.LogConfig
	httpClientConfig     httpclient.Config
	contextNameOverride  string
	apiServerURLOverride string
	issuerURLOverride    string
	namespaceOverride    string
	noContextSwitch      bool
	force                bool
	kubeconfigPath       string
	standalone           bool
	scopes               []string
	grantType            string
	pkce                 string
}

func init() {
	configCmd.PersistentFlags().StringVarP(&configParams.logConfig.Level, "logLevel", "l", "INFO", "Log level(DEBUG, INFO, WARN, ERROR)")
	configCmd.PersistentFlags().StringVar(&configParams.logConfig.Mode, "logMode", "text", "Log mode ('text' or 'json')")

	configCmd.PersistentFlags().BoolVar(&configParams.httpClientConfig.DumpExchanges, "dumpExchanges", false, "Dump http client req/resp")
	configCmd.PersistentFlags().BoolVar(&configParams.httpClientConfig.InsecureSkipVerify, "insecureSkipVerify", false, "Don't validate issuer certificate")
	configCmd.PersistentFlags().StringArrayVar(&configParams.httpClientConfig.RootCaPaths, "caFile", []string{}, "Root CA path(s) for validation of URL.")

	configCmd.PersistentFlags().StringVar(&configParams.contextNameOverride, "contextNameOverride", "", "Override context name. (Will be used as base for cluster and user name)")
	configCmd.PersistentFlags().StringVar(&configParams.apiServerURLOverride, "apiServerURLOverride", "", "Override K8s API server URL")
	configCmd.PersistentFlags().StringVar(&configParams.issuerURLOverride, "issuerURLOverride", "", "Override oidc issuer URL")
	configCmd.PersistentFlags().StringVar(&configParams.namespaceOverride, "namespaceOverride", "", "Override namespace")
	configCmd.PersistentFlags().BoolVar(&configParams.noContextSwitch, "noContextSwitch", false, "Do not set default context to the newly create one.")
	configCmd.PersistentFlags().BoolVar(&configParams.force, "force", false, "Override any already existing context")

	configCmd.PersistentFlags().StringVar(&configParams.kubeconfigPath, "kubeconfig", "", "kubeconfig file path. Override default configuration.")

	configCmd.PersistentFlags().BoolVar(&configParams.standalone, "standalone", false, "Use kubelogin in standalone mode")
	configCmd.PersistentFlags().StringArrayVar(&configParams.scopes, "scope", []string{}, "Extra scopes")
	configCmd.PersistentFlags().StringVar(&configParams.grantType, "grantType", "auto", "Grant type (auto|authcode|password) (default: auto)")
	//configCmd.PersistentFlags().StringVar(&configParams.grantType, "grantType", "auto", "Grant type (auto|authcode|authcode-keyboard|password|device-code|client-credentials) (default: auto)")
	configCmd.PersistentFlags().StringVar(&configParams.pkce, "pkce", "auto", "PKCE (auto|no|S256) (default: auto)")

}

var validGrantTypes = map[string]bool{
	"auto":               true,
	"authcode":           true,
	"authcode-keyboard":  true,
	"password":           true,
	"device-code":        true,
	"client-credentials": true,
}

var validPKCETypes = map[string]bool{
	"auto": true,
	"no":   true,
	"S256": true,
}

var configCmd = &cobra.Command{
	Use:   "config <configuration_url>",
	Short: "Initialize KUBECONFIG for OIDC connection",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		logger, err := misc.NewLogger(&configParams.logConfig)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, err.Error())
			os.Exit(1)
		}
		err = func() error {
			url := args[0]
			if !(strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")) {
				url = "https://" + url
			}
			if _, ok := validGrantTypes[configParams.grantType]; !ok {
				return fmt.Errorf("invalid grant type: %s", configParams.grantType)
			}
			if _, ok := validPKCETypes[configParams.pkce]; !ok {
				return fmt.Errorf("invalid pkce parameter: %s", configParams.pkce)
			}
			ctx := logr.NewContextWithSlogLogger(context.Background(), logger)
			kubeConfigResponse, err := getRemoteKubeconfigInfo(ctx, url)
			if err != nil {
				return err
			}
			_ = kubeConfigResponse
			// ---------------------------------------------------- Override parameters
			if configParams.contextNameOverride != "" {
				kubeConfigResponse.Context.Name = configParams.contextNameOverride
			}
			if configParams.apiServerURLOverride != "" {
				kubeConfigResponse.Cluster.ApiServerURL = configParams.apiServerURLOverride
			}
			if configParams.issuerURLOverride != "" {
				kubeConfigResponse.Oidc.IssuerURL = configParams.issuerURLOverride
			}
			if configParams.namespaceOverride != "" {
				kubeConfigResponse.Context.Namespace = configParams.namespaceOverride
			}
			// ---------------------------------------------------- Define some entity names
			contextName := kubeConfigResponse.Context.Name
			clusterName := contextName + "-cluster"
			userName := contextName + "-user"

			// ----------------------------------------------- Load the current kubeconfig
			loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
			loadingRules.ExplicitPath = configParams.kubeconfigPath // From the command line. Must take precedence
			loadingRules.WarnIfAllMissing = false
			configOverrides := &clientcmd.ConfigOverrides{}
			kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
			rawConfig, err := kubeConfig.RawConfig()
			if err != nil {
				return err
			}
			configAccess := kubeConfig.ConfigAccess()

			// logger.Debug("ConfigAccess", "AuthInfos", rawConfig.AuthInfos["oidc-kubo6-user"])

			// -----------------------------------------------------In case of init blank file
			if rawConfig.Clusters == nil {
				rawConfig.Clusters = make(map[string]*api.Cluster)
			}
			if rawConfig.AuthInfos == nil {
				rawConfig.AuthInfos = make(map[string]*api.AuthInfo)
			}
			if rawConfig.Contexts == nil {
				rawConfig.Contexts = make(map[string]*api.Context)
			}
			// ---------------------------------------------------- Test previous config overwrite
			_, exitingContext := rawConfig.Contexts[contextName]
			if exitingContext && !configParams.force {
				return fmt.Errorf("context %s already exists in this config file (%s). Use --force to override\n", contextName, configAccess.GetDefaultFilename())
			}
			if _, ok := rawConfig.Clusters[clusterName]; ok && !configParams.force {
				return fmt.Errorf("cluster '%s' already existing in this config file (%s). Use --force to override\n", clusterName, configAccess.GetDefaultFilename())
			}
			if _, ok := rawConfig.AuthInfos[userName]; ok && !configParams.force {
				return fmt.Errorf("user '%s' already existing in this config file (%s). Use --force to override\n", userName, configAccess.GetDefaultFilename())
			}

			if exitingContext {
				fmt.Printf("Update existing context '%s' in kubeconfig file '%s'\n", contextName, configAccess.GetDefaultFilename())
			} else {
				fmt.Printf("Setup new context '%s' in kubeconfig file '%s'\n", contextName, configAccess.GetDefaultFilename())
			}

			rootCaData, err := base64.StdEncoding.DecodeString(kubeConfigResponse.Cluster.RootCaData)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "ERROR: Invalid server certificate. Refer to system administrator\n")
				os.Exit(15)
			}
			rawConfig.Clusters[clusterName] = &api.Cluster{
				Server:                   kubeConfigResponse.Cluster.ApiServerURL,
				CertificateAuthorityData: rootCaData,
				InsecureSkipTLSVerify:    kubeConfigResponse.Cluster.InsecureSkipVerify,
			}
			rawConfig.Contexts[contextName] = &api.Context{
				Cluster:   clusterName,
				AuthInfo:  userName,
				Namespace: kubeConfigResponse.Context.Namespace,
			}
			if rawConfig.CurrentContext == "" || !configParams.noContextSwitch {
				rawConfig.CurrentContext = contextName
			}
			if configParams.standalone {
				scopes := configParams.scopes
				scopes = addScope(scopes, "offline") // NB: openid is added by kubelogin
				rawConfig.AuthInfos[userName] = &api.AuthInfo{
					AuthProvider: &api.AuthProviderConfig{
						Name: "oidc",
						Config: map[string]string{
							"idp-issuer-url":                 kubeConfigResponse.Oidc.IssuerURL,
							"client-id":                      kubeConfigResponse.Oidc.ClientId,
							"client-secret":                  kubeConfigResponse.Oidc.ClientSecret,
							"idp-certificate-authority-data": kubeConfigResponse.Oidc.IssuerCaData,
							"extra-scopes":                   strings.Join(scopes, ","),
						},
					},
				}
			} else {
				scopes := configParams.scopes
				scopes = addScope(scopes, "offline") // NB: openid is added by kubelogin
				rawConfig.AuthInfos[userName] = &api.AuthInfo{
					Exec: &api.ExecConfig{
						APIVersion:      "client.authentication.k8s.io/v1",
						Command:         "kubectl",
						InteractiveMode: "IfAvailable",
						Args: []string{
							"oidc-login",
							"get-token",
							"--oidc-issuer-url=" + kubeConfigResponse.Oidc.IssuerURL,
							"--oidc-client-id=" + kubeConfigResponse.Oidc.ClientId,
							"--oidc-client-secret=" + kubeConfigResponse.Oidc.ClientSecret,
							"--certificate-authority-data=" + kubeConfigResponse.Oidc.IssuerCaData,
							"--insecure-skip-tls-verify=" + strconv.FormatBool(kubeConfigResponse.Oidc.InsecureSkipVerify),
							"--grant-type=" + configParams.grantType,
							"--oidc-extra-scope=" + strings.Join(scopes, ","),
							"--oidc-pkce-method=" + configParams.pkce,
						},
					},
				}
				if configParams.grantType == "authcode-keyboard" {
					rawConfig.AuthInfos[userName].Exec.Args = append(rawConfig.AuthInfos[userName].Exec.Args, "--oidc-redirect-url=http://localhost:8000")
					rawConfig.AuthInfos[userName].Exec.Args = append(rawConfig.AuthInfos[userName].Exec.Args, "--listen-address=http://localhost:8000")
				}

			}
			return clientcmd.ModifyConfig(configAccess, rawConfig, false)
		}()
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "ERROR: %s\n", err.Error())
			os.Exit(1)
		}

	},
}

func addScope(scopes []string, newScope string) []string {
	for _, scope := range scopes {
		if scope == newScope {
			return scopes
		}
	}
	return append(scopes, newScope)
}

func getRemoteKubeconfigInfo(ctx context.Context, url string) (*proto.KubeconfigConfig, error) {
	logger := logr.FromContextAsSlogLogger(ctx)

	configParams.httpClientConfig.BaseURL = url // Need to set for http/https detection

	httpClient, err := httpclient.New(&configParams.httpClientConfig)
	if err != nil {
		return nil, err
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	// Perform request
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Kubeconfig configuration: %w", err)
	}
	defer resp.Body.Close()

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("kubeconfig configuration request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Kubeconfig configuration response: %w", err)
	}

	// Parse JSON response
	kubeconfig := &proto.KubeconfigConfig{}
	if err := json.Unmarshal(body, &kubeconfig); err != nil {
		return nil, fmt.Errorf("failed to parse OIDC configuration: %w", err)
	}

	logger.Debug("Successfully retrieved Kubeconfig configuration", "context", kubeconfig.Context.Name, "apiServerURL", kubeconfig.Cluster.ApiServerURL, "issuerURL", kubeconfig.Oidc.IssuerURL, "clientId", kubeconfig.Oidc.ClientId)

	return kubeconfig, nil
}
