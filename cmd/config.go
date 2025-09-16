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
	osuser "os/user"
	"path/filepath"
	"strings"
)

/*

Here is the target generated user config, part of kubeconfig file
ref: https://kubernetes.io/docs/reference/access-authn-authz/authentication/#option-1-oidc-authenticator

	users:
	- name: mmosley
	  user:
		auth-provider:
		  name: oidc
		  config:
			client-id: kubernetes
			client-secret: 1db158f6-177d-4d9c-8a8b-d36869918ec5
			id-token: eyJraWQiOiJDTj1vaWRjaWRwLnRyZW1vbG8ubGFuLCBPVT1EZW1vLCBPPVRybWVvbG8gU2VjdXJpdHksIEw9QXJsaW5ndG9uLCBTVD1WaXJnaW5pYSwgQz1VUy1DTj1rdWJlLWNhLTEyMDIxNDc5MjEwMzYwNzMyMTUyIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL29pZGNpZHAudHJlbW9sby5sYW46ODQ0My9hdXRoL2lkcC9PaWRjSWRQIiwiYXVkIjoia3ViZXJuZXRlcyIsImV4cCI6MTQ4MzU0OTUxMSwianRpIjoiMm96US15TXdFcHV4WDlHZUhQdy1hZyIsImlhdCI6MTQ4MzU0OTQ1MSwibmJmIjoxNDgzNTQ5MzMxLCJzdWIiOiI0YWViMzdiYS1iNjQ1LTQ4ZmQtYWIzMC0xYTAxZWU0MWUyMTgifQ.w6p4J_6qQ1HzTG9nrEOrubxIMb9K5hzcMPxc9IxPx2K4xO9l-oFiUw93daH3m5pluP6K7eOE6txBuRVfEcpJSwlelsOsW8gb8VJcnzMS9EnZpeA0tW_p-mnkFc3VcfyXuhe5R3G7aa5d8uHv70yJ9Y3-UhjiN9EhpMdfPAoEB9fYKKkJRzF7utTTIPGrSaSU6d2pcpfYKaxIwePzEkT4DfcQthoZdy9ucNvvLoi1DIC-UocFD8HLs8LYKEqSxQvOcvnThbObJ9af71EwmuE21fO5KzMW20KtAeget1gnldOosPtz1G5EwvaQ401-RPQzPGMVBld0_zMCAwZttJ4knw
			idp-certificate-authority: /root/ca.pem
			idp-issuer-url: https://oidcidp.tremolo.lan:8443/auth/idp/OidcIdP
			refresh-token: q1bKLFOyUiosTfawzA93TzZIDzH2TNa2SMm0zEiPKTUwME6BkEo6Sql5yUWVBSWpKUGphaWpxSVAfekBOZbBhaEW+VlFUeVRGcluyVF5JT4+haZmPsluFoFu5XkpXk5BXq

*/

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
			// ------------------------------------------------ Prepare some values
			// As the target structure require a path for the issuer CA, we must save it in some place.
			issuerCaPath, err := saveIssuerCA(kubeConfigResponse.Oidc.IssuerURL, kubeConfigResponse.Oidc.IssuerCaData)
			if err != nil {
				return err
			}
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
			configAccess := kubeConfig.ConfigAccess()

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
				return fmt.Errorf("context %s already exists in this config file (%s)", contextName, configAccess.GetDefaultFilename())
			}
			if _, ok := rawConfig.Clusters[clusterName]; ok && !configParams.force {
				return fmt.Errorf("cluster '%s' already existing in this config file (%s)\n", clusterName, configAccess.GetDefaultFilename())
			}
			if _, ok := rawConfig.AuthInfos[userName]; ok && !configParams.force {
				return fmt.Errorf("user '%s' already existing in this config file (%s)\n", userName, configAccess.GetDefaultFilename())
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
			rawConfig.AuthInfos[userName] = &api.AuthInfo{
				AuthProvider: &api.AuthProviderConfig{
					Name: "oidc",
					Config: map[string]string{
						"issuer-url":                kubeConfigResponse.Oidc.IssuerURL,
						"client-id":                 kubeConfigResponse.Oidc.ClientId,
						"client-secret":             kubeConfigResponse.Oidc.ClientSecret,
						"idp-certificate-authority": issuerCaPath,
						"id-token":                  "wait for login",
						"refresh-token":             "wait for login",
					},
				},
			}
			return clientcmd.ModifyConfig(configAccess, rawConfig, false)
		}()
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			os.Exit(1)
		}

	},
}

func saveIssuerCA(issuerURL string, issuerCaData string) (string, error) {
	// ----------------- Build the path
	usr, err := osuser.Current()
	if err != nil {
		return "", err
	}
	dashed := strings.Replace(strings.Replace(strings.Replace(issuerURL, ":", "-", -1), "/", "-", -1), ".", "-", -1)
	caPath := filepath.Join(usr.HomeDir, ".kube/cache/kubauth/issuers-ca", dashed, "cert.pem")
	err = misc.EnsureDir(filepath.Dir(caPath))
	if err != nil {
		return "", err
	}
	issuerCa, err := base64.StdEncoding.DecodeString(issuerCaData)
	if err != nil {
		return "", err
	}
	err = os.WriteFile(caPath, issuerCa, 0644)
	if err != nil {
		return "", err
	}
	return caPath, nil
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
