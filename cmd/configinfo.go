package cmd

import (
	"fmt"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

type configInfo struct {
	issuerURL             string
	insecureSkipTlsVerify bool
	caData                string
	standalone            bool
	idToken               string
	refreshToken          string
}

func getConfigInfo(kubeconfig string, contextName string, logger *slog.Logger) (*configInfo, error) {
	kubeconfigPath := os.Getenv("KUBECONFIG")
	if kubeconfigPath == "" {
		kubeconfigPath = clientcmd.RecommendedHomeFile
	}
	// Load the raw kubeconfig
	rawConfig, err := clientcmd.LoadFromFile(kubeconfigPath)
	if err != nil {
		logger.Debug("No kubernetes configuration found.")
		return nil, nil // No k8s config is a normal case
	}

	// Access the AuthInfo
	if contextName == "" {
		contextName = rawConfig.CurrentContext
	}
	if contextName == "" {
		return nil, fmt.Errorf("context not found in %s", kubeconfigPath)
	}

	authInfoName := rawConfig.Contexts[contextName].AuthInfo
	if authInfoName == "" {
		return nil, fmt.Errorf("auth info not found in context %s of %s", contextName, kubeconfigPath)
	}
	authInfo := rawConfig.AuthInfos[authInfoName]

	configInfo := &configInfo{}

	if authInfo.Exec != nil && authInfo.Exec.Command == "kubectl" && authInfo.Exec.Args != nil && len(authInfo.Exec.Args) > 0 && authInfo.Exec.Args[0] == "oidc-login" {
		logger.Debug("Using OIDC Exec Provider")
		for _, arg := range authInfo.Exec.Args[1:] {
			a := strings.Split(arg, "=")
			if len(a) == 2 {
				switch a[0] {
				case "--oidc-issuer-url":
					configInfo.issuerURL = a[1]
				case "--certificate-authority-data":
					configInfo.caData = a[1]
				case "--insecure-skip-tls-verify":
					configInfo.insecureSkipTlsVerify = a[1] == "true"
				}
			}
		}
		configInfo.standalone = false
		return configInfo, nil
	}
	if authInfo.AuthProvider != nil && authInfo.AuthProvider.Name == "oidc" {
		config := authInfo.AuthProvider.Config
		if config != nil {
			logger.Debug("Using OIDC Auth Provider")
			configInfo.issuerURL = config["idp-issuer-url"]
			configInfo.caData = config["idp-certificate-authority-data"]
			configInfo.idToken = config["idp-token"]
			configInfo.refreshToken = config["refresh-token"]
			configInfo.insecureSkipTlsVerify = false
			configInfo.standalone = true
			return configInfo, nil
		}
	}
	logger.Debug("No OIDC Auth Provider nor Exec Provider")
	return nil, nil
}

func getConfigInfoOld(kubeconfig string, logger *slog.Logger) *configInfo {
	configInfo := &configInfo{}
	restConfig, err := GetRestConfig(kubeconfig)
	if err != nil {
		logger.Debug("Error getting rest config", "error", err)
		return nil
	}
	logger.Debug("getConfigInfo", "authProvider", restConfig.AuthProvider, "exec", restConfig.ExecProvider)
	if restConfig.AuthProvider != nil && restConfig.AuthProvider.Name == "oidc" {
		config := restConfig.AuthProvider.Config
		if config != nil {
			logger.Debug("Using OIDC Auth Provider")
			configInfo.issuerURL = config["idp-issuer-url"]
			configInfo.caData = config["idp-certificate-authority-data"]
			configInfo.idToken = config["idp-token"]
			configInfo.refreshToken = config["refresh-token"]
			configInfo.insecureSkipTlsVerify = false
			configInfo.standalone = true
			return configInfo
		}
	}
	if restConfig.ExecProvider != nil && restConfig.ExecProvider.Command == "kubectl" && restConfig.ExecProvider.Args[0] == "oidc-config" {
		logger.Debug("Using OIDC Exec Provider")
		for _, arg := range restConfig.ExecProvider.Args[1:] {
			a := strings.Split(arg, "=")
			if len(a) == 2 {
				switch a[0] {
				case "--oidc-issuer-url":
					configInfo.issuerURL = a[1]
				case "--certificate-authority-data":
					configInfo.caData = a[1]
				case "--insecure-skip-tls-verify":
					configInfo.insecureSkipTlsVerify = a[1] == "true"
				}
			}
		}
		configInfo.standalone = false
		return configInfo
	}
	logger.Debug("No OIDC Auth Provider nor Exec Provider")
	return nil
}

func GetRestConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	config, err := rest.InClusterConfig()
	if err != nil {
		// fallback to kubeconfig
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("unable to locate home directory: %w", err)
		}
		kubeconfig := filepath.Join(home, ".kube", "config")
		if envVar := os.Getenv("KUBECONFIG"); len(envVar) > 0 {
			kubeconfig = envVar
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("unable to build kubernetes config: %w", err)
		}
	}
	return config, nil
}
