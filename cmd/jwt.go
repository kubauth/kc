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
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"kc/internal/misc"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
)

var jwtdParams struct {
	logConfig misc.LogConfig
}

func init() {
	jwtCmd.PersistentFlags().StringVar(&jwtdParams.logConfig.Mode, "logMode", "text", "Log mode ('text' or 'json')")
	jwtCmd.PersistentFlags().StringVarP(&jwtdParams.logConfig.Level, "logLevel", "l", "INFO", "Log level(DEBUG, INFO, WARN, ERROR)")
}

// setupJwtd initializes minimal configuration needed for jwtd command
func setupJwt() (*slog.Logger, error) {
	logger, err := misc.NewLogger(&jwtdParams.logConfig)
	if err != nil {
		return nil, fmt.Errorf("could not create logger: %w", err)
	}
	return logger, nil
}

var jwtCmd = &cobra.Command{
	Use:   "jwt [jwt-token]",
	Short: "Decode and display JWT token content in pretty JSON",
	Long: `Decode and display JWT token content in pretty JSON format.
The JWT token can be provided as a command line argument or read from stdin.

Examples:
  kc jwtd eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
  echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." | kc jwtd`,

	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		logger, err := setupJwt()
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		var jwtToken string

		// Get JWT token from args or stdin
		if len(args) > 0 {
			jwtToken = args[0]
		} else {
			// Read from stdin
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				jwtToken = strings.TrimSpace(scanner.Text())
			}
			if err := scanner.Err(); err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
				os.Exit(1)
			}
		}

		if jwtToken == "" {
			_, _ = fmt.Fprintln(os.Stderr, "No JWT token provided. Please provide a token as argument or via stdin.")
			os.Exit(1)
		}

		logger.Debug("Decoding JWT token", "length", len(jwtToken))

		// Decode and display JWT
		err = decodeAndDisplayJWT("Token", jwtToken, false)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error decoding JWT: %v\n", err)
			os.Exit(1)
		}
		logger.Debug("JWT decoded successfully")
	},
}

func decodeJWT(token string) (header string, payload string, err error) {
	// Split JWT into parts (header.payload.signature)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("invalid JWT format: expected 3 parts separated by '.', got %d", len(parts))
	}

	// Decode header
	header, err = decodeJWTPart(parts[0])
	if err != nil {
		return "", "", fmt.Errorf("failed to decode JWT header: %w", err)
	}

	// Decode payload
	payload, err = decodeJWTPart(parts[1])
	if err != nil {
		return header, "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}
	return header, payload, nil
}

// decodeAndDisplayJWT decodes a JWT token and displays its header and payload in pretty JSON
func decodeAndDisplayJWT(name string, token string, onlyPayload bool) error {
	header, payload, err := decodeJWT(token)
	if err != nil {
		return err
	}
	// Display results
	if !onlyPayload {
		fmt.Printf("%s: JWT Header:\n", name)
		fmt.Println(header)
		fmt.Println()
	}
	fmt.Printf("%s: JWT Payload:\n", name)
	fmt.Println(payload)

	return nil
}

// decodeJWTPart decodes a base64url encoded JWT part and returns it as pretty JSON
func decodeJWTPart(part string) (string, error) {
	// Add padding if necessary for base64url decoding
	switch len(part) % 4 {
	case 2:
		part += "=="
	case 3:
		part += "="
	}

	// Base64url decode
	decoded, err := base64.URLEncoding.DecodeString(part)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed: %w", err)
	}

	// Parse as JSON and format prettily
	var jsonData interface{}
	if err := json.Unmarshal(decoded, &jsonData); err != nil {
		return "", fmt.Errorf("JSON parse failed: %w", err)
	}

	// Enhance with human-readable timestamps
	enhancedData := enhanceWithTimestamps(jsonData)

	prettyJSON, err := json.MarshalIndent(enhancedData, "", "  ")
	if err != nil {
		return "", fmt.Errorf("JSON formatting failed: %w", err)
	}
	return string(prettyJSON), nil
}

// enhanceWithTimestamps adds human-readable date strings for known timestamp claims
func enhanceWithTimestamps(data interface{}) interface{} {
	// List of known timestamp claims in JWT
	timestampClaims := map[string]bool{
		"exp":        true, // Expiration time
		"iat":        true, // Issued at
		"nbf":        true, // Not before
		"auth_time":  true, // Authentication time
		"rat":        true, // Refresh token issued at (some providers)
		"updated_at": true, // Profile updated at (some providers)
	}

	switch v := data.(type) {
	case map[string]interface{}:
		enhanced := make(map[string]interface{})
		for key, value := range v {
			enhanced[key] = enhanceWithTimestamps(value)

			// Check if this is a timestamp claim
			if timestampClaims[key] {
				if timestamp, ok := value.(float64); ok && timestamp > 0 {
					// Convert Unix timestamp to human-readable date
					t := time.Unix(int64(timestamp), 0).UTC()
					enhanced[key+"_human"] = t.Format("2006-01-02 15:04:05 UTC")
				}
			}
		}
		return enhanced
	case []interface{}:
		enhanced := make([]interface{}, len(v))
		for i, item := range v {
			enhanced[i] = enhanceWithTimestamps(item)
		}
		return enhanced
	default:
		return v
	}
}

// verifyIDToken verifies the ID token using go-oidc verifier
func verifyIDToken(ctx context.Context, provider *oidc.Provider, idToken, clientID string) error {
	logger := logr.FromContextAsSlogLogger(ctx)

	// Create ID token verifier
	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	// Verify the ID token
	token, err := verifier.Verify(ctx, idToken)
	if err != nil {
		return fmt.Errorf("ID token verification failed: %w", err)
	}

	logger.Debug("ID token verified", "subject", token.Subject, "issuer", token.Issuer, "audience", token.Audience)

	return nil
}
