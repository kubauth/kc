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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"getok/global"
	"getok/internal/misc"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var jwtdCmd = &cobra.Command{
	Use:   "jwtd [jwt-token]",
	Short: "Decode and display JWT token content in pretty JSON",
	Long: `Decode and display JWT token content in pretty JSON format.
The JWT token can be provided as a command line argument or read from stdin.

Examples:
  getok jwtd eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
  echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." | getok jwtd`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		err := setupJwtd()
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

		global.Logger.Debug("Decoding JWT token", "length", len(jwtToken))

		// Decode and display JWT
		err = decodeAndDisplayJWT(jwtToken)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error decoding JWT: %v\n", err)
			os.Exit(1)
		}
	},
}

// decodeAndDisplayJWT decodes a JWT token and displays its header and payload in pretty JSON
func decodeAndDisplayJWT(token string) error {
	// Split JWT into parts (header.payload.signature)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format: expected 3 parts separated by '.', got %d", len(parts))
	}

	// Decode header
	header, err := decodeJWTPart(parts[0])
	if err != nil {
		return fmt.Errorf("failed to decode JWT header: %w", err)
	}

	// Decode payload
	payload, err := decodeJWTPart(parts[1])
	if err != nil {
		return fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Display results
	fmt.Println("JWT Header:")
	fmt.Println(header)
	fmt.Println()
	fmt.Println("JWT Payload:")
	fmt.Println(payload)

	global.Logger.Debug("JWT decoded successfully")
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

	prettyJSON, err := json.MarshalIndent(jsonData, "", "  ")
	if err != nil {
		return "", fmt.Errorf("JSON formatting failed: %w", err)
	}

	return string(prettyJSON), nil
}

// setupJwtd initializes minimal configuration needed for jwtd command
func setupJwtd() error {
	var err error
	// Only setup logging, no need for OIDC/OAuth2 configuration
	logConfig := misc.LogConfig{
		Mode:  "text",
		Level: "INFO",
	}
	
	global.Logger, err = misc.NewLogger(&logConfig)
	if err != nil {
		return fmt.Errorf("could not create logger: %w", err)
	}
	
	return nil
}
