# kc - Kubauth Companion Tool

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-1.24.6+-00ADD8?logo=go)](https://golang.org/)

`kc` is a comprehensive OIDC (OpenID Connect) client tool that serves two main purposes:

1. **Token Management**: Obtain OIDC tokens for injection into applications and services
2. **Kubernetes Authentication**: Integrate with kubectl and kubelogin for cluster authentication

## Features

### Token Management
- **Multiple Authentication Flows**:
  - Authorization Code Flow with optional PKCE (browser-based)
  - Resource Owner Password Credentials (ROPC) flow (username/password)
- **Token Output**: Clean token output suitable for scripting and application integration
- **JWT Token Inspection**: Decode and display JWT tokens with human-readable timestamps
- **Secure Token Handling**: Support for custom CA certificates and SSL/TLS verification
- **Browser Integration**: Automatic browser launching with support for Chrome, Firefox, and Safari

### Kubernetes Integration  
- **Automatic kubeconfig configuration**: Works with [okit](https://github.com/kubauth/okit) configuration services
- **kubectl/kubelogin Integration**: Support for both kubelogin and native OIDC auth providers
- **User Identity Management**: Display current authenticated user information from JWT tokens
- **Context and cluster management**: Handle multiple Kubernetes clusters and contexts

### Additional Utilities
- **Security Utilities**: BCrypt hash generation for secrets and passwords
- **Logout Support**: Automatic discovery and opening of OIDC end session endpoints

## Installation

### Download Pre-built Binary

Download the latest release from GitHub:

```bash
# Download the latest release (replace with your OS/architecture)
curl -L -o kc https://github.com/kubauth/kc/releases/download/0.1.1/kc-linux-amd64

# Make it executable
chmod +x kc

# Move to your PATH (optional)
sudo mv kc /usr/local/bin/
```

**Available binaries:**
- `kc-linux-amd64` - Linux 64-bit
- `kc-darwin-amd64` - macOS Intel
- `kc-darwin-arm64` - macOS Apple Silicon
- `kc-windows-amd64.exe` - Windows 64-bit

Visit [releases page](https://github.com/kubauth/kc/releases/tag/0.1.1) for all available downloads.

### Building from Source

```bash
# Clone the repository
git clone https://github.com/kubauth/kc.git
cd kc

# Build the binary
make build

# The binary will be available at bin/kc
```

### Prerequisites

- Go 1.24.6 or later (for building from source)
- Internet connection for OIDC provider communication
- kubectl (for Kubernetes integration features)

## Usage

### Basic Configuration

`kc` can be configured using command-line flags, environment variables, or by automatically reading from your kubeconfig:

| Flag | Environment Variable | Description |
|------|---------------------|-------------|
| `--issuerURL`, `-i` | `KC_ISSUER_URL` | OIDC issuer URL |
| `--clientId`, `-c` | `KC_CLIENT_ID` | OAuth2 client ID |
| `--clientSecret`, `-s` | `KC_CLIENT_SECRET` | OAuth2 client secret (optional for public clients) |
| `--kubeconfig` | `KUBECONFIG` | Path to kubeconfig file for automatic configuration |
| `--context` | - | Specific context in kubeconfig to use |

### Commands

`kc` provides two groups of commands:

## Token Management Commands

These commands are designed to obtain OIDC tokens for injection into applications and services. They can work independently or optionally use kubeconfig for convenience.

#### 1. Browser-based Authentication (`token`)

Obtain tokens using the authorization code flow with a browser:

```bash
# Basic usage
kc token --issuerURL https://your-oidc-provider.com --clientId your-client-id

# With PKCE (recommended for enhanced security)
kc token --issuerURL https://your-oidc-provider.com --clientId your-client-id --pkce

# Specify browser
kc token --issuerURL https://your-oidc-provider.com --clientId your-client-id --browser chrome

# Custom port for local callback server
kc token --issuerURL https://your-oidc-provider.com --clientId your-client-id --bindPort 8080

# Optional: Use kubeconfig for convenience (auto-fills issuer URL and client ID)
kc token --context my-cluster
```

**Primary Use Cases:**
- Getting tokens for application authentication
- Scripting with OIDC-enabled services
- Testing OIDC integrations

**Options:**
- `--pkce`: Enable PKCE (Proof Key for Code Exchange) for enhanced security
- `--bindPort`, `-p`: Local server bind port (default: 9921)
- `--browser`: Browser to use (`chrome`, `firefox`, `safari`, or default system browser)
- `--scope`: Requested scopes (default: `["openid", "profile", "offline"]`)
- `--detailIDToken`, `-d`: Display detailed ID token information after authentication

#### 2. No-UI Authentication (`token-nui`)

Obtain tokens using username and password (ROPC flow):

```bash
# Interactive (prompts for credentials)
kc token-nui --issuerURL https://your-oidc-provider.com --clientId your-client-id

# With credentials as flags
kc token-nui --issuerURL https://your-oidc-provider.com --clientId your-client-id --login user@example.com --password mypassword

# Using environment variables
export KC_USER_LOGIN=user@example.com
export KC_USER_PASSWORD=mypassword
kc token-nui --issuerURL https://your-oidc-provider.com --clientId your-client-id

# Optional: Use kubeconfig for convenience
kc token-nui --context my-cluster --login user@example.com
```

**Primary Use Cases:**
- Automated scripts and CI/CD pipelines
- Headless environments without browser access
- Service account authentication

**Options:**
- `--login`, `-u`: Username (or use `KC_USER_LOGIN` environment variable)
- `--password`, `-p`: Password (or use `KC_USER_PASSWORD` environment variable)
- `--detailIDToken`, `-d`: Display detailed ID token information after authentication

## Kubernetes Integration Commands

These commands are specifically designed to work with kubectl and kubelogin for Kubernetes cluster authentication.

#### 3. Kubernetes Configuration (`config`)

Initialize or update kubeconfig for OIDC authentication. Requires a configuration service (see [okit](https://github.com/kubauth/okit)):

```bash
# Configure from an okit-compatible configuration service
kc config https://kubauth.example.com/config

# With custom context name
kc config https://kubauth.example.com/config --contextNameOverride my-cluster

# Override specific settings
kc config https://kubauth.example.com/config \
  --apiServerURLOverride https://k8s-api.example.com:6443 \
  --namespaceOverride production

# Use standalone OIDC auth provider (no kubelogin)
kc config https://kubauth.example.com/config --standalone

# Configure with specific grant type and PKCE settings
kc config https://kubauth.example.com/config \
  --grantType authcode \
  --pkce S256

# Don't switch to the new context automatically
kc config https://kubauth.example.com/config --noContextSwitch
```

**Primary Use Cases:**
- Setting up kubectl authentication for new clusters
- Configuring OIDC authentication for team members
- Managing multiple cluster configurations

**Options:**
- `--contextNameOverride`: Override the context name
- `--apiServerURLOverride`: Override the Kubernetes API server URL
- `--issuerURLOverride`: Override the OIDC issuer URL
- `--namespaceOverride`: Override the default namespace
- `--force`: Override existing context/cluster/user configurations
- `--noContextSwitch`: Don't set the new context as default
- `--standalone`: Use built-in OIDC auth provider instead of kubelogin
- `--grantType`: Grant type (`auto`, `authcode`, `password`) (default: `auto`)
- `--pkce`: PKCE method (`auto`, `no`, `S256`) (default: `auto`)
- `--scope`: Additional scopes beyond the defaults

#### 4. User Identity (`whoami`)

Display information about the current authenticated Kubernetes user. This command works after the user has been authenticated through kubectl/kubelogin:

```bash
# Basic usage (reads from kubelogin cache or kubeconfig)
kc whoami

# With detailed ID token information
kc whoami --detailed

# Specific kubeconfig file and context
kc whoami --kubeconfig ~/.kube/config-prod --context prod-cluster
```

**Primary Use Cases:**
- Verifying current Kubernetes authentication status
- Debugging kubectl authentication issues
- Checking token expiration

**Prerequisites:** User must be authenticated through kubectl/kubelogin first.

**Options:**
- `--detailed`, `-d`: Show detailed ID token payload
- `--kubeconfig`: Specify kubeconfig file path
- `--context`: Specify context within kubeconfig

## Utility Commands

#### 5. JWT Token Inspection (`jwt`)

Decode and display JWT token content in pretty JSON format:

```bash
# From command line argument
kc jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# From stdin
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." | kc jwt

# Pipe from token commands
kc token-nui --onlyIDToken --issuerURL https://provider.com --clientId abc123 | kc jwt
```

The JWT decoder automatically adds human-readable timestamps for standard claims like `exp`, `iat`, `nbf`, `auth_time`, etc.

#### 6. Hash Generation (`hash`)

Generate BCrypt hashes for Kubauth user passwords and OIDC client secrets:

```bash
# Generate hash for a secret
kc hash my-secret-password

# Example output shows usage in Kubauth resources
kc hash mypassword123
# Secret: mypassword123
# Hash: $2a$12$example...
# 
# Use this hash in your User 'passwordHash' field
# ...
```

#### 7. Logout (`logout`)

Open browser to the OIDC provider's logout endpoint and clear kubectl/kubelogin authentication:

```bash
kc logout --issuerURL https://your-oidc-provider.com

# With specific browser
kc logout --issuerURL https://your-oidc-provider.com --browser firefox

# Optional: Use kubeconfig for convenience
kc logout --context my-cluster
```

**Note:** This command will also clear any cached kubectl/kubelogin authentication tokens.

#### 8. Version Information (`version`)

Display version information:

```bash
# Basic version
kc version

# Extended version with build timestamp
kc version --extended
```

### Output Options

Control token output format for token management commands:

```bash
# Output only the access token (for application integration)
kc token --onlyAccessToken --issuerURL https://provider.com --clientId abc123

# Output only the ID token (for identity verification)
kc token-nui --onlyIDToken --issuerURL https://provider.com --clientId abc123

# Default: output all tokens with labels
kc token --issuerURL https://provider.com --clientId abc123

# Show detailed ID token information inline
kc token --detailIDToken --issuerURL https://provider.com --clientId abc123

# Optional: Use kubeconfig for convenience (auto-fills parameters)
kc token --onlyAccessToken --context my-cluster
```

### Security Options

#### Custom CA Certificates

```bash
kc token --issuerURL https://provider.com --clientId abc123 --caFile /path/to/ca.pem
```

#### Skip TLS Verification (Development Only)

```bash
kc token --issuerURL https://provider.com --clientId abc123 --insecureSkipVerify
```

**⚠️ Warning**: Only use `--insecureSkipVerify` in development environments.

### Logging and Debugging

Control logging behavior:

```bash
# Debug level logging
kc token --logLevel DEBUG --context my-cluster

# JSON logging format
kc token --logMode json --context my-cluster

# Dump HTTP exchanges for debugging
kc token --dumpClientExchanges --context my-cluster
```

## Environment Variables

Set these environment variables to avoid repeating common flags:

```bash
export KC_ISSUER_URL=https://your-oidc-provider.com
export KC_CLIENT_ID=your-client-id
export KC_CLIENT_SECRET=your-client-secret  # Optional for public clients
export KC_USER_LOGIN=user@example.com       # For token-nui command
export KC_USER_PASSWORD=mypassword          # For token-nui command
export KUBECONFIG=~/.kube/config            # For automatic kubeconfig integration
```

## Complete Workflow Examples

### 1. Token Management for Applications

```bash
# Get ID token for application authentication
ID_TOKEN=$(kc token --onlyIDToken --issuerURL https://auth.example.com --clientId app-client-id)

# Use ID token in application API calls
curl -H "Authorization: Bearer $ID_TOKEN" https://api.example.com/data

# For CI/CD pipelines (headless)
ID_TOKEN=$(kc token-nui --onlyIDToken \
  --issuerURL https://auth.example.com \
  --clientId ci-client-id \
  --login service-account@example.com \
  --password "$SERVICE_PASSWORD")

# Use ID token for service authentication
curl -H "Authorization: Bearer $ID_TOKEN" https://internal-service.example.com/api
```

### 2. JWT Token Analysis

```bash
# Get ID token and inspect it
ID_TOKEN=$(kc token --onlyIDToken --issuerURL https://auth.example.com --clientId web-client)
echo $ID_TOKEN | kc jwt

# Or use the inline detailed view
kc token --detailIDToken --issuerURL https://auth.example.com --clientId web-client

# Inspect any JWT token
echo "eyJhbGciOiJSUzI1NiIs..." | kc jwt
```

### 3. Kubernetes Cluster Setup

```bash
# Configure kubeconfig from okit configuration service
kc config https://kubauth.example.com/config

# Authenticate (required before whoami)
kubectl get pods  # This will trigger authentication

# Verify configuration and check identity
kc whoami

# Now kubectl commands work with OIDC authentication
kubectl get namespaces
```

### 4. Multiple Cluster Management

```bash
# Add production cluster
kc config https://kubauth-prod.example.com/config --contextNameOverride prod

# Add development cluster  
kc config https://kubauth-dev.example.com/config --contextNameOverride dev

# Switch between clusters and authenticate
kubectl config use-context prod
kubectl get pods  # Triggers authentication
kc whoami

kubectl config use-context dev
kubectl get pods  # Triggers authentication
kc whoami
```

### 5. Administrative Tasks

```bash
# Generate password hash for Kubauth User resource
kc hash user-password123

# Check who is currently authenticated in Kubernetes
kc whoami --detailed

# Logout from OIDC provider
kc logout --issuerURL https://auth.example.com
```

### 6. Development and Testing

```bash
# Test token retrieval with debug logging
kc token --issuerURL https://dev-auth.example.com \
  --clientId dev-client \
  --insecureSkipVerify \
  --logLevel DEBUG

# Test different authentication flows
kc token-nui --issuerURL https://dev-auth.example.com \
  --clientId dev-client \
  --logLevel DEBUG
```

## Kubeconfig Integration

### Kubernetes Commands

The `config` and `whoami` commands are specifically designed for Kubernetes workflows:

- **`config`**: Sets up kubeconfig for kubectl authentication using okit-compatible configuration services
- **`whoami`**: Shows current Kubernetes user identity from kubelogin cache or kubeconfig

### Token Commands with Kubeconfig

The `token` and `token-nui` commands can optionally use kubeconfig for convenience, but are primarily designed for general OIDC token retrieval:

```bash
# Primary usage: standalone token retrieval
kc token --issuerURL https://auth.example.com --clientId app-client

# Optional: use kubeconfig for parameter convenience
kc token --context my-cluster  # auto-fills issuer URL and client ID from kubeconfig
```

### Two Authentication Modes for Kubernetes

1. **kubelogin Mode** (default): Uses kubectl-oidc-login plugin
2. **Standalone Mode**: Uses built-in OIDC authentication provider

```bash
# Configure for kubelogin (requires kubectl-oidc-login plugin)
kc config https://kubauth.example.com/config

# Configure for standalone mode (no external dependencies)
kc config https://kubauth.example.com/config --standalone
```

## Configuration Files

For repeated usage with different environments:

```bash
# ~/.bashrc or ~/.zshrc
alias kc-dev='kc token --context dev-cluster'
alias kc-prod='kc token --context prod-cluster'
alias kc-staging='kc token --context staging-cluster'

# Quick identity check
alias whoami-k8s='kc whoami'
```

## Troubleshooting

### Common Issues

1. **"issuer URL cannot be empty"**
   - Set `--issuerURL` flag, `KC_ISSUER_URL` environment variable, or ensure your kubeconfig has OIDC configuration

2. **"client ID cannot be empty"**
   - Set `--clientId` flag, `KC_CLIENT_ID` environment variable, or use `kc config` to set up kubeconfig

3. **"No kubernetes configuration found"**
   - Run `kc config` to set up kubeconfig, or specify configuration manually

4. **"context not found"**
   - List available contexts: `kubectl config get-contexts`
   - Set correct context: `kubectl config use-context <context-name>`

5. **Certificate verification errors**
   - Use `--caFile` to specify custom CA certificates
   - For development only: use `--insecureSkipVerify`

6. **Browser doesn't open automatically**
   - The callback URL will be displayed in the terminal
   - Manually open the URL in your browser
   - Try specifying a specific browser with `--browser`

7. **Port already in use**
   - Change the callback port with `--bindPort <port>`

### Debug Mode

Enable debug logging for detailed troubleshooting:

```bash
kc token --logLevel DEBUG --dumpClientExchanges --context my-cluster
```

### Cache and Token Issues

```bash
# Clear kubelogin cache if needed
rm -rf ~/.kube/cache/oidc-login

# Check current authentication status
kc whoami --detailed

# Force re-authentication
kc token --context my-cluster
```

## Security Considerations

- **PKCE**: Always use PKCE when available for enhanced security
- **Client Secrets**: Avoid passing client secrets on the command line in production; use environment variables or kubeconfig
- **ROPC Flow**: The `token-nui` command uses Resource Owner Password Credentials flow, which is less secure than authorization code flow
- **TLS**: Never use `--insecureSkipVerify` in production environments
- **Token Storage**: Be careful with token output redirection and logging in production scripts

## Integration with Kubauth

`kc` is designed to work seamlessly with [Kubauth](https://github.com/kubauth/kubauth), providing:

- Automatic kubeconfig generation via the `config` command
- BCrypt hash generation for User and OidcClient resources
- Flexible authentication flows for different use cases
- Deep integration with Kubernetes RBAC and identity management

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Copyright

Copyright 2025 Kubotal

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.