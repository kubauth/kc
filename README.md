# kc - Kubauth Companion Tool

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-1.24.6+-00ADD8?logo=go)](https://golang.org/)

`kc` is an OIDC (OpenID Connect) client tool designed to fetch access tokens and ID tokens from OIDC providers. It supports multiple authentication flows and provides convenient utilities for token management and JWT inspection.

## Features

- **Multiple Authentication Flows**:
  - Authorization Code Flow with optional PKCE (browser-based)
  - Resource Owner Password Credentials (ROPC) flow (username/password)
- **JWT Token Inspection**: Decode and display JWT tokens with human-readable timestamps
- **Secure Token Handling**: Support for custom CA certificates and SSL/TLS verification
- **Browser Integration**: Automatic browser launching with support for Chrome, Firefox, and Safari
- **Logout Support**: Automatic discovery and opening of OIDC end session endpoints
- **Flexible Output**: Output specific tokens (access/ID) or full token information

## Installation

### Download Pre-built Binary

Download the latest release from GitHub:

```bash
# Download the latest release (replace with your OS/architecture)
curl -L -o kc https://github.com/kubauth/kc/releases/download/0.1.0/kc-linux-amd64

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

Visit [releases page](https://github.com/kubauth/kc/releases/tag/0.1.0) for all available downloads.

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

## Usage

### Basic Configuration

`kc` can be configured using command-line flags or environment variables:

| Flag | Environment Variable | Description |
|------|---------------------|-------------|
| `--issuerURL`, `-i` | `KC_ISSUER_URL` | OIDC issuer URL |
| `--clientId`, `-c` | `KC_CLIENT_ID` | OAuth2 client ID |
| `--clientSecret`, `-s` | `KC_CLIENT_SECRET` | OAuth2 client secret (optional for public clients) |

### Commands

#### 1. UI-based Authentication (`ui`)

Perform authentication using the authorization code flow with a browser:

```bash
# Basic usage
kc ui --issuerURL https://your-oidc-provider.com --clientId your-client-id

# With PKCE (recommended for enhanced security)
kc ui --issuerURL https://your-oidc-provider.com --clientId your-client-id --pkce

# Specify browser
kc ui --issuerURL https://your-oidc-provider.com --clientId your-client-id --browser chrome

# Custom port for local callback server
kc ui --issuerURL https://your-oidc-provider.com --clientId your-client-id --bindPort 8080
```

**Options:**
- `--pkce`: Enable PKCE (Proof Key for Code Exchange) for enhanced security
- `--bindPort`, `-p`: Local server bind port (default: 9921)
- `--browser`: Browser to use (`chrome`, `firefox`, `safari`, or default system browser)
- `--scope`: Requested scopes (default: `["openid", "profile"]`)

#### 2. No-UI Authentication (`noui`)

Perform authentication using username and password (ROPC flow):

```bash
# Interactive (prompts for credentials)
kc noui --issuerURL https://your-oidc-provider.com --clientId your-client-id

# With credentials as flags
kc noui --issuerURL https://your-oidc-provider.com --clientId your-client-id --login user@example.com --password mypassword

# Using environment variables
export KC_USER_LOGIN=user@example.com
export KC_USER_PASSWORD=mypassword
kc noui --issuerURL https://your-oidc-provider.com --clientId your-client-id
```

**Options:**
- `--login`, `-u`: Username (or use `KC_USER_LOGIN` environment variable)
- `--password`, `-p`: Password (or use `KC_USER_PASSWORD` environment variable)

#### 3. JWT Token Inspection (`jwt`)

Decode and display JWT token content in pretty JSON format:

```bash
# From command line argument
kc jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# From stdin
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." | kc jwt

# Pipe from other commands
kc noui --onlyIDToken --issuerURL https://provider.com --clientId abc123 | kc jwt
```

The JWT decoder automatically adds human-readable timestamps for standard claims like `exp`, `iat`, `nbf`, `auth_time`, etc.

#### 4. Logout (`logout`)

Open browser to the OIDC provider's logout endpoint:

```bash
kc logout --issuerURL https://your-oidc-provider.com

# With specific browser
kc logout --issuerURL https://your-oidc-provider.com --browser firefox
```

#### 5. Version Information (`version`)

Display version information:

```bash
# Basic version
kc version

# Extended version with build timestamp
kc version --extended
```

### Output Options

Control token output format:

```bash
# Output only the access token
kc ui --onlyAccessToken --issuerURL https://provider.com --clientId abc123

# Output only the ID token
kc noui --onlyIDToken --issuerURL https://provider.com --clientId abc123

# Default: output all tokens with labels
kc ui --issuerURL https://provider.com --clientId abc123
```

### Security Options

#### Custom CA Certificates

```bash
kc ui --issuerURL https://provider.com --clientId abc123 --caFile /path/to/ca.pem
```

#### Skip TLS Verification (Development Only)

```bash
kc ui --issuerURL https://provider.com --clientId abc123 --insecureSkipVerify
```

**⚠️ Warning**: Only use `--insecureSkipVerify` in development environments.

### Logging and Debugging

Control logging behavior:

```bash
# Debug level logging
kc ui --logLevel DEBUG --issuerURL https://provider.com --clientId abc123

# JSON logging format
kc ui --logMode json --issuerURL https://provider.com --clientId abc123

# Dump HTTP exchanges for debugging
kc ui --dumpClientExchanges --issuerURL https://provider.com --clientId abc123
```

## Environment Variables

Set these environment variables to avoid repeating common flags:

```bash
export KC_ISSUER_URL=https://your-oidc-provider.com
export KC_CLIENT_ID=your-client-id
export KC_CLIENT_SECRET=your-client-secret  # Optional for public clients
export KC_USER_LOGIN=user@example.com       # For noui command
export KC_USER_PASSWORD=mypassword          # For noui command
```

## Examples

### Complete Workflow Examples

#### 1. Get tokens using browser (recommended)

```bash
# Set up environment
export KC_ISSUER_URL=https://auth.example.com
export KC_CLIENT_ID=my-client-id

# Get tokens with PKCE
kc ui --pkce

# Expected output:
# Access token: eyJhbGciOiJSUzI1NiIs...
# Refresh token: eyJhbGciOiJSUzI1NiIs...
# ID token: eyJhbGciOiJSUzI1NiIs...
# Expire in: 1h0m0s
```

#### 2. Script-friendly token retrieval

```bash
# Get only access token for API calls
ACCESS_TOKEN=$(kc noui --onlyAccessToken --login user@example.com --password mypass)

# Use in API calls
curl -H "Authorization: Bearer $ACCESS_TOKEN" https://api.example.com/data
```

#### 3. JWT inspection workflow

```bash
# Get ID token and inspect it
ID_TOKEN=$(kc ui --onlyIDToken --pkce)
echo $ID_TOKEN | kc jwt

# Expected output:
# JWT Header:
# {
#   "alg": "RS256",
#   "typ": "JWT",
#   "kid": "abc123"
# }
# 
# JWT Payload:
# {
#   "sub": "user123",
#   "aud": "my-client-id",
#   "exp": 1704067200,
#   "exp_human": "2024-01-01 00:00:00 UTC",
#   "iat": 1704063600,
#   "iat_human": "2023-12-31 23:00:00 UTC"
# }
```

#### 4. Complete session with logout

```bash
# 1. Authenticate
kc ui --pkce

# 2. Use tokens for your application...

# 3. Logout when done
kc logout
```

## Configuration Files

For repeated usage, consider creating shell scripts or aliases:

```bash
# ~/.bashrc or ~/.zshrc
alias kc-dev='kc ui --issuerURL https://dev-auth.company.com --clientId dev-client --pkce'
alias kc-prod='kc ui --issuerURL https://auth.company.com --clientId prod-client --pkce'
```

## Troubleshooting

### Common Issues

1. **"issuer URL cannot be empty"**
   - Set `--issuerURL` flag or `KC_ISSUER_URL` environment variable

2. **"client ID cannot be empty"**
   - Set `--clientId` flag or `KC_CLIENT_ID` environment variable

3. **Certificate verification errors**
   - Use `--caFile` to specify custom CA certificates
   - For development only: use `--insecureSkipVerify`

4. **Browser doesn't open automatically**
   - The callback URL will be displayed in the terminal
   - Manually open the URL in your browser
   - Try specifying a specific browser with `--browser`

5. **Port already in use**
   - Change the callback port with `--bindPort <port>`

### Debug Mode

Enable debug logging for detailed troubleshooting:

```bash
kc ui --logLevel DEBUG --dumpClientExchanges --issuerURL https://provider.com --clientId abc123
```

## Security Considerations

- **PKCE**: Always use `--pkce` flag with the `ui` command for enhanced security
- **Client Secrets**: Avoid passing client secrets on the command line in production; use environment variables
- **ROPC Flow**: The `noui` command uses Resource Owner Password Credentials flow, which is less secure than authorization code flow
- **TLS**: Never use `--insecureSkipVerify` in production environments

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Copyright

Copyright 2025 Kubotal

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.