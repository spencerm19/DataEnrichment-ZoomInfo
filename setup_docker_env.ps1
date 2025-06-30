# Disable TLS verification
$env:DOCKER_TLS_VERIFY = ""
$env:COMPOSE_TLS_VERSION = ""
$env:NODE_TLS_REJECT_UNAUTHORIZED = "0"

# Set proxy settings
$env:DOCKER_BUILDKIT = "1"
$env:COMPOSE_DOCKER_CLI_BUILD = "1"
$env:HTTP_PROXY = "http://http.docker.internal:3128"
$env:HTTPS_PROXY = "http://http.docker.internal:3128"
$env:NO_PROXY = "hubproxy.docker.internal"

# Set Docker config
$env:DOCKER_CONFIG = "$HOME\.docker"
$env:DOCKER_REGISTRY_MIRROR = "http://hubproxy.docker.internal:5555"

Write-Host "Environment variables set for Docker build" 