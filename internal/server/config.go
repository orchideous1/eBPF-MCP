package server

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	// TransportStdio starts MCP over stdin/stdout.
	TransportStdio = "stdio"
	// TransportHTTP starts MCP over streamable HTTP.
	TransportHTTP = "http"
)

// ServerConfig describes protocol access configuration.
type ServerConfig struct {
	Transport string
	HTTPPort  string
	AuthToken string
	Debug     bool
}

// Validate checks whether the server config is safe and complete.
func (c ServerConfig) Validate() error {
	transport := strings.TrimSpace(c.Transport)
	if transport == "" {
		transport = TransportStdio
	}

	if transport != TransportStdio && transport != TransportHTTP {
		return fmt.Errorf("invalid transport %q", c.Transport)
	}

	if transport == TransportHTTP {
		if strings.TrimSpace(c.AuthToken) == "" {
			return fmt.Errorf("auth token is required for http transport")
		}
		if strings.TrimSpace(c.HTTPPort) == "" {
			return fmt.Errorf("http port is required for http transport")
		}
		if _, err := strconv.Atoi(c.HTTPPort); err != nil {
			return fmt.Errorf("invalid http port %q: %w", c.HTTPPort, err)
		}
	}

	return nil
}
