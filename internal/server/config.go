package server

import (
	"strconv"
	"strings"

	"ebpf-mcp/internal/logx"
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
		return logx.Wrapf(logx.ErrInvalidTransport, "invalid transport %q", c.Transport)
	}

	if transport == TransportHTTP {
		if strings.TrimSpace(c.AuthToken) == "" {
			return logx.ErrAuthTokenRequired
		}
		if strings.TrimSpace(c.HTTPPort) == "" {
			return logx.ErrHTTPPortRequired
		}
		if _, err := strconv.Atoi(c.HTTPPort); err != nil {
			return logx.NewDomainErrorWithCause(logx.ErrorInvalidConfig, "invalid http port", err)
		}
	}

	return nil
}
