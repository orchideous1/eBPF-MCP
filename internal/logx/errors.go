package logx

import (
	"errors"
	"fmt"
)

// Level represents log severity.
type Level string

const (
	LevelDebug Level = "DEBUG"
	LevelInfo  Level = "INFO"
	LevelWarn  Level = "WARN"
	LevelError Level = "ERROR"
)

// ErrorCode is the normalized protocol error code for tool responses.
type ErrorCode string

const (
	ErrorInvalidArgument  ErrorCode = "INVALID_ARGUMENT"
	ErrorPermissionDenied ErrorCode = "PERMISSION_DENIED"
	ErrorQuotaExceeded    ErrorCode = "QUOTA_EXCEEDED"
	ErrorProbeNotFound    ErrorCode = "PROBE_NOT_FOUND"
	ErrorRuntimeFailure   ErrorCode = "RUNTIME_FAILURE"
	ErrorConflict         ErrorCode = "CONFLICT"
)

// DomainError marks service-layer errors with normalized code and level.
type DomainError struct {
	Code    ErrorCode
	Level   Level
	Message string
}

// Error implements error.
func (e *DomainError) Error() string {
	return e.Message
}

// NewDomainError creates a coded domain error with inferred level.
func NewDomainError(code ErrorCode, message string) error {
	return &DomainError{Code: code, Level: defaultLevelForCode(code), Message: message}
}

// ToolError is the final mapped error shown by protocol layer.
type ToolError struct {
	Code    ErrorCode
	Level   Level
	Message string
}

// String returns wire-safe text for MCP tool error content.
func (e ToolError) String() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// MapDomainError converts domain or generic errors into wire-safe tool errors.
func MapDomainError(err error) ToolError {
	if err == nil {
		return ToolError{}
	}

	var de *DomainError
	if errors.As(err, &de) {
		if de.Message == "" {
			return ToolError{Code: de.Code, Level: de.Level, Message: "operation failed"}
		}
		return ToolError{Code: de.Code, Level: de.Level, Message: de.Message}
	}

	return ToolError{Code: ErrorRuntimeFailure, Level: LevelError, Message: err.Error()}
}

func defaultLevelForCode(code ErrorCode) Level {
	switch code {
	case ErrorInvalidArgument, ErrorConflict:
		return LevelWarn
	case ErrorPermissionDenied, ErrorQuotaExceeded:
		return LevelWarn
	case ErrorProbeNotFound, ErrorRuntimeFailure:
		return LevelError
	default:
		return LevelError
	}
}
