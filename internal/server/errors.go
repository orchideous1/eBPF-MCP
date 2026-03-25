package server

import (
	"errors"
	"fmt"
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

// DomainError marks service-layer errors with normalized code.
type DomainError struct {
	Code    ErrorCode
	Message string
}

// Error implements error.
func (e *DomainError) Error() string {
	return e.Message
}

// NewDomainError creates a coded domain error.
func NewDomainError(code ErrorCode, message string) error {
	return &DomainError{Code: code, Message: message}
}

// ToolError is the final mapped error shown by protocol layer.
type ToolError struct {
	Code    ErrorCode
	Message string
}

func (e ToolError) String() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func mapDomainError(err error) ToolError {
	if err == nil {
		return ToolError{}
	}
	var de *DomainError
	if errors.As(err, &de) {
		if de.Message == "" {
			return ToolError{Code: de.Code, Message: "operation failed"}
		}
		return ToolError{Code: de.Code, Message: de.Message}
	}
	return ToolError{Code: ErrorRuntimeFailure, Message: err.Error()}
}
