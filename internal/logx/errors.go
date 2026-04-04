package logx

import (
	"errors"
	"fmt"
)

// =============================================================================
// 日志级别定义
// =============================================================================

// Level represents log severity.
type Level string

const (
	LevelDebug Level = "DEBUG"
	LevelInfo  Level = "INFO"
	LevelWarn  Level = "WARN"
	LevelError Level = "ERROR"
)

// =============================================================================
// 错误码定义
// =============================================================================

// ErrorCode is the normalized protocol error code for tool responses.
type ErrorCode string

const (
	// 参数相关错误
	ErrorInvalidArgument ErrorCode = "INVALID_ARGUMENT"
	ErrorMissingArgument ErrorCode = "MISSING_ARGUMENT"

	// 权限与资源错误
	ErrorPermissionDenied ErrorCode = "PERMISSION_DENIED"
	ErrorQuotaExceeded    ErrorCode = "QUOTA_EXCEEDED"

	// 探针相关错误
	ErrorProbeNotFound    ErrorCode = "PROBE_NOT_FOUND"
	ErrorProbeNotLoaded   ErrorCode = "PROBE_NOT_LOADED"
	ErrorProbeAlreadyLoaded ErrorCode = "PROBE_ALREADY_LOADED"
	ErrorProbeStartFailed ErrorCode = "PROBE_START_FAILED"
	ErrorProbeStopFailed  ErrorCode = "PROBE_STOP_FAILED"
	ErrorProbeUpdateFailed ErrorCode = "PROBE_UPDATE_FAILED"

	// 配置相关错误
	ErrorInvalidConfig ErrorCode = "INVALID_CONFIG"

	// 数据库相关错误
	ErrorDBConnection ErrorCode = "DB_CONNECTION_FAILED"
	ErrorDBOperation  ErrorCode = "DB_OPERATION_FAILED"

	// 运行时错误
	ErrorRuntimeFailure ErrorCode = "RUNTIME_FAILURE"
	ErrorConflict       ErrorCode = "CONFLICT"
	ErrorNotSupported   ErrorCode = "NOT_SUPPORTED"
)

// =============================================================================
// 全局错误变量（用于错误比较）
// =============================================================================

var (
	// 探针生命周期错误
	ErrProbeNotFound      = errors.New("probe not found")
	ErrProbeAlreadyLoaded = errors.New("probe already loaded")
	ErrProbeNotLoaded     = errors.New("probe not loaded")
	ErrProbeNotStarted    = errors.New("probe is not started")

	// 数据库错误
	ErrDBIsNil          = errors.New("database is nil")
	ErrDBOpenerNotConfigured = errors.New("db opener not configured")
	ErrNotDuckDBConn    = errors.New("connection is not a duckdb.Conn")

	// 配置错误
	ErrControllerRequired = errors.New("controller is required")
	ErrAuthTokenRequired  = errors.New("auth token is required")
	ErrHTTPPortRequired   = errors.New("http port is required for http transport")
	ErrInvalidTransport   = errors.New("invalid transport")
	ErrUnsupportedTransport = errors.New("unsupported transport")

	// 参数错误
	ErrInvalidFilterValue = errors.New("invalid filter value")
	ErrNegativeValue      = errors.New("negative value")
	ErrUnsupportedType    = errors.New("unsupported type")
)

// =============================================================================
// 领域错误（DomainError）- 服务层错误封装
// =============================================================================

// DomainError marks service-layer errors with normalized code and level.
type DomainError struct {
	Code    ErrorCode
	Level   Level
	Message string
	Cause   error // 原始错误，用于错误链
}

// Error implements error.
func (e *DomainError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

// Unwrap returns the underlying error for errors.Is/As support.
func (e *DomainError) Unwrap() error {
	return e.Cause
}

// NewDomainError creates a coded domain error with inferred level.
func NewDomainError(code ErrorCode, message string) error {
	return &DomainError{Code: code, Level: defaultLevelForCode(code), Message: message}
}

// NewDomainErrorWithCause creates a coded domain error with cause.
func NewDomainErrorWithCause(code ErrorCode, message string, cause error) error {
	return &DomainError{Code: code, Level: defaultLevelForCode(code), Message: message, Cause: cause}
}

// Wrap wraps an error with context message, preserving the error chain.
// 如果 err 为 nil，返回 nil。
func Wrap(err error, message string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}

// Wrapf wraps an error with formatted context message, preserving the error chain.
// 如果 err 为 nil，返回 nil。
func Wrapf(err error, format string, args ...interface{}) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", fmt.Sprintf(format, args...), err)
}

// =============================================================================
// 工具错误（ToolError）- 协议层错误
// =============================================================================

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
		msg := de.Message
		if msg == "" {
			msg = "operation failed"
		}
		return ToolError{Code: de.Code, Level: de.Level, Message: msg}
	}

	// 检查是否是已知的全局错误变量
	code := errorCodeForError(err)
	return ToolError{Code: code, Level: defaultLevelForCode(code), Message: err.Error()}
}

// =============================================================================
// 错误码映射
// =============================================================================

// errorCodeForError 将已知的全局错误变量映射到对应的 ErrorCode。
func errorCodeForError(err error) ErrorCode {
	switch {
	case errors.Is(err, ErrProbeNotFound):
		return ErrorProbeNotFound
	case errors.Is(err, ErrProbeAlreadyLoaded):
		return ErrorProbeAlreadyLoaded
	case errors.Is(err, ErrProbeNotLoaded):
		return ErrorProbeNotLoaded
	case errors.Is(err, ErrProbeNotStarted):
		return ErrorRuntimeFailure
	case errors.Is(err, ErrInvalidFilterValue), errors.Is(err, ErrNegativeValue), errors.Is(err, ErrUnsupportedType):
		return ErrorInvalidArgument
	case errors.Is(err, ErrDBIsNil), errors.Is(err, ErrDBOpenerNotConfigured), errors.Is(err, ErrNotDuckDBConn):
		return ErrorDBConnection
	case errors.Is(err, ErrControllerRequired):
		return ErrorInvalidConfig
	case errors.Is(err, ErrAuthTokenRequired):
		return ErrorPermissionDenied
	case errors.Is(err, ErrHTTPPortRequired):
		return ErrorInvalidConfig
	case errors.Is(err, ErrInvalidTransport), errors.Is(err, ErrUnsupportedTransport):
		return ErrorInvalidConfig
	default:
		return ErrorRuntimeFailure
	}
}

// defaultLevelForCode 根据错误码推断日志级别。
func defaultLevelForCode(code ErrorCode) Level {
	switch code {
	case ErrorInvalidArgument, ErrorMissingArgument, ErrorConflict:
		return LevelWarn
	case ErrorPermissionDenied, ErrorQuotaExceeded:
		return LevelWarn
	case ErrorProbeNotFound, ErrorProbeNotLoaded, ErrorProbeAlreadyLoaded:
		return LevelWarn
	case ErrorInvalidConfig:
		return LevelWarn
	case ErrorDBConnection, ErrorDBOperation:
		return LevelError
	case ErrorProbeStartFailed, ErrorProbeStopFailed, ErrorProbeUpdateFailed:
		return LevelError
	case ErrorRuntimeFailure:
		return LevelError
	default:
		return LevelError
	}
}
