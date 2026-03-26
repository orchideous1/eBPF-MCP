package logx

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var testFuncPattern = regexp.MustCompile(`\.Test[^.]*$`)

// Logger provides leveled logging with file output under project log directory.
type Logger struct {
	std   *log.Logger
	debug bool
}

// NewRunLogger creates one logger for one run (startup or test item).
func NewRunLogger(debug bool, scenario string) (*Logger, error) {
	if strings.TrimSpace(scenario) == "" {
		scenario = DetectScenario("server")
	}

	logDir, err := resolveLogDir()
	if err != nil {
		return nil, fmt.Errorf("resolve log dir: %w", err)
	}
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}

	fileName := fmt.Sprintf("%s_%s.log", time.Now().Format("20060102_150405.000"), sanitizeScenario(scenario))
	filePath := filepath.Join(logDir, fileName)

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	mw := io.MultiWriter(os.Stderr, f)
	return &Logger{std: log.New(mw, "", log.LstdFlags|log.Lmicroseconds), debug: debug}, nil
}

// StdLogger exposes the underlying standard logger when needed by external middleware.
func (l *Logger) StdLogger() *log.Logger {
	if l == nil {
		return nil
	}
	return l.std
}

// Debugf logs debug messages when debug mode is enabled.
func (l *Logger) Debugf(format string, args ...any) {
	if l == nil || !l.debug || l.std == nil {
		return
	}
	l.std.Printf("[DEBUG] "+format, args...)
}

// Infof logs informational messages.
func (l *Logger) Infof(format string, args ...any) {
	if l == nil || l.std == nil {
		return
	}
	l.std.Printf("[INFO] "+format, args...)
}

// Warnf logs warning messages.
func (l *Logger) Warnf(format string, args ...any) {
	if l == nil || l.std == nil {
		return
	}
	l.std.Printf("[WARN] "+format, args...)
}

// Errorf logs error messages.
func (l *Logger) Errorf(format string, args ...any) {
	if l == nil || l.std == nil {
		return
	}
	l.std.Printf("[ERROR] "+format, args...)
}

// LogToolError logs one tool error with its level, code and message.
func (l *Logger) LogToolError(prefix string, e ToolError) {
	if l == nil || l.std == nil {
		return
	}
	msg := "%s code=%s message=%s"
	switch e.Level {
	case LevelDebug:
		l.Debugf(msg, prefix, e.Code, e.Message)
	case LevelInfo:
		l.Infof(msg, prefix, e.Code, e.Message)
	case LevelWarn:
		l.Warnf(msg, prefix, e.Code, e.Message)
	default:
		l.Errorf(msg, prefix, e.Code, e.Message)
	}
}

// DetectScenario tries to discover current test item name from stack; falls back to defaultScenario.
func DetectScenario(defaultScenario string) string {
	if envName := strings.TrimSpace(os.Getenv("MCP_LOG_SCENARIO")); envName != "" {
		return sanitizeScenario(envName)
	}

	pcs := make([]uintptr, 32)
	n := runtime.Callers(2, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	for {
		frame, more := frames.Next()
		funcName := frame.Function
		if testFuncPattern.MatchString(funcName) {
			parts := strings.Split(funcName, ".")
			return sanitizeScenario(parts[len(parts)-1])
		}
		if !more {
			break
		}
	}
	return sanitizeScenario(defaultScenario)
}

func sanitizeScenario(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "run"
	}
	v = strings.ReplaceAll(v, " ", "_")
	v = strings.ReplaceAll(v, "/", "_")
	v = strings.ReplaceAll(v, "\\", "_")
	v = strings.ReplaceAll(v, ":", "_")
	v = strings.ReplaceAll(v, "\t", "_")
	v = strings.ReplaceAll(v, "\n", "_")
	return v
}

func resolveLogDir() (string, error) {
	root, err := findRepoRoot()
	if err != nil {
		cwd, cwdErr := os.Getwd()
		if cwdErr != nil {
			return "", err
		}
		return filepath.Join(cwd, "log"), nil
	}
	return filepath.Join(root, "log"), nil
}

func findRepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, statErr := os.Stat(filepath.Join(wd, "go.mod")); statErr == nil {
			return wd, nil
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			return "", os.ErrNotExist
		}
		wd = parent
	}
}
