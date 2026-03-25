package server

import (
	"errors"
	"testing"
)

func TestMapDomainError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorCode
	}{
		{name: "invalid argument", err: NewDomainError(ErrorInvalidArgument, "bad input"), want: ErrorInvalidArgument},
		{name: "permission denied", err: NewDomainError(ErrorPermissionDenied, "forbidden"), want: ErrorPermissionDenied},
		{name: "quota exceeded", err: NewDomainError(ErrorQuotaExceeded, "quota"), want: ErrorQuotaExceeded},
		{name: "probe not found", err: NewDomainError(ErrorProbeNotFound, "missing"), want: ErrorProbeNotFound},
		{name: "conflict", err: NewDomainError(ErrorConflict, "conflict"), want: ErrorConflict},
		{name: "runtime", err: NewDomainError(ErrorRuntimeFailure, "runtime"), want: ErrorRuntimeFailure},
		{name: "unknown fallback", err: errors.New("boom"), want: ErrorRuntimeFailure},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapDomainError(tt.err)
			if got.Code != tt.want {
				t.Fatalf("expected %s got %s", tt.want, got.Code)
			}
		})
	}
}
