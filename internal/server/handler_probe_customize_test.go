package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

func TestHandleProbeCustomize(t *testing.T) {
	customize := &fakeCustomizeService{result: CustomizeResult{Accepted: true, NewState: "loaded", AuditID: "a1"}}
	audit := &fakeAuditLogger{}
	s := newTestServer(customize, nil, audit)

	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]any{
		"name":   "vfs-nfs-file-read",
		"params": map[string]any{"filter_pid": 12},
	}}}

	res, err := s.handleProbeCustomize(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected success result")
	}
	if customize.calls != 1 {
		t.Fatalf("expected one call got %d", customize.calls)
	}
	if len(audit.events) != 1 {
		t.Fatalf("expected one audit event")
	}

	text := firstText(t, res)
	var got CustomizeResult
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("failed to decode result json: %v", err)
	}
	if !got.Accepted || got.NewState != "loaded" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestHandleProbeCustomizeInvalidArgs(t *testing.T) {
	s := newTestServer(nil, nil, nil)
	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]any{"params": map[string]any{}}}}

	res, err := s.handleProbeCustomize(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected error result")
	}
	if !strings.Contains(firstText(t, res), string(ErrorInvalidArgument)) {
		t.Fatalf("expected invalid argument code")
	}
}

func TestHandleProbeCustomizeDomainError(t *testing.T) {
	customize := &fakeCustomizeService{err: NewDomainError(ErrorQuotaExceeded, "quota exceeded")}
	audit := &fakeAuditLogger{}
	s := newTestServer(customize, nil, audit)

	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]any{
		"name":   "vfs-nfs-file-read",
		"params": map[string]any{"filter_pid": 1},
	}}}

	res, err := s.handleProbeCustomize(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected error result")
	}
	if !strings.Contains(firstText(t, res), string(ErrorQuotaExceeded)) {
		t.Fatalf("expected quota code")
	}
	if len(audit.events) != 1 || audit.events[0].Accepted {
		t.Fatalf("expected rejected audit event")
	}
}
