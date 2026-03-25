package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

func TestHandleSystemObserveControl(t *testing.T) {
	observe := &fakeObserveService{result: ObserveResult{State: "loaded", Admission: "allowed"}}
	audit := &fakeAuditLogger{}
	s := newTestServer(nil, observe, audit)

	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]any{
		"probeName": "vfs-nfs-file-read",
		"operation": "status",
	}}}

	res, err := s.handleSystemObserveControl(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected success result")
	}
	if observe.calls != 1 {
		t.Fatalf("expected one call got %d", observe.calls)
	}
	if len(audit.events) != 1 {
		t.Fatalf("expected one audit event")
	}

	text := firstText(t, res)
	var got ObserveResult
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	if got.Admission != "allowed" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestHandleSystemObserveControlInvalidOperation(t *testing.T) {
	s := newTestServer(nil, nil, nil)
	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]any{
		"probeName": "vfs-nfs-file-read",
		"operation": "restart",
	}}}

	res, err := s.handleSystemObserveControl(context.Background(), req)
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

func TestHandleSystemObserveControlConflict(t *testing.T) {
	observe := &fakeObserveService{err: NewDomainError(ErrorConflict, "already loaded")}
	s := newTestServer(nil, observe, &fakeAuditLogger{})

	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]any{
		"probeName": "vfs-nfs-file-read",
		"operation": "load",
	}}}

	res, err := s.handleSystemObserveControl(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected error result")
	}
	if !strings.Contains(firstText(t, res), string(ErrorConflict)) {
		t.Fatalf("expected conflict code")
	}
}
