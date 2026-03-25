package integration

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ebpf-mcp/internal/server"
)

type integrationRPCExecutor struct {
	loadCalls   atomic.Int32
	unloadCalls atomic.Int32
	statusCalls atomic.Int32
}

func (e *integrationRPCExecutor) Load(context.Context, string) (server.ObserveExecutionStatus, error) {
	e.loadCalls.Add(1)
	return server.ObserveExecutionStatus{State: "loaded", Loaded: true}, nil
}

func (e *integrationRPCExecutor) Unload(context.Context, string) (server.ObserveExecutionStatus, error) {
	e.unloadCalls.Add(1)
	return server.ObserveExecutionStatus{State: "unloaded", Loaded: false}, nil
}

func (e *integrationRPCExecutor) Status(context.Context, string) (server.ObserveExecutionStatus, error) {
	e.statusCalls.Add(1)
	return server.ObserveExecutionStatus{State: "loaded", Loaded: true}, nil
}

func TestMCPLoaderSocketFlow(t *testing.T) {
	rpcExec := &integrationRPCExecutor{}
	socketPath := filepath.Join(t.TempDir(), "loader.sock")

	loaderCtx, loaderCancel := context.WithCancel(context.Background())
	defer loaderCancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.RunLoaderRPCServer(loaderCtx, socketPath, rpcExec)
	}()

	waitForLoaderSocket(t, socketPath)

	observeExecutor, err := server.NewRPCObserveExecutor(socketPath)
	if err != nil {
		t.Fatalf("new rpc observe executor: %v", err)
	}

	probeServices, err := server.NewProbeServicesWithExecutor(observeExecutor, server.ToggleLoadAuthorizer{Allow: true})
	if err != nil {
		t.Fatalf("new probe services: %v", err)
	}

	s, err := server.New(server.ServerConfig{
		Transport: server.TransportHTTP,
		HTTPPort:  "18081",
		AuthToken: "loader-token",
	}, server.Dependencies{
		Customize: server.DisabledCustomizeService{Reason: "customization disabled in remote loader mode"},
		Observe:   probeServices,
		Audit:     server.NoopAuditLogger{},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	h, err := s.MCPServerHTTPHandlerForTest()
	if err != nil {
		t.Fatalf("build http handler: %v", err)
	}

	httpSrv := httptest.NewServer(h)
	defer httpSrv.Close()
	sessionID := initMCPSession(t, httpSrv.URL, "loader-token")

	loadBody := callTool(t, httpSrv.URL, "loader-token", sessionID, 11, "system_observe_control", map[string]any{
		"probeName": "nfs_file_read",
		"operation": "load",
	})
	if !strings.Contains(loadBody, "loaded") {
		t.Fatalf("expected loaded state in response, got: %s", loadBody)
	}

	statusBody := callTool(t, httpSrv.URL, "loader-token", sessionID, 12, "system_observe_control", map[string]any{
		"probeName": "nfs_file_read",
		"operation": "status",
	})
	if !strings.Contains(statusBody, "\\\"loaded\\\":true") && !strings.Contains(statusBody, "\"loaded\":true") {
		t.Fatalf("expected loaded=true report in status response, got: %s", statusBody)
	}

	unloadBody := callTool(t, httpSrv.URL, "loader-token", sessionID, 13, "system_observe_control", map[string]any{
		"probeName": "nfs_file_read",
		"operation": "unload",
	})
	if !strings.Contains(unloadBody, "unloaded") {
		t.Fatalf("expected unloaded state in response, got: %s", unloadBody)
	}

	if rpcExec.loadCalls.Load() != 1 {
		t.Fatalf("expected one loader load call, got %d", rpcExec.loadCalls.Load())
	}
	if rpcExec.statusCalls.Load() != 1 {
		t.Fatalf("expected one loader status call, got %d", rpcExec.statusCalls.Load())
	}
	if rpcExec.unloadCalls.Load() != 1 {
		t.Fatalf("expected one loader unload call, got %d", rpcExec.unloadCalls.Load())
	}

	loaderCancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("loader rpc server exit error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting loader rpc server exit")
	}
}

func TestMCPLoaderSocketLoadDeniedByPolicy(t *testing.T) {
	rpcExec := &integrationRPCExecutor{}
	socketPath := filepath.Join(t.TempDir(), "loader.sock")

	loaderCtx, loaderCancel := context.WithCancel(context.Background())
	defer loaderCancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.RunLoaderRPCServer(loaderCtx, socketPath, rpcExec)
	}()

	waitForLoaderSocket(t, socketPath)

	observeExecutor, err := server.NewRPCObserveExecutor(socketPath)
	if err != nil {
		t.Fatalf("new rpc observe executor: %v", err)
	}

	probeServices, err := server.NewProbeServicesWithExecutor(observeExecutor, server.ToggleLoadAuthorizer{Allow: false})
	if err != nil {
		t.Fatalf("new probe services: %v", err)
	}

	s, err := server.New(server.ServerConfig{
		Transport: server.TransportHTTP,
		HTTPPort:  "18082",
		AuthToken: "loader-token-2",
	}, server.Dependencies{
		Customize: server.DisabledCustomizeService{Reason: "customization disabled in remote loader mode"},
		Observe:   probeServices,
		Audit:     server.NoopAuditLogger{},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	h, err := s.MCPServerHTTPHandlerForTest()
	if err != nil {
		t.Fatalf("build http handler: %v", err)
	}

	httpSrv := httptest.NewServer(h)
	defer httpSrv.Close()
	sessionID := initMCPSession(t, httpSrv.URL, "loader-token-2")

	loadBody := callTool(t, httpSrv.URL, "loader-token-2", sessionID, 21, "system_observe_control", map[string]any{
		"probeName": "nfs_file_read",
		"operation": "load",
	})
	if !strings.Contains(loadBody, string(server.ErrorPermissionDenied)) {
		t.Fatalf("expected permission denied in response, got: %s", loadBody)
	}

	if rpcExec.loadCalls.Load() != 0 {
		t.Fatalf("expected no loader load call when denied, got %d", rpcExec.loadCalls.Load())
	}

	loaderCancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("loader rpc server exit error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting loader rpc server exit")
	}
}

func waitForLoaderSocket(t *testing.T, socketPath string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("loader socket not ready: %s", socketPath)
}
