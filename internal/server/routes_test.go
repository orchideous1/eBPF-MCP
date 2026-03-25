package server

import "testing"

func TestRegisterRoutes(t *testing.T) {
	s := newTestServer(nil, nil, nil)
	tools := s.MCPServer().ListTools()
	if _, ok := tools["probe_customize"]; !ok {
		t.Fatalf("probe_customize tool is not registered")
	}
	if _, ok := tools["system_observe_control"]; !ok {
		t.Fatalf("system_observe_control tool is not registered")
	}
}
