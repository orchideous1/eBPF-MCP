package server

import (
	"context"
)

type fakeCustomizeService struct {
	result CustomizeResult
	err    error
	calls  int
}

func (f *fakeCustomizeService) Customize(context.Context, CustomizeRequest) (CustomizeResult, error) {
	f.calls++
	return f.result, f.err
}

type fakeObserveService struct {
	result ObserveResult
	err    error
	calls  int
}

func (f *fakeObserveService) Control(context.Context, ObserveRequest) (ObserveResult, error) {
	f.calls++
	return f.result, f.err
}

type fakeAuditLogger struct {
	events []AuditEvent
}

func (f *fakeAuditLogger) Record(_ context.Context, e AuditEvent) {
	f.events = append(f.events, e)
}

func newTestServer(customize CustomizeService, observe ObserveService, audit AuditLogger) *Server {
	if customize == nil {
		customize = &fakeCustomizeService{}
	}
	if observe == nil {
		observe = &fakeObserveService{}
	}
	if audit == nil {
		audit = &fakeAuditLogger{}
	}

	s, err := New(ServerConfig{Transport: TransportStdio}, Dependencies{
		Customize: customize,
		Observe:   observe,
		Audit:     audit,
	})
	if err != nil {
		panic(err)
	}
	return s
}
